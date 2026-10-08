/*******************************************************************************
 *     ___                  _   ____  ____
 *    / _ \ _   _  ___  ___| |_|  _ \| __ )
 *   | | | | | | |/ _ \/ __| __| | | |  _ \
 *   | |_| | |_| |  __/\__ \ |_| |_| | |_) |
 *    \__\_\\__,_|\___||___/\__|____/|____/
 *
 *  Copyright (c) 2014-2019 Appsicle
 *  Copyright (c) 2019-2025 QuestDB
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 ******************************************************************************/

//! Sync QWP/WebSocket (RFC 6455) sender. Hand-rolled HTTP/1.1 upgrade and binary
//! framing — no external WebSocket dependency. See QWP_SPECIFICATION §2 (transport),
//! §3 (version negotiation) and §13 (response format).

use std::collections::VecDeque;
use std::io::{ErrorKind, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, TryLockError};
use std::thread;
use std::time::{Duration, Instant};

use rand::RngCore;

use crate::error;
use crate::ingress::SyncProtocolHandler;
use crate::ingress::buffer::QwpWsColumnarBuffer;
use crate::ingress::conf::{QwpWsConfig, QwpWsEndpoint, QwpWsInitialConnectMode, SfDurability};
use crate::ingress::tls::{TlsSettings, configure_tls};
use crate::ws::frame::{
    OPCODE_BINARY, OPCODE_CLOSE, OPCODE_CONTINUATION, OPCODE_PING, OPCODE_PONG, OPCODE_TEXT, Opcode,
};
use crate::ws::nosigpipe::NoSigpipeTcp;

use super::qwp_ws_codec::{self as codec, MAX_INBOUND_FRAME_BYTES};
#[cfg(test)]
use super::qwp_ws_driver::QwpWsCoreTestHarness;
use super::qwp_ws_driver::{
    BlockingQwpWsTransport, CatchUpDriveError, CloseOutcome, DriveOutcome, DriverError,
    DriverEvent, PublicationLifecycle, PublicationLog, PublicationState, QwpWsCoreTransport,
    QwpWsCounters, QwpWsHotResponseProgress, QwpWsHotSendProgress, QwpWsPublicationStore,
    QwpWsReconnectState, QwpWsReconnectStep, QwpWsSendCore, QwpWsTransportFailureAction,
    ReconnectPolicy, ReconnectReason, TransportFailure, TransportPoll, TransportResponse,
    reconnect_error_is_terminal, reconnect_sleep_duration, retry_budget_exhausted_error,
};
use super::qwp_ws_orphan::{
    ManualOrphanDrainers, OrphanDrainerConfig, OrphanDrainerPool, is_candidate_orphan,
    scan_orphan_slots,
};
use super::qwp_ws_ownership::QwpWsSenderError;
use super::qwp_ws_publisher::{QwpWsReplayEncoder, qwp_ws_encoded_message_size_error};
use super::qwp_ws_queue::{OutboundFrame, SentFrame};
use super::qwp_ws_recycle::{PendingRecycle, RecycleLink, RecyclePermit};
use super::qwp_ws_sfa_queue::{
    SfaMemoryQueueOptions, SfaProducer, SfaProgressView, SfaQueueError, segment_payload_capacity,
    two_frame_segment_payload_capacity,
};
use super::qwp_ws_sfa_slot::{SfaSlotOptions, SfaSlotQueue};
use super::qwp_ws_sfa_symbol_dict::PersistedSymbolDict;

// ---------- transport ----------

type TlsStream = rustls::StreamOwned<rustls::ClientConnection, NoSigpipeTcp>;

const QWP_WS_TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
const QWP_WS_DEFAULT_BOUNDED_CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
const QWP_WS_RUNNER_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(30);

#[cfg(test)]
thread_local! {
    pub(super) static TERMINAL_AFTER_RECYCLE_PARK: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static FAIL_NEXT_RECYCLE_SPAWN: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static FAIL_NEXT_RECOVERED_DICT_COPY: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[cfg(test)]
pub(crate) fn fail_next_recovered_dict_copy_for_test() {
    FAIL_NEXT_RECOVERED_DICT_COPY.with(|fail| fail.set(true));
}

#[cfg(test)]
fn should_fail_recovered_dict_copy_for_test() -> bool {
    FAIL_NEXT_RECOVERED_DICT_COPY.with(|fail| fail.replace(false))
}
const QWP_WS_RUNNER_SHUTDOWN_POLL: Duration = Duration::from_millis(1);

/// Cold-path handle used by the runner owner to break blocking socket I/O.
///
/// The duplicated descriptor prevents fd-reuse races, and `shut` is sticky so
/// a reconnect that installs a socket after close has started is interrupted
/// immediately. The mutex is never taken by frame send/receive.
#[derive(Default)]
pub(crate) struct TrafficGate {
    state: Mutex<TrafficGateState>,
}

#[derive(Default)]
struct TrafficGateState {
    current: Option<TcpStream>,
    /// Raw handle of the ORIGINAL socket, not the `current` dup. Winsock
    /// `shutdown()` does not unblock a `recv()` already in progress on
    /// another thread, so `shutdown()` first runs `CancelIoEx` — and that
    /// must target the handle the blocked thread issued its I/O on; a
    /// `try_clone` (WSADuplicateSocket) handle is not guaranteed to share
    /// the file object. Only valid while `current` is `Some`: every close
    /// of the original is mutex-ordered behind `clear()`/re-register, so
    /// the handle cannot be recycled while the gate still holds it.
    #[cfg(windows)]
    original: Option<std::os::windows::io::RawSocket>,
    shut: bool,
}

// Clears a newly registered socket if TLS or WebSocket setup returns early.
#[cfg(all(test, unix))]
type TestRawSocket = std::os::fd::RawFd;

#[cfg(all(test, windows))]
type TestRawSocket = std::os::windows::io::RawSocket;

struct TrafficRegistration<'a> {
    gate: &'a TrafficGate,
    armed: bool,
    #[cfg(all(test, any(unix, windows)))]
    original: TestRawSocket,
}

#[cfg(all(test, unix))]
fn test_socket_is_open(socket: TestRawSocket) -> bool {
    // SAFETY: F_GETFD only inspects the descriptor value and dereferences no pointers.
    unsafe { libc::fcntl(socket, libc::F_GETFD) != -1 }
}

#[cfg(all(test, windows))]
fn test_socket_is_open(socket: TestRawSocket) -> bool {
    use windows_sys::Win32::Networking::WinSock::{SO_TYPE, SOCKET, SOL_SOCKET, getsockopt};

    let Ok(socket) = SOCKET::try_from(socket) else {
        return false;
    };

    let mut socket_type = 0i32;
    let mut option_len = std::mem::size_of_val(&socket_type) as i32;
    // SAFETY: the output buffer is a live i32 and option_len describes its exact size.
    unsafe {
        getsockopt(
            socket,
            SOL_SOCKET,
            SO_TYPE,
            (&mut socket_type as *mut i32).cast(),
            &mut option_len,
        ) == 0
    }
}

impl TrafficGate {
    fn register(&self, stream: &TcpStream) -> std::io::Result<TrafficRegistration<'_>> {
        let shutdown_handle = stream.try_clone()?;
        let mut state = self.state.lock().unwrap_or_else(|err| err.into_inner());
        if state.shut {
            drop(state);
            shutdown_socket(&shutdown_handle)?;
            return Err(std::io::Error::new(
                ErrorKind::Interrupted,
                "QWP/WebSocket traffic is shutting down",
            ));
        }
        state.current = Some(shutdown_handle);
        #[cfg(windows)]
        {
            use std::os::windows::io::AsRawSocket;
            state.original = Some(stream.as_raw_socket());
        }
        Ok(TrafficRegistration {
            gate: self,
            armed: true,
            #[cfg(all(test, unix))]
            original: {
                use std::os::fd::AsRawFd;
                stream.as_raw_fd()
            },
            #[cfg(all(test, windows))]
            original: {
                use std::os::windows::io::AsRawSocket;
                stream.as_raw_socket()
            },
        })
    }

    pub(super) fn clear(&self) {
        let mut state = self.state.lock().unwrap_or_else(|err| err.into_inner());
        state.current = None;
        #[cfg(windows)]
        {
            state.original = None;
        }
    }

    fn is_shutdown(&self) -> bool {
        self.state
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .shut
    }

    pub(super) fn shutdown(&self) -> std::io::Result<()> {
        // The syscalls run under the gate mutex on purpose: every close of
        // the original socket is mutex-ordered behind `clear()`, so while
        // `current` is `Some` the original handle is still open and
        // `CancelIoEx` cannot hit a recycled handle. Cold path only.
        let mut state = self.state.lock().unwrap_or_else(|err| err.into_inner());
        state.shut = true;
        #[cfg(windows)]
        if let Some(original) = state.original.take() {
            // Winsock shutdown() does not unblock an in-progress recv() on
            // another thread. Cancel outstanding I/O on the worker's own
            // handle first, mirroring the Java client's windows/net.c
            // shutdown(). A failure with ERROR_NOT_FOUND (nothing pending)
            // is expected and deliberately ignored.
            use windows_sys::Win32::Foundation::HANDLE;
            unsafe {
                windows_sys::Win32::System::IO::CancelIoEx(original as HANDLE, std::ptr::null());
            }
        }
        if let Some(stream) = state.current.take() {
            shutdown_socket(&stream)?;
        }
        Ok(())
    }
}

impl TrafficRegistration<'_> {
    fn keep(mut self) {
        self.armed = false;
    }
}

impl Drop for TrafficRegistration<'_> {
    fn drop(&mut self) {
        if self.armed {
            #[cfg(all(test, any(unix, windows)))]
            {
                let state = self
                    .gate
                    .state
                    .lock()
                    .unwrap_or_else(|err| err.into_inner());
                if state.current.is_some() {
                    assert!(
                        test_socket_is_open(self.original),
                        "traffic gate registration outlived its original socket"
                    );
                }
            }
            self.gate.clear();
        }
    }
}

fn shutdown_socket(stream: &TcpStream) -> std::io::Result<()> {
    match stream.shutdown(Shutdown::Both) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == ErrorKind::NotConnected => Ok(()),
        Err(err) => Err(err),
    }
}

/// Which lifecycle owns a shared QWP/WebSocket connect walk.
///
/// `Foreground` is a caller-thread initial connect: the user is synchronously
/// waiting and no bounded-shutdown deadline depends on the dial returning.
/// `ForegroundBounded` is foreground work whose dial a bounded wait does
/// depend on -- I/O-runner reconnects and the async initial-connect retry
/// loop (both raced by the 30s runner shutdown), and manual-mode reconnects
/// inside `drive_once`. Only orphan-slot drainers use `BackgroundDrainer`,
/// matching Java's background-connect policy; a transport stores the kind of
/// its lifecycle (`Foreground`/`BackgroundDrainer`) and derives the bounded
/// variant per reconnect via [`Self::for_reconnect`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum QwpWsConnectKind {
    Foreground,
    ForegroundBounded,
    BackgroundDrainer,
}

impl QwpWsConnectKind {
    fn is_background(self) -> bool {
        self == Self::BackgroundDrainer
    }

    fn bounded_dial(self) -> bool {
        self != Self::Foreground
    }

    pub(crate) fn for_reconnect(self) -> Self {
        match self {
            Self::Foreground | Self::ForegroundBounded => Self::ForegroundBounded,
            Self::BackgroundDrainer => Self::BackgroundDrainer,
        }
    }
}

/// Extends Java's `effectiveConnectTimeoutMs`: caller-thread initial connects
/// preserve the configured value verbatim (`None` keeps the OS-default dial),
/// while an unset timeout on any bounded dial receives a finite fallback so a
/// bounded shutdown cannot remain parked until the OS TCP-connect deadline.
/// Java instead cancels an in-flight dial with `shutdown(2)` on a pre-published
/// fd (`ConnectCancellation`); that fd does not exist before
/// `TcpStream::connect` returns, and mid-`SYN_SENT` shutdown wake is
/// Linux-specific, so bounding the dial is the portable equivalent.
fn effective_connect_timeout(bounded_dial: bool, configured: Option<Duration>) -> Option<Duration> {
    if bounded_dial && configured.is_none() {
        Some(QWP_WS_DEFAULT_BOUNDED_CONNECT_TIMEOUT)
    } else {
        configured
    }
}

pub(crate) enum WsStream {
    Plain(NoSigpipeTcp),
    Tls(Box<TlsStream>),
}

impl WsStream {
    pub(crate) fn set_timeouts(
        &self,
        read: Option<Duration>,
        write: Option<Duration>,
    ) -> std::io::Result<()> {
        let sock = self.tcp_stream();
        sock.set_read_timeout(read)?;
        sock.set_write_timeout(write)?;
        Ok(())
    }

    pub(crate) fn read_nonblocking_once(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        let guard = NonblockingModeGuard::new(self.tcp_stream())?;
        let read = self.read(out);
        let restore = guard.restore();
        match (read, restore) {
            (_, Err(err)) => Err(err),
            (result, Ok(())) => result,
        }
    }

    pub(crate) fn begin_io_deadline(
        &mut self,
        deadline: Instant,
    ) -> std::io::Result<(Option<Duration>, Option<Duration>)> {
        let timeouts = (
            self.tcp_stream().read_timeout()?,
            self.tcp_stream().write_timeout()?,
        );
        match self {
            Self::Plain(sock) => sock.set_io_deadline(Some(deadline)),
            Self::Tls(stream) => stream.sock.set_io_deadline(Some(deadline)),
        }
        Ok(timeouts)
    }

    pub(crate) fn end_io_deadline(
        &mut self,
        timeouts: (Option<Duration>, Option<Duration>),
    ) -> std::io::Result<()> {
        match self {
            Self::Plain(sock) => sock.set_io_deadline(None),
            Self::Tls(stream) => stream.sock.set_io_deadline(None),
        }
        self.set_timeouts(timeouts.0, timeouts.1)
    }

    fn tcp_stream(&self) -> &TcpStream {
        match self {
            WsStream::Plain(sock) => sock.tcp(),
            WsStream::Tls(stream) => stream.get_ref().tcp(),
        }
    }

    /// Emit a TLS `close_notify` and try to flush it. No-op for plain
    /// sockets. `rustls::ClientConnection` does NOT auto-send
    /// `close_notify` on `Drop`, so callers issuing a clean shutdown
    /// (after writing the WS Close frame) must invoke this explicitly to
    /// satisfy RFC 8446 §6.1 and avoid server-side truncation warnings.
    pub(crate) fn shutdown_tls(&mut self) {
        if let WsStream::Tls(stream) = self {
            stream.conn.send_close_notify();
            let _ = stream.conn.complete_io(&mut stream.sock);
        }
    }
}

struct NonblockingModeGuard {
    sock: TcpStream,
    armed: bool,
}

impl NonblockingModeGuard {
    fn new(sock: &TcpStream) -> std::io::Result<Self> {
        let guard_sock = sock.try_clone()?;
        sock.set_nonblocking(true)?;
        Ok(Self {
            sock: guard_sock,
            armed: true,
        })
    }

    fn restore(mut self) -> std::io::Result<()> {
        self.armed = false;
        self.sock.set_nonblocking(false)
    }
}

impl Drop for NonblockingModeGuard {
    fn drop(&mut self) {
        if self.armed {
            let _ = self.sock.set_nonblocking(false);
        }
    }
}

impl Read for WsStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            WsStream::Plain(s) => s.read(buf),
            WsStream::Tls(s) => s.read(buf),
        }
    }
}

impl Write for WsStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            WsStream::Plain(s) => s.write(buf),
            WsStream::Tls(s) => s.write(buf),
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            WsStream::Plain(s) => s.flush(),
            WsStream::Tls(s) => s.flush(),
        }
    }
}

// ---------- handler state ----------

struct QwpWsConnectedParts {
    encoder: QwpWsReplayEncoder,
    store: QwpWsPublicationStore<SfaSlotQueue>,
    send_core: QwpWsSendCore<BlockingQwpWsTransport>,
    /// Delta symbol-dict mode for the slot (memory always; file iff the side-file
    /// opened). Drives both the encoder and the driver mirror.
    delta_dict_enabled: bool,
    /// Recovered symbol-dict entries (`[len][utf8]...`) + count, to seed the
    /// producer dict and the driver mirror on file-mode recovery / orphan-drain.
    /// Empty otherwise.
    recovered_dict_entries: Vec<u8>,
    recovered_dict_count: u32,
    /// The slot's persisted symbol dictionary (file mode) for the foreground's
    /// write-ahead. `None` in memory mode / on open failure.
    persisted_symbol_dict: Option<PersistedSymbolDict>,
}

/// The active foreground alone owns global IDs and any persisted write-ahead handle.
pub(crate) trait RecycleForeground {
    fn symbol_count(&self) -> usize;
    fn take_persisted_dict(&mut self) -> Option<PersistedSymbolDict>;
    fn replace_dictionary(&mut self, delta_enabled: bool, persisted: Option<PersistedSymbolDict>);
}

/// Retained above the session seal: successful destructive steps are never repeated
/// when a later storage barrier or worker spawn needs another public call to resume.
enum ForegroundRecyclePhase {
    Idle,
    Storage {
        old_count: usize,
    },
    Dictionary {
        old_count: usize,
        slot_dir: Option<std::path::PathBuf>,
    },
    Installing {
        old_count: usize,
        delta_enabled: bool,
    },
}

struct PublicationRecycle {
    policy: super::qwp_ws_recycle::RecyclePolicy,
    phase: ForegroundRecyclePhase,
}

trait RecycleSession {
    fn pending_boundary(&self) -> Option<Option<u64>>;
    fn recycle_snapshot(&self) -> crate::Result<(Option<u64>, bool, bool)>;
    fn claim_recycle(&mut self, boundary: Option<u64>) -> crate::Result<Option<RecyclePermit>>;
    fn reset_storage(
        &mut self,
        permit: &RecyclePermit,
    ) -> crate::Result<Option<std::path::PathBuf>>;
    fn install_session(&mut self, permit: RecyclePermit, delta: bool) -> crate::Result<()>;
    fn drain_recycle_once(&mut self, deadline: Instant) -> crate::Result<()>;
}

impl PublicationRecycle {
    fn new(settings: super::qwp_ws_recycle::RecycleSettings) -> Self {
        Self {
            policy: super::qwp_ws_recycle::RecyclePolicy::new(settings),
            phase: ForegroundRecyclePhase::Idle,
        }
    }

    fn before_publication(
        &mut self,
        session: &mut impl RecycleSession,
        foreground: &mut impl RecycleForeground,
        nonempty: bool,
        deferred: bool,
    ) -> crate::Result<()> {
        let pending = session.pending_boundary();
        if pending.is_none() && (!nonempty || deferred || !self.policy.is_armed()) {
            return Ok(());
        }
        let boundary = if let Some(boundary) = pending {
            boundary
        } else {
            let (boundary, drained, live) = session.recycle_snapshot()?;
            if !drained
                && let Some(budget) = self.policy.take_wait_budget(Instant::now(), live, deferred)
                && let Some(deadline) = Instant::now().checked_add(budget)
            {
                while Instant::now() < deadline {
                    let (_, drained, live) = session.recycle_snapshot()?;
                    if drained || !live {
                        break;
                    }
                    session.drain_recycle_once(deadline)?;
                }
            }
            boundary
        };
        let Some(permit) = session.claim_recycle(boundary)? else {
            return Ok(());
        };
        if matches!(self.phase, ForegroundRecyclePhase::Idle) {
            self.phase = ForegroundRecyclePhase::Storage {
                old_count: foreground.symbol_count(),
            };
            // Close the old dictionary file before any destructive filesystem work.
            drop(foreground.take_persisted_dict());
        }
        if let ForegroundRecyclePhase::Storage { old_count } = self.phase {
            let slot_dir = session.reset_storage(&permit)?;
            self.phase = ForegroundRecyclePhase::Dictionary {
                old_count,
                slot_dir,
            };
        }
        if let ForegroundRecyclePhase::Dictionary {
            old_count,
            ref slot_dir,
        } = self.phase
        {
            let persisted = slot_dir
                .as_ref()
                .map(|path| PersistedSymbolDict::reset_drained(path))
                .transpose()
                .map_err(|err| {
                    error::fmt!(
                        SocketError,
                        "Could not reset recycled symbol dictionary: {err}"
                    )
                })?;
            // Memory always supports delta; a successful side-file reset heals dense fallback.
            let delta_enabled = true;
            foreground.replace_dictionary(delta_enabled, persisted);
            self.phase = ForegroundRecyclePhase::Installing {
                old_count,
                delta_enabled,
            };
        }
        if let ForegroundRecyclePhase::Installing {
            old_count,
            delta_enabled,
        } = self.phase
        {
            session.install_session(permit, delta_enabled)?;
            self.policy.committed(old_count);
            self.phase = ForegroundRecyclePhase::Idle;
        }
        Ok(())
    }
}

macro_rules! foreground_recycle_api {
    () => {
        pub(crate) fn before_publication(
            &mut self,
            foreground: &mut impl RecycleForeground,
            nonempty: bool,
            deferred: bool,
        ) -> crate::Result<()> {
            let mut recycle = self
                .publication_recycle
                .take()
                .expect("exclusive foreground recycle owner");
            let result = recycle.before_publication(self, foreground, nonempty, deferred);
            self.publication_recycle = Some(recycle);
            result
        }
        pub(crate) fn reset_symbol_dictionary(&mut self) -> crate::Result<()> {
            self.check_advisory_state()?;
            self.publication_recycle
                .as_mut()
                .unwrap()
                .policy
                .request_reset(Instant::now(), 0);
            Ok(())
        }
        pub(crate) fn after_publication(&mut self, symbol_count: usize) {
            self.publication_recycle
                .as_mut()
                .unwrap()
                .policy
                .after_publication(Instant::now(), symbol_count);
        }
    };
}

impl RecycleSession for SyncQwpWsHandlerState {
    fn pending_boundary(&self) -> Option<Option<u64>> {
        self.pending_recycle_boundary()
    }
    fn recycle_snapshot(&self) -> crate::Result<(Option<u64>, bool, bool)> {
        self.runner.check_error()?;
        self.runner.check_publication_open()?;
        let store = self.runner.lock_shared()?;
        check_store_error(&store)?;
        Ok((
            store.published_fsn(),
            store.all_published_receipts_resolved(),
            self.runner.recycle.is_live(),
        ))
    }
    fn claim_recycle(&mut self, boundary: Option<u64>) -> crate::Result<Option<RecyclePermit>> {
        self.request_recycle(boundary)
    }
    fn reset_storage(
        &mut self,
        permit: &RecyclePermit,
    ) -> crate::Result<Option<std::path::PathBuf>> {
        self.with_recycle_storage(permit, |queue, producer| {
            reset_recycle_storage(queue, producer)?;
            Ok(queue.slot_dir().map(std::path::Path::to_path_buf))
        })
    }
    fn install_session(&mut self, permit: RecyclePermit, delta: bool) -> crate::Result<()> {
        self.finish_recycle(permit, delta)
    }
    fn drain_recycle_once(&mut self, deadline: Instant) -> crate::Result<()> {
        // The worker keeps its normal progress mode; never dial on the foreground.
        std::thread::sleep(
            deadline
                .saturating_duration_since(Instant::now())
                .min(Duration::from_millis(1)),
        );
        self.runner.check_error()
    }
}

impl RecycleSession for ManualQwpWsHandlerState {
    fn pending_boundary(&self) -> Option<Option<u64>> {
        self.pending_recycle_boundary()
    }
    fn recycle_snapshot(&self) -> crate::Result<(Option<u64>, bool, bool)> {
        check_store_error(&self.store)?;
        if self.store.lifecycle().load() != PublicationState::Open {
            return Err(driver_error_to_error_without_state(DriverError::Closing));
        }
        Ok((
            self.store.published_fsn(),
            self.store.all_published_receipts_resolved(),
            !self.send_core.has_pending_reconnect(),
        ))
    }
    fn claim_recycle(&mut self, boundary: Option<u64>) -> crate::Result<Option<RecyclePermit>> {
        self.request_recycle(boundary)
    }
    fn reset_storage(
        &mut self,
        permit: &RecyclePermit,
    ) -> crate::Result<Option<std::path::PathBuf>> {
        self.with_recycle_storage(permit, |queue, producer| {
            reset_recycle_storage(queue, producer)?;
            Ok(queue.slot_dir().map(std::path::Path::to_path_buf))
        })
    }
    fn install_session(&mut self, permit: RecyclePermit, delta: bool) -> crate::Result<()> {
        self.finish_recycle(permit, delta)
    }
    fn drain_recycle_once(&mut self, deadline: Instant) -> crate::Result<()> {
        self.send_core
            .drive_recycle_once(&mut self.store, deadline)
            .map_err(|err| driver_error_to_error_from_store(&self.store, err))?;
        check_store_error(&self.store)?;
        std::thread::sleep(
            deadline
                .saturating_duration_since(Instant::now())
                .min(Duration::from_millis(1)),
        );
        Ok(())
    }
}

pub(crate) struct SyncQwpWsHandlerState {
    encoder: Option<QwpWsReplayEncoder>,
    publication_recycle: Option<PublicationRecycle>,
    runner: SyncQwpWsRunner,
    pub(crate) server_max_batch_size: Arc<AtomicUsize>,
    pub(crate) request_durable_ack: bool,
    /// Hard cap on a single store-and-forward frame's payload: `sf_max_segment_bytes`
    /// minus the segment and frame headers. The queue rejects anything larger,
    /// so publishers must size-check and split against THIS bound —
    /// `max_buf_size` (100 MiB default) sits far above it and never binds
    /// first.
    pub(crate) sfa_frame_payload_cap: usize,
    /// Split target for oversize flushes: the largest payload that still packs
    /// two frames per segment, so split output amortizes segment rotation
    /// instead of forcing a fresh segment per near-cap frame.
    pub(crate) sfa_frame_split_target: usize,
    orphan_pool: Option<OrphanDrainerPool>,
    close_drain_timeout: Duration,
    /// Whether the background driver enabled its symbol-dict catch-up mirror
    /// (memory mode always; file mode iff the persisted side-file opened). The
    /// column foreground reads this so it emits delta frames on exactly the same
    /// condition — the two must stay in lockstep.
    pub(crate) delta_dict_enabled: bool,
    /// Symbols recovered from the slot's persisted dictionary on a file-mode
    /// reconnect/adopt, in id order (empty in memory mode / on a fresh slot).
    /// Seeds whichever foreground dictionary owns this state so newly ingested
    /// symbols continue above the recovered ids.
    pub(crate) recovered_dict_entries: Vec<u8>,
    pub(crate) recovered_dict_count: u32,
    /// The slot's persisted symbol dictionary (file mode) for foreground
    /// write-ahead. Routed to whichever foreground owns this state — the
    /// standalone replay encoder in [`connect_qwp_ws`] or the pooled core in
    /// [`super::column_sender::PooledSenderCore::new_store_and_forward`]; the two are
    /// mutually exclusive. `None` in memory mode / on side-file open failure.
    pub(crate) persisted_symbol_dict: Option<PersistedSymbolDict>,
    /// Whether a split chunk may defer its non-final frames' commit.
    ///
    /// Memory mode only. `FLAG_DEFER_COMMIT` is unknown to the queue, segment,
    /// manifest and recovery layers, so a process death between a deferred
    /// append and its committing append leaves a persisted tail nothing
    /// downstream can interpret: the orphan drainer opens replay-only with no
    /// producer, so it can never append the committing frame, and
    /// `orphan_queue_drained` is `completed >= published`, which such a tail
    /// never satisfies. In memory mode the queue dies with the process, so
    /// there is no tail to strand. Lifting this needs commit-boundary
    /// recovery in the queue itself.
    pub(crate) sfa_split_deferral_enabled: bool,
}

impl SyncQwpWsHandlerState {
    fn check_advisory_state(&self) -> crate::Result<()> {
        self.runner.check_error()?;
        if self.runner.lifecycle.load() == PublicationState::Closing {
            return Err(driver_error_to_error_without_state(DriverError::Closing));
        }
        Ok(())
    }
    pub(crate) fn needs_recycle_boundary(&self) -> bool {
        self.publication_recycle.as_ref().unwrap().policy.is_armed()
            || self.pending_recycle_boundary().is_some()
    }

    foreground_recycle_api!();
    #[cfg(test)]
    pub(crate) fn recycle_allocation_probe(&self) -> Box<dyn Fn() -> Option<u64>> {
        self.runner
            .shared
            .lock()
            .unwrap()
            .progress_view()
            .recycle_allocation_probe()
    }

    pub(crate) fn request_recycle(
        &mut self,
        boundary: Option<u64>,
    ) -> crate::Result<Option<RecyclePermit>> {
        self.runner.request_recycle(boundary)
    }

    pub(crate) fn pending_recycle_boundary(&self) -> Option<Option<u64>> {
        self.runner
            .pending_recycle
            .as_ref()
            .map(|pending| pending.boundary)
    }

    pub(crate) fn with_recycle_storage<R>(
        &mut self,
        permit: &RecyclePermit,
        operation: impl FnOnce(&mut SfaSlotQueue, &mut SfaProducer) -> crate::Result<R>,
    ) -> crate::Result<R> {
        self.runner.with_recycle_storage(permit, operation)
    }

    pub(crate) fn finish_recycle(
        &mut self,
        permit: RecyclePermit,
        delta_enabled: bool,
    ) -> crate::Result<()> {
        self.runner.finish_recycle(permit, delta_enabled)?;
        self.delta_dict_enabled = delta_enabled;
        self.recovered_dict_entries.clear();
        self.recovered_dict_count = 0;
        Ok(())
    }

    /// Releases the recovered dictionary seeded into the standalone replay
    /// encoder at connect. The pooled core uses its own dictionary and never
    /// touches this encoder, so that seed is dead weight once the pooled core
    /// claims the state; called from [`PooledSenderCore::new_store_and_forward`].
    ///
    /// [`PooledSenderCore::new_store_and_forward`]: super::column_sender::PooledSenderCore::new_store_and_forward
    pub(crate) fn release_dormant_encoder_dict(&mut self) {
        if let Some(mut encoder) = self.encoder.take() {
            encoder.release_dormant_dict();
        }
    }
}

/// Manual mode owns the core directly, so quiescence needs no worker or join.
struct ManualRecycle {
    owner: Arc<RecycleLink>,
    pending: Option<PendingRecycle>,
    generation: u64,
    producer: Option<SfaProducer>,
    gate: Arc<TrafficGate>,
}

impl ManualRecycle {
    fn new(gate: Arc<TrafficGate>) -> Self {
        Self {
            owner: Arc::new(RecycleLink::new(true)),
            pending: None,
            generation: 0,
            producer: None,
            gate,
        }
    }

    fn request<Q: PublicationLog, T: QwpWsCoreTransport>(
        &mut self,
        store: &mut QwpWsPublicationStore<Q>,
        core: &mut QwpWsSendCore<T>,
        boundary: Option<u64>,
    ) -> crate::Result<Option<RecyclePermit>> {
        check_store_error(store)?;
        if store.lifecycle().load() != PublicationState::Open {
            return Err(driver_error_to_error_without_state(DriverError::Closing));
        }
        if let Some(pending) = &self.pending {
            if pending.boundary != boundary {
                return Err(error::fmt!(
                    SocketError,
                    "QWP/WebSocket recycle boundary changed while parked"
                ));
            }
        } else {
            if core.has_pending_reconnect()
                || store.published_fsn() != boundary
                || !store.all_published_receipts_resolved()
                || store
                    .storage_maintenance_in_flight()
                    .map_err(driver_error_to_error_without_state)?
            {
                return Ok(None);
            }
            self.pending = Some(PendingRecycle {
                boundary,
                wait_spent: true,
                quiesced: true,
                installed: false,
                generation: 0,
            });
            self.producer = store.take_producer();
            self.gate.shutdown().map_err(|err| {
                error::fmt!(
                    SocketError,
                    "Could not cancel recycled QWP/WebSocket session: {err}"
                )
            })?;
        }
        core.release_recycle_views();
        self.generation = self.generation.checked_add(1).ok_or_else(|| {
            error::fmt!(
                SocketError,
                "QWP/WebSocket recycle permit generation exhausted"
            )
        })?;
        self.pending.as_mut().unwrap().generation = self.generation;
        Ok(Some(RecyclePermit {
            owner: Arc::clone(&self.owner),
            generation: self.generation,
            boundary,
        }))
    }

    fn validate<Q: PublicationLog>(
        &self,
        store: &mut QwpWsPublicationStore<Q>,
        permit: &RecyclePermit,
    ) -> crate::Result<()> {
        check_store_error(store)?;
        if store.lifecycle().load() != PublicationState::Open {
            return Err(driver_error_to_error_without_state(DriverError::Closing));
        }
        if !Arc::ptr_eq(&self.owner, &permit.owner)
            || !self.pending.as_ref().is_some_and(|pending| {
                pending.boundary == permit.boundary && pending.generation == permit.generation
            })
        {
            return Err(error::fmt!(
                SocketError,
                "Invalid QWP/WebSocket recycle permit"
            ));
        }
        recheck_recycle_boundary(store, permit.boundary)
    }

    fn finish<T: QwpWsCoreTransport>(
        &mut self,
        store: &mut QwpWsPublicationStore<SfaSlotQueue>,
        core: &mut QwpWsSendCore<T>,
        permit: RecyclePermit,
        delta_enabled: bool,
    ) -> crate::Result<()> {
        self.validate(store, &permit)?;
        if store
            .storage_maintenance_in_flight()
            .map_err(driver_error_to_error_without_state)?
        {
            return Err(error::fmt!(
                SocketError,
                "QWP/WebSocket recycle storage reset is incomplete"
            ));
        }
        let gate = Arc::new(TrafficGate::default());
        core.install_recycled_session(delta_enabled, Arc::clone(&gate));
        if let Some(producer) = self.producer.take() {
            store.recycle_queue_mut().restore_producer(producer);
        }
        self.gate = gate;
        self.pending = None;
        Ok(())
    }
}

pub(crate) struct ManualQwpWsHandlerState {
    recycle: ManualRecycle,
    publication_recycle: Option<PublicationRecycle>,
    encoder: Option<QwpWsReplayEncoder>,
    store: QwpWsPublicationStore<SfaSlotQueue>,
    send_core: QwpWsSendCore<BlockingQwpWsTransport>,
    pub(crate) server_max_batch_size: Arc<AtomicUsize>,
    pub(crate) request_durable_ack: bool,
    orphan_drainers: Option<ManualOrphanDrainers>,
    append_deadline: Duration,
    close_drain_timeout: Duration,
}

impl ManualQwpWsHandlerState {
    fn check_advisory_state(&self) -> crate::Result<()> {
        check_manual_driver_error(self)?;
        if self.store.lifecycle().load() == PublicationState::Closing {
            return Err(driver_error_to_error_without_state(DriverError::Closing));
        }
        Ok(())
    }
    foreground_recycle_api!();
    pub(crate) fn pending_recycle_boundary(&self) -> Option<Option<u64>> {
        self.recycle
            .pending
            .as_ref()
            .map(|pending| pending.boundary)
    }

    pub(crate) fn request_recycle(
        &mut self,
        boundary: Option<u64>,
    ) -> crate::Result<Option<RecyclePermit>> {
        self.recycle
            .request(&mut self.store, &mut self.send_core, boundary)
    }

    pub(crate) fn with_recycle_storage<R>(
        &mut self,
        permit: &RecyclePermit,
        operation: impl FnOnce(&mut SfaSlotQueue, &mut SfaProducer) -> crate::Result<R>,
    ) -> crate::Result<R> {
        self.recycle.validate(&mut self.store, permit)?;
        let producer = self
            .recycle
            .producer
            .as_mut()
            .ok_or_else(|| error::fmt!(SocketError, "QWP/WebSocket recycle has no producer"))?;
        operation(self.store.recycle_queue_mut(), producer)
    }

    pub(crate) fn finish_recycle(
        &mut self,
        permit: RecyclePermit,
        delta_enabled: bool,
    ) -> crate::Result<()> {
        self.recycle
            .finish(&mut self.store, &mut self.send_core, permit, delta_enabled)
    }
}

fn recheck_recycle_boundary<Q: PublicationLog>(
    store: &mut QwpWsPublicationStore<Q>,
    boundary: Option<u64>,
) -> crate::Result<()> {
    check_store_error(store)?;
    if store.published_fsn() != boundary || !store.all_published_receipts_resolved() {
        let err = error::fmt!(
            SocketError,
            "QWP/WebSocket recycle lost its drained publication boundary"
        );
        store.mark_terminal(Some(err.clone()));
        return Err(err);
    }
    Ok(())
}

/// Capacity deferral happens before the storage reset reserves topology. Retire
/// ordinary drained storage work off-lock, then retry without releasing the seal.
/// The foreground must release its persisted dictionary before calling this.
pub(crate) fn reset_recycle_storage(
    queue: &mut SfaSlotQueue,
    producer: &mut SfaProducer,
) -> crate::Result<()> {
    match queue.reset_drained(producer) {
        Ok(()) => Ok(()),
        Err(err) => {
            let err: DriverError = err.into();
            if !driver_error_is_backpressure(&err) {
                return Err(driver_error_to_error_without_state(err));
            }
            if let Some(task) = queue
                .take_storage_maintenance_step(false)
                .map_err(driver_error_to_error_without_state)?
            {
                let result = match task.perform() {
                    Ok(result) => result,
                    Err(err) => {
                        queue
                            .complete_storage_maintenance()
                            .map_err(driver_error_to_error_without_state)?;
                        return Err(driver_error_to_error_without_state(err.into()));
                    }
                };
                let finish = match queue.finish_storage_maintenance(result, false) {
                    Ok(finish) => finish,
                    Err(err) => {
                        queue
                            .complete_storage_maintenance()
                            .map_err(driver_error_to_error_without_state)?;
                        return Err(driver_error_to_error_without_state(err));
                    }
                };
                let failure = finish.into_cleanup().and_then(|cleanup| cleanup.perform());
                let cleanup_result = if let Some(failure) = failure {
                    queue.record_storage_cleanup_failure(failure)
                } else {
                    Ok(())
                };
                queue
                    .complete_storage_maintenance()
                    .map_err(driver_error_to_error_without_state)?;
                cleanup_result.map_err(driver_error_to_error_without_state)?;
            }
            queue
                .reset_drained(producer)
                .map_err(DriverError::from)
                .map_err(driver_error_to_error_without_state)
        }
    }
}

/// Type erasure retains the actual transport (including endpoint history) when
/// generic test runners and production runners hand their parked core back.
trait ParkedRunner<Q>: Send {
    fn install(&mut self, delta_enabled: bool, gate: Arc<TrafficGate>);
    fn run(
        self: Box<Self>,
        shared: Arc<Mutex<QwpWsPublicationStore<Q>>>,
        stop: Arc<AtomicBool>,
        parked: ParkedRunnerSlot<Q>,
    );
}

type ParkedRunnerSlot<Q> = Arc<Mutex<Option<Box<dyn ParkedRunner<Q>>>>>;

fn spawn_parked_runner<Q: PublicationLog + Send + 'static>(
    shared: Arc<Mutex<QwpWsPublicationStore<Q>>>,
    stop: Arc<AtomicBool>,
    parked: ParkedRunnerSlot<Q>,
) -> std::io::Result<thread::JoinHandle<()>> {
    #[cfg(test)]
    if FAIL_NEXT_RECYCLE_SPAWN.with(|fail| fail.replace(false)) {
        return Err(std::io::Error::other(
            "injected recycle worker spawn failure",
        ));
    }
    // Only the successfully spawned worker takes the capsule. If thread creation
    // fails, dropping this closure drops Arc clones, not the retained session.
    thread::Builder::new().spawn(move || {
        let core = parked
            .lock()
            .unwrap()
            .take()
            .expect("parked runner capsule");
        core.run(shared, stop, parked);
    })
}

impl<Q, T> ParkedRunner<Q> for SyncQwpWsRunnerCore<T>
where
    Q: PublicationLog + Send + 'static,
    T: QwpWsCoreTransport + Send + 'static,
{
    fn install(&mut self, delta_enabled: bool, gate: Arc<TrafficGate>) {
        self.send_core.install_recycled_session(delta_enabled, gate);
    }

    fn run(
        mut self: Box<Self>,
        shared: Arc<Mutex<QwpWsPublicationStore<Q>>>,
        stop: Arc<AtomicBool>,
        parked: ParkedRunnerSlot<Q>,
    ) {
        while !stop.load(Ordering::Acquire) {
            match self.drive_step(&shared, &stop) {
                RunnerStep::Idle => thread::sleep(Duration::from_micros(50)),
                RunnerStep::Continue => {}
                RunnerStep::Stop => break,
            }
        }
        // A hot ACK can precede its cold watermark/event effects. Flush even
        // on shutdown, before publishing the ownership capsule to the caller.
        if let Ok(mut store) = shared.lock() {
            self.flush_cold_effects_locked(&mut store);
        } else {
            self.handle_poisoned_lock();
        }
        self.send_core.release_recycle_views();
        if let Ok(mut slot) = parked.lock() {
            *slot = Some(self);
        }
    }
}

pub(crate) struct SyncQwpWsRunner<Q = SfaSlotQueue> {
    shared: Arc<Mutex<QwpWsPublicationStore<Q>>>,
    producer: Option<SfaProducer>,
    lifecycle: PublicationLifecycle,
    backpressure: Arc<BackpressureNotifier>,
    ok_completed_upper: Arc<AtomicU64>,
    append_deadline: Duration,
    stop: Arc<AtomicBool>,
    traffic_gate: Arc<TrafficGate>,
    shutdown_timeout: Duration,
    recycle: Arc<RecycleLink>,
    pending_recycle: Option<PendingRecycle>,
    recycle_generation: u64,
    parked: ParkedRunnerSlot<Q>,
    thread: Option<thread::JoinHandle<()>>,
}

struct SyncQwpWsRunnerCore<T = BlockingQwpWsTransport> {
    send_core: QwpWsSendCore<T>,
    progress: SfaProgressView,
    cold_effects: VecDeque<RunnerColdEffect>,
    backpressure: Arc<BackpressureNotifier>,
    ok_completed_upper: Arc<AtomicU64>,
    lifecycle: PublicationLifecycle,
    recycle: Arc<RecycleLink>,
}

struct SyncQwpWsPendingRunnerCore {
    connected: Option<SyncQwpWsRunnerCore<BlockingQwpWsTransport>>,
    pending_connect: QwpWsPendingConnect,
    progress: SfaProgressView,
    backpressure: Arc<BackpressureNotifier>,
    ok_completed_upper: Arc<AtomicU64>,
    lifecycle: PublicationLifecycle,
    recycle: Arc<RecycleLink>,
}

struct QwpWsPendingConnect {
    host: String,
    port: String,
    use_tls: bool,
    tls_settings: Option<TlsSettings>,
    qwp_ws: QwpWsConfig,
    auth_header: Option<String>,
    reconnect_policy: ReconnectPolicy,
    durable_ack: bool,
    server_max_batch_size: Arc<AtomicUsize>,
    traffic_gate: Arc<TrafficGate>,
    /// Whether the I/O thread enables its symbol-dict catch-up mirror once
    /// connected (memory mode always; file mode iff the side-file opened).
    delta_dict_enabled: bool,
    /// Symbols recovered from the slot's persisted dictionary (file mode), in id
    /// order, used to seed the catch-up mirror when the send core is first built.
    /// Empty in memory mode / on a fresh slot.
    recovered_dict_entries: Vec<u8>,
    recovered_dict_count: u32,
}

#[derive(Debug, Clone, Copy)]
enum RunnerColdEffect {
    Sent { frame: SentFrame, replayed: bool },
    Event(DriverEvent),
    CompletedThrough { fsn: u64, wire_seq: u64 },
}

#[derive(Debug)]
struct BackpressureNotifier {
    lock: Mutex<()>,
    available: Condvar,
    generation: AtomicU64,
}

#[cfg(test)]
const DEFAULT_APPEND_DEADLINE: Duration = Duration::from_secs(30);
const BACKPRESSURE_PARK: Duration = Duration::from_micros(50);

impl<Q> SyncQwpWsRunner<Q>
where
    Q: PublicationLog + Send + 'static,
{
    #[cfg(test)]
    fn start<T>(driver: QwpWsCoreTestHarness<Q, T>) -> Self
    where
        T: QwpWsCoreTransport + Send + 'static,
    {
        Self::start_driver_with_append_deadline(driver, DEFAULT_APPEND_DEADLINE)
    }

    #[cfg(test)]
    fn start_driver_with_append_deadline<T>(
        driver: QwpWsCoreTestHarness<Q, T>,
        append_deadline: Duration,
    ) -> Self
    where
        T: QwpWsCoreTransport + Send + 'static,
    {
        let (store, send_core) = driver.into_parts();
        Self::start_with_append_deadline(
            store,
            send_core,
            append_deadline,
            Arc::new(TrafficGate::default()),
        )
    }

    fn start_with_append_deadline<T>(
        mut store: QwpWsPublicationStore<Q>,
        send_core: QwpWsSendCore<T>,
        append_deadline: Duration,
        traffic_gate: Arc<TrafficGate>,
    ) -> Self
    where
        T: QwpWsCoreTransport + Send + 'static,
    {
        let lifecycle = store.lifecycle();
        let progress = store.progress_view();
        let producer = store.take_producer();
        let shared = Arc::new(Mutex::new(store));
        let backpressure = Arc::new(BackpressureNotifier::new());
        let ok_completed_upper = Arc::new(AtomicU64::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let recycle = Arc::new(RecycleLink::new(true));
        let parked: ParkedRunnerSlot<Q> = Arc::new(Mutex::new(None));
        let core = Box::new(SyncQwpWsRunnerCore {
            send_core,
            progress,
            cold_effects: VecDeque::new(),
            backpressure: Arc::clone(&backpressure),
            ok_completed_upper: Arc::clone(&ok_completed_upper),
            lifecycle: lifecycle.clone(),
            recycle: Arc::clone(&recycle),
        });
        *parked.lock().unwrap() = Some(core);
        let thread =
            spawn_parked_runner(Arc::clone(&shared), Arc::clone(&stop), Arc::clone(&parked))
                .expect("QWP/WebSocket runner thread");

        Self {
            shared,
            producer,
            lifecycle,
            backpressure,
            ok_completed_upper,
            append_deadline,
            stop,
            traffic_gate,
            shutdown_timeout: QWP_WS_RUNNER_SHUTDOWN_TIMEOUT,
            recycle,
            pending_recycle: None,
            recycle_generation: 0,
            parked,
            thread: Some(thread),
        }
    }

    fn start_pending_connect(
        queue: Q,
        pending_connect: QwpWsPendingConnect,
        append_deadline: Duration,
        event_capacity: usize,
        rejection_sink: Option<Arc<crate::ingress::rejection_events::RejectionEventSource>>,
    ) -> Self {
        let mut store = QwpWsPublicationStore::new(queue, event_capacity);
        store.set_rejection_sink(rejection_sink);
        let lifecycle = store.lifecycle();
        let progress = store.progress_view();
        let producer = store.take_producer();
        let shared = Arc::new(Mutex::new(store));
        let backpressure = Arc::new(BackpressureNotifier::new());
        let ok_completed_upper = Arc::new(AtomicU64::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let traffic_gate = Arc::clone(&pending_connect.traffic_gate);
        let recycle = Arc::new(RecycleLink::new(false));
        let thread_recycle = Arc::clone(&recycle);
        let parked: ParkedRunnerSlot<Q> = Arc::new(Mutex::new(None));
        let thread_parked = Arc::clone(&parked);
        let thread_shared = Arc::clone(&shared);
        let thread_backpressure = Arc::clone(&backpressure);
        let thread_ok_completed_upper = Arc::clone(&ok_completed_upper);
        let thread_stop = Arc::clone(&stop);
        let thread_lifecycle = lifecycle.clone();
        let thread = thread::spawn(move || {
            let mut core = SyncQwpWsPendingRunnerCore {
                connected: None,
                pending_connect,
                progress,
                backpressure: thread_backpressure,
                ok_completed_upper: thread_ok_completed_upper,
                lifecycle: thread_lifecycle,
                recycle: thread_recycle,
            };
            while !thread_stop.load(Ordering::Acquire) {
                match core.drive_step(&thread_shared, &thread_stop) {
                    RunnerStep::Idle => thread::sleep(Duration::from_micros(50)),
                    RunnerStep::Continue => {}
                    RunnerStep::Stop => break,
                };
            }
            if let Some(mut connected) = core.connected.take() {
                if let Ok(mut store) = thread_shared.lock() {
                    connected.flush_cold_effects_locked(&mut store);
                } else {
                    connected.handle_poisoned_lock();
                }
                connected.send_core.release_recycle_views();
                if let Ok(mut slot) = thread_parked.lock() {
                    *slot = Some(Box::new(connected));
                }
            }
        });

        Self {
            shared,
            producer,
            lifecycle,
            backpressure,
            ok_completed_upper,
            append_deadline,
            stop,
            traffic_gate,
            shutdown_timeout: QWP_WS_RUNNER_SHUTDOWN_TIMEOUT,
            recycle,
            pending_recycle: None,
            recycle_generation: 0,
            parked,
            thread: Some(thread),
        }
    }

    /// None is a side-effect-free defer. An accepted request always remains
    /// sealed across timeout/error; later calls only probe the retained worker.
    pub(crate) fn request_recycle(
        &mut self,
        boundary: Option<u64>,
    ) -> crate::Result<Option<RecyclePermit>> {
        self.check_error()?;
        if self.lifecycle.load() != PublicationState::Open {
            return Err(driver_error_to_error_without_state(DriverError::Closing));
        }
        if let Some(pending) = self.pending_recycle.as_ref() {
            if pending.boundary != boundary {
                return Err(error::fmt!(
                    SocketError,
                    "QWP/WebSocket recycle boundary changed while parked"
                ));
            }
        } else {
            let store = self.lock_shared()?;
            check_store_error(&store)?;
            if store.published_fsn() != boundary || !store.all_published_receipts_resolved() {
                return Ok(None);
            }
            drop(store);
            if !self.recycle.claim() {
                return Ok(None);
            }
            self.pending_recycle = Some(PendingRecycle {
                boundary,
                wait_spent: false,
                quiesced: false,
                installed: false,
                generation: 0,
            });
            self.stop.store(true, Ordering::Release);
            self.backpressure.notify_all();
            // Sticky cancellation belongs to this retired session only.
            self.traffic_gate.shutdown().map_err(|err| {
                error::fmt!(
                    SocketError,
                    "Could not cancel recycled QWP/WebSocket session: {err}"
                )
            })?;
        }
        let pending = self.pending_recycle.as_mut().unwrap();
        if let Some(worker) = self.thread.as_ref() {
            let timeout = if pending.wait_spent {
                Duration::ZERO
            } else {
                self.shutdown_timeout
            };
            pending.wait_spent = true;
            if !wait_for_runner_exit(worker, timeout) {
                return Err(error::fmt!(
                    SocketError,
                    "QWP/WebSocket recycle is waiting for its retired worker"
                ));
            }
        }
        self.join_recycle_worker()?;
        #[cfg(test)]
        super::qwp_ws_sfa_queue::observe_recycle_phase("accepted park");
        #[cfg(test)]
        if TERMINAL_AFTER_RECYCLE_PARK.with(|fault| fault.replace(false)) {
            self.lock_shared()?
                .record_protocol_violation(Some(1002), "terminal during accepted park".into());
        }
        // Errors must win even when the captured completion boundary is empty.
        let store = self.lock_shared()?;
        check_store_error(&store)?;
        if self.lifecycle.load() != PublicationState::Open {
            return Err(driver_error_to_error_without_state(DriverError::Closing));
        }
        if store.published_fsn() != boundary || !store.all_published_receipts_resolved() {
            drop(store);
            let err = error::fmt!(
                SocketError,
                "QWP/WebSocket recycle lost its drained publication boundary"
            );
            self.lock_shared()?.mark_terminal(Some(err.clone()));
            return Err(err);
        }
        if !self.pending_recycle.as_ref().unwrap().quiesced
            && store
                .storage_maintenance_in_flight()
                .map_err(driver_error_to_error_without_state)?
        {
            return Err(error::fmt!(
                SocketError,
                "QWP/WebSocket recycle storage is still busy"
            ));
        }
        drop(store);
        if self
            .parked
            .lock()
            .map_err(|_| error::fmt!(SocketError, "QWP/WebSocket parked runner lock poisoned"))?
            .is_none()
        {
            let err = error::fmt!(
                SocketError,
                "QWP/WebSocket retired worker did not return its session"
            );
            self.lock_shared()?.mark_terminal(Some(err.clone()));
            return Err(err);
        }
        self.recycle_generation = self.recycle_generation.checked_add(1).ok_or_else(|| {
            error::fmt!(
                SocketError,
                "QWP/WebSocket recycle permit generation exhausted"
            )
        })?;
        self.pending_recycle.as_mut().unwrap().generation = self.recycle_generation;
        self.pending_recycle.as_mut().unwrap().quiesced = true;
        Ok(Some(RecyclePermit {
            owner: Arc::clone(&self.recycle),
            generation: self.recycle_generation,
            boundary,
        }))
    }

    /// Consume a confirmed-exited maintenance worker off-lock. Both resume and
    /// final close must observe its result before authorizing storage changes.
    fn join_recycle_worker(&mut self) -> crate::Result<()> {
        if let Some(worker) = self.thread.take()
            && worker.join().is_err()
        {
            let err = error::fmt!(SocketError, "QWP/WebSocket recycle worker panicked");
            self.lock_shared()?.mark_terminal(Some(err.clone()));
            return Err(err);
        }
        Ok(())
    }

    fn validate_recycle_permit(&self, permit: &RecyclePermit) -> crate::Result<()> {
        self.check_error()?;
        if self.lifecycle.load() != PublicationState::Open {
            return Err(driver_error_to_error_without_state(DriverError::Closing));
        }
        if self.thread.is_some()
            || !Arc::ptr_eq(&permit.owner, &self.recycle)
            || !self.pending_recycle.as_ref().is_some_and(|pending| {
                pending.generation == permit.generation && pending.boundary == permit.boundary
            })
        {
            return Err(error::fmt!(
                SocketError,
                "Invalid QWP/WebSocket recycle permit"
            ));
        }
        recheck_recycle_boundary(&mut *self.lock_shared()?, permit.boundary)
    }

    /// The foreground dictionary and storage must already belong to the new
    /// namespace. Errors leave the capsule and publication seal in place.
    pub(crate) fn finish_recycle(
        &mut self,
        permit: RecyclePermit,
        delta_enabled: bool,
    ) -> crate::Result<()> {
        self.validate_recycle_permit(&permit)?;
        if self
            .lock_shared()?
            .storage_maintenance_in_flight()
            .map_err(driver_error_to_error_without_state)?
        {
            return Err(error::fmt!(
                SocketError,
                "QWP/WebSocket recycle storage reset is incomplete"
            ));
        }
        let mut slot = self
            .parked
            .lock()
            .map_err(|_| error::fmt!(SocketError, "QWP/WebSocket parked runner lock poisoned"))?;
        let core = slot.as_mut().ok_or_else(|| {
            error::fmt!(
                SocketError,
                "QWP/WebSocket retired worker did not return its session"
            )
        })?;
        if !self.pending_recycle.as_ref().unwrap().installed {
            let gate = Arc::new(TrafficGate::default());
            core.install(delta_enabled, Arc::clone(&gate));
            self.traffic_gate = gate;
            self.stop = Arc::new(AtomicBool::new(false));
            self.recycle.restart();
            self.pending_recycle.as_mut().unwrap().installed = true;
        }
        drop(slot);
        self.thread = Some(
            spawn_parked_runner(
                Arc::clone(&self.shared),
                Arc::clone(&self.stop),
                Arc::clone(&self.parked),
            )
            .map_err(|err| {
                error::fmt!(
                    SocketError,
                    "Could not restart recycled QWP/WebSocket worker: {err}"
                )
            })?,
        );
        self.pending_recycle = None;
        Ok(())
    }

    /// Exclusive ownership after join avoids holding the shared-store mutex
    /// across storage barriers. An unexpected observer retains the entire seal.
    pub(crate) fn with_recycle_storage<R>(
        &mut self,
        permit: &RecyclePermit,
        operation: impl FnOnce(&mut Q, &mut SfaProducer) -> crate::Result<R>,
    ) -> crate::Result<R> {
        self.validate_recycle_permit(permit)?;
        let mutex = Arc::get_mut(&mut self.shared).ok_or_else(|| {
            error::fmt!(
                SocketError,
                "QWP/WebSocket recycle store still has observers"
            )
        })?;
        let store = mutex.get_mut().map_err(|_| {
            error::fmt!(SocketError, "QWP/WebSocket publication store lock poisoned")
        })?;
        let producer = self
            .producer
            .as_mut()
            .ok_or_else(|| error::fmt!(SocketError, "QWP/WebSocket recycle has no producer"))?;
        operation(store.recycle_queue_mut(), producer)
    }

    fn publish_replay_payload(&mut self, payload: &[u8]) -> crate::Result<u64> {
        let deadline = Instant::now().checked_add(self.append_deadline);
        loop {
            let backpressure_generation = self.backpressure.generation();
            self.check_publication_open()?;
            if let Some(producer) = self.producer.as_mut() {
                match producer.try_submit(payload) {
                    Ok(receipt) => return Ok(receipt.fsn),
                    Err(err) => {
                        let err: DriverError = err.into();
                        let backpressure = driver_error_backpressure_queue(&err);
                        if backpressure.is_some() {
                            if !self
                                .wait_for_publication_capacity(backpressure_generation, deadline)
                            {
                                return Err(driver_error_to_error_without_state(
                                    DriverError::SubmitTimedOut { backpressure },
                                ));
                            }
                            continue;
                        }
                        return Err(driver_error_to_error_without_state(err));
                    }
                }
            }

            let submit_result = {
                let mut store = self.lock_shared()?;
                check_store_error(&store)?;
                store.try_submit(payload)
            };
            match submit_result {
                Ok(receipt) => return Ok(receipt.fsn),
                Err(err) if driver_error_is_backpressure(&err) => {
                    if !self.wait_for_publication_capacity(backpressure_generation, deadline) {
                        return Err(driver_error_to_error_without_state(
                            DriverError::SubmitTimedOut {
                                backpressure: driver_error_backpressure_queue(&err),
                            },
                        ));
                    }
                }
                Err(err) => return Err(driver_error_to_error_without_state(err)),
            }
        }
    }

    fn check_publication_open(&self) -> crate::Result<()> {
        match self.lifecycle.load() {
            PublicationState::Open => {
                if self.pending_recycle.is_some() {
                    return Err(error::fmt!(
                        SocketError,
                        "QWP/WebSocket publication is parked for dictionary recycling"
                    ));
                }
                Ok(())
            }
            PublicationState::Closing => {
                Err(driver_error_to_error_without_state(DriverError::Closing))
            }
            PublicationState::Terminal => {
                let store = self.lock_shared()?;
                Err(driver_error_to_error_from_store(
                    &store,
                    DriverError::Terminal,
                ))
            }
        }
    }

    fn check_error(&self) -> crate::Result<()> {
        if let Some(producer) = self.producer.as_ref() {
            producer
                .check_durability()
                .map_err(DriverError::from)
                .map_err(driver_error_to_error_without_state)?;
        } else {
            let store = self.lock_shared()?;
            check_store_error(&store)?;
        }
        if self.lifecycle.is_terminal() {
            let store = self.lock_shared()?;
            return Err(driver_error_to_error_from_store(
                &store,
                DriverError::Terminal,
            ));
        }
        Ok(())
    }

    fn published_fsn(&self) -> crate::Result<Option<u64>> {
        self.check_error()?;
        if let Some(producer) = self.producer.as_ref() {
            return Ok(producer.published_fsn());
        }

        let store = self.lock_shared()?;
        check_store_error(&store)?;
        Ok(store.published_fsn())
    }

    fn acked_fsn(&self) -> crate::Result<Option<u64>> {
        self.check_error()?;
        if let Some(producer) = self.producer.as_ref() {
            return Ok(producer.completed_fsn());
        }

        let store = self.lock_shared()?;
        check_store_error(&store)?;
        Ok(store.completed_fsn())
    }

    fn ok_fsn(&self) -> crate::Result<Option<u64>> {
        self.check_error()?;
        let completed_upper = if let Some(producer) = self.producer.as_ref() {
            producer
                .completed_fsn()
                .map_or(0, |fsn| fsn.saturating_add(1))
        } else {
            let store = self.lock_shared()?;
            check_store_error(&store)?;
            store.completed_fsn().map_or(0, |fsn| fsn.saturating_add(1))
        };
        let upper = self
            .ok_completed_upper
            .load(Ordering::Acquire)
            .max(completed_upper);
        Ok(upper.checked_sub(1))
    }

    fn poll_sender_error(&self) -> crate::Result<Option<QwpWsSenderError>> {
        let mut store = self.lock_shared()?;
        Ok(store.poll_sender_error())
    }

    fn poll_sender_error_notification(&self) -> crate::Result<Option<QwpWsSenderError>> {
        let mut store = self.lock_shared()?;
        Ok(store.poll_sender_error_notification())
    }

    fn terminal_sender_error(&self) -> crate::Result<Option<QwpWsSenderError>> {
        let store = self.lock_shared()?;
        Ok(store.terminal_sender_error().cloned())
    }

    fn lifecycle_is_terminal(&self) -> bool {
        self.lifecycle.is_terminal()
    }

    fn sender_errors_dropped_total(&self) -> crate::Result<u64> {
        let store = self.lock_shared()?;
        Ok(store.sender_errors_dropped_total())
    }

    fn counters(&self) -> crate::Result<QwpWsCounters> {
        let store = self.lock_shared()?;
        Ok(store.counters())
    }

    fn close_drain(&mut self, timeout: Duration) -> crate::Result<()> {
        self.begin_close();
        self.producer.take();
        if timeout.is_zero() {
            return Ok(());
        }
        self.drain_to_deadline(Instant::now().checked_add(timeout))
    }

    /// Stop accepting new publications and wake the background runner so it
    /// flushes whatever is already queued. Non-blocking and idempotent; pairs
    /// with [`Self::drain_to_deadline`]. The unified sender pool calls this on
    /// every connection being retired *before* waiting on any of them, so a
    /// multi-connection close drains in parallel rather than serially.
    fn begin_close(&self) {
        self.lifecycle.begin_close();
        self.backpressure.notify_all();
    }

    /// Block until every published frame has resolved its receipt, then close
    /// the queue; give up with a `SocketError` once `deadline` passes (an
    /// already-elapsed deadline fails fast, which is what bounds a batched pool
    /// close). `deadline == None` waits indefinitely. Assumes
    /// [`Self::begin_close`] has already run.
    fn drain_to_deadline(&mut self, deadline: Option<Instant>) -> crate::Result<()> {
        // No publication can pass the Closing lifecycle latch. Release the
        // detached producer's active-segment mapping before queue.close()
        // starts the ordered unlink protocol.
        self.producer.take();
        loop {
            if self.pending_recycle.is_some()
                && let Some(worker) = self.thread.as_ref()
                && !worker.is_finished()
            {
                let remaining = deadline.map_or(self.shutdown_timeout, |deadline| {
                    deadline.saturating_duration_since(Instant::now())
                });
                if !wait_for_runner_exit(worker, remaining)
                    && backpressure_deadline_expired(deadline)
                {
                    return Err(error::fmt!(
                        SocketError,
                        "QWP/WebSocket close drain timed out waiting for recycled worker"
                    ));
                }
                continue;
            }

            if self.pending_recycle.is_some() {
                self.join_recycle_worker()?;
            }

            let backpressure_generation = self.backpressure.generation();
            {
                let mut store = self.lock_shared()?;
                // A periodic-checkpoint failure is recoverable: the runner
                // keeps retrying it, and close_queue() performs its own
                // covering sync before tearing down an undrained queue. Do
                // not let the public durability latch prevent close from
                // reaching either recovery path.
                check_store_terminal_error(&store)?;
                if store.all_published_receipts_resolved() {
                    // Storage maintenance performs file work off the
                    // publication-store lock. A task may own segment mappings,
                    // create a hot-spare file, or unlink a retired segment, so
                    // wait for the entire task (including deferred cleanup) to
                    // retire before close tears down the slot.
                    if !store
                        .storage_maintenance_in_flight()
                        .map_err(driver_error_to_error_without_state)?
                    {
                        store
                            .close_queue()
                            .map_err(driver_error_to_error_without_state)?;
                        return Ok(());
                    }
                }
            }

            if !self.wait_for_publication_capacity(backpressure_generation, deadline) {
                return Err(error::fmt!(
                    SocketError,
                    "QWP/WebSocket close drain timed out before all published frames were acknowledged"
                ));
            }
        }
    }

    fn lock_shared(&self) -> crate::Result<std::sync::MutexGuard<'_, QwpWsPublicationStore<Q>>> {
        self.shared
            .lock()
            .map_err(|_| error::fmt!(SocketError, "QWP/WebSocket runner state lock is poisoned"))
    }

    /// Whether the queue has room for a deferred frame AND the frame that will
    /// commit it, or `None` when the runner has no producer and cannot read the
    /// queue without blocking on the driver.
    fn has_deferred_commit_headroom(&self) -> Option<bool> {
        if let Some(producer) = self.producer.as_ref() {
            return Some(producer.has_deferred_commit_headroom());
        }
        // Only reached once `take_producer` has run (close drain), so this is
        // not the publishing path. try_lock, not lock: the answer only informs
        // a defer/commit choice and both answers are safe, so blocking the
        // foreground on the driver thread to learn it is the worse trade.
        let store = self.shared.try_lock().ok()?;
        Some(store.progress_view().has_deferred_commit_headroom())
    }

    fn wait_for_publication_capacity(&self, generation: u64, deadline: Option<Instant>) -> bool {
        self.backpressure.wait_for_change(generation, deadline)
    }
}

impl BackpressureNotifier {
    fn new() -> Self {
        Self {
            lock: Mutex::new(()),
            available: Condvar::new(),
            generation: AtomicU64::new(0),
        }
    }

    fn generation(&self) -> u64 {
        self.generation.load(Ordering::Acquire)
    }

    fn notify_all(&self) {
        let _guard = self.lock();
        self.generation.fetch_add(1, Ordering::Release);
        self.available.notify_all();
    }

    fn wait_for_change(&self, generation: u64, deadline: Option<Instant>) -> bool {
        let mut guard = self.lock();
        while self.generation.load(Ordering::Acquire) == generation {
            let Some(deadline) = deadline else {
                guard = match self.available.wait(guard) {
                    Ok(guard) => guard,
                    Err(poisoned) => poisoned.into_inner(),
                };
                continue;
            };
            if backpressure_deadline_expired(Some(deadline)) {
                return false;
            }
            let wait_for = deadline.saturating_duration_since(Instant::now());
            if wait_for.is_zero() {
                return false;
            }
            guard = match self.available.wait_timeout(guard, wait_for) {
                Ok((guard, _)) => guard,
                Err(poisoned) => {
                    let (guard, _) = poisoned.into_inner();
                    guard
                }
            };
        }
        true
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, ()> {
        match self.lock.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }
}

fn update_atomic_max(cell: &AtomicU64, value: u64) {
    let mut current = cell.load(Ordering::Acquire);
    while value > current {
        match cell.compare_exchange_weak(current, value, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => return,
            Err(observed) => current = observed,
        }
    }
}

impl QwpWsPendingConnect {
    #[allow(clippy::too_many_arguments)]
    fn new(
        host: &str,
        port: &str,
        use_tls: bool,
        tls_settings: Option<TlsSettings>,
        qwp_ws: &QwpWsConfig,
        auth_header: Option<String>,
        durable_ack: bool,
        server_max_batch_size: Arc<AtomicUsize>,
        traffic_gate: Arc<TrafficGate>,
        delta_dict_enabled: bool,
        recovered_dict_entries: Vec<u8>,
        recovered_dict_count: u32,
    ) -> Self {
        Self {
            host: host.to_string(),
            port: port.to_string(),
            use_tls,
            tls_settings,
            qwp_ws: qwp_ws.clone(),
            auth_header,
            reconnect_policy: ReconnectPolicy::bounded(
                *qwp_ws.reconnect_max_duration,
                *qwp_ws.reconnect_initial_backoff,
                *qwp_ws.reconnect_max_backoff,
            ),
            durable_ack,
            server_max_batch_size,
            traffic_gate,
            delta_dict_enabled,
            recovered_dict_entries,
            recovered_dict_count,
        }
    }

    fn connect_with_retry(
        &self,
        stop: &AtomicBool,
    ) -> Result<Option<BlockingQwpWsTransport>, crate::Error> {
        let started = Instant::now();
        let deadline = started.checked_add(self.reconnect_policy.max_duration());
        let endpoints = qwp_ws_configured_endpoints(&self.host, &self.port, &self.qwp_ws);
        let mut tracker = QwpWsHostHealthTracker::new(endpoints.len());
        let mut previous_idx = None;
        let mut backoff = self.reconnect_policy.initial_backoff();
        let mut attempts = 0usize;
        let mut last_error = None;

        while !stop.load(Ordering::Acquire)
            && deadline.is_none_or(|deadline| Instant::now() < deadline)
        {
            attempts += 1;
            match connect_qwp_ws_endpoint_round(
                &endpoints,
                &mut tracker,
                &mut previous_idx,
                None,
                self.use_tls,
                self.tls_settings.clone(),
                // Runner-owned: the 30s shutdown wait races this dial, so an
                // unset connect_timeout must not fall back to the OS deadline.
                QwpWsConnectKind::ForegroundBounded,
                &self.qwp_ws,
                self.auth_header.as_deref(),
                self.qwp_ws.conn_events.as_deref(),
                Some(&self.traffic_gate),
            ) {
                Ok(connected) => {
                    return Ok(Some(BlockingQwpWsTransport::from_connected(
                        Arc::clone(&endpoints),
                        tracker,
                        self.use_tls,
                        self.tls_settings.clone(),
                        QwpWsConnectKind::Foreground,
                        self.qwp_ws.clone(),
                        self.auth_header.clone(),
                        Arc::clone(&self.server_max_batch_size),
                        Some(Arc::clone(&self.traffic_gate)),
                        connected,
                    )));
                }
                Err(err) if reconnect_error_is_terminal(&err) => return Err(err),
                Err(err) => {
                    let role_reject = is_qwp_ws_role_reject_error(&err);
                    last_error = Some(err);
                    let sleep_for = reconnect_sleep_duration(
                        role_reject,
                        self.reconnect_policy.initial_backoff(),
                        backoff,
                    );
                    if !sleep_before_runner_reconnect(deadline, sleep_for, stop) {
                        break;
                    }
                    backoff = if role_reject {
                        self.reconnect_policy.initial_backoff()
                    } else {
                        double_duration(backoff).min(self.reconnect_policy.max_backoff())
                    };
                }
            }
        }

        if stop.load(Ordering::Acquire) {
            Ok(None)
        } else {
            Err(retry_budget_exhausted_error(
                "QWP/WebSocket async initial connect",
                attempts,
                started,
                last_error,
            ))
        }
    }
}

impl SyncQwpWsPendingRunnerCore {
    fn drive_step<Q>(
        &mut self,
        shared: &Arc<Mutex<QwpWsPublicationStore<Q>>>,
        stop: &AtomicBool,
    ) -> RunnerStep
    where
        Q: PublicationLog,
    {
        if let Some(connected) = self.connected.as_mut() {
            return connected.drive_step(shared, stop);
        }

        match self.pending_connect.connect_with_retry(stop) {
            Ok(Some(transport)) => {
                let mut send_core = QwpWsSendCore::new_with_durable_ack_and_rejection_limit(
                    transport,
                    self.pending_connect.reconnect_policy,
                    self.pending_connect.durable_ack,
                    *self.pending_connect.qwp_ws.max_frame_rejections,
                    *self.pending_connect.qwp_ws.poison_min_escalation_window,
                );
                // Enable the symbol-dict catch-up mirror on the same condition the
                // foreground delta-encodes (memory mode always; file mode iff the
                // side-file opened), seeding it from any recovered dictionary so
                // the mirror's count matches the producer's baseline. The two must
                // stay in lockstep.
                if self.pending_connect.delta_dict_enabled {
                    // Take the recovered entries so the buffer is freed after
                    // seeding the mirror rather than living dead in
                    // `pending_connect` (a permanent runner field) for the
                    // connection's life.
                    let recovered =
                        std::mem::take(&mut self.pending_connect.recovered_dict_entries);
                    send_core.enable_delta_dict_owned(
                        recovered,
                        self.pending_connect.recovered_dict_count,
                    );
                }
                self.connected = Some(SyncQwpWsRunnerCore {
                    send_core,
                    progress: self.progress.clone(),
                    cold_effects: VecDeque::new(),
                    backpressure: Arc::clone(&self.backpressure),
                    ok_completed_upper: Arc::clone(&self.ok_completed_upper),
                    lifecycle: self.lifecycle.clone(),
                    recycle: Arc::clone(&self.recycle),
                });
                self.recycle.connected();
                RunnerStep::Continue
            }
            Ok(None) => RunnerStep::Stop,
            Err(err) => {
                if !reconnect_error_is_terminal(&err) {
                    thread::sleep(self.pending_connect.reconnect_policy.initial_backoff());
                    return RunnerStep::Continue;
                }
                let mut store = match shared.lock() {
                    Ok(store) => store,
                    Err(_) => return RunnerStep::Stop,
                };
                store.mark_terminal(Some(err));
                self.backpressure.notify_all();
                RunnerStep::Stop
            }
        }
    }
}

impl<T> SyncQwpWsRunnerCore<T>
where
    T: QwpWsCoreTransport,
{
    fn drive_step<Q>(
        &mut self,
        shared: &Arc<Mutex<QwpWsPublicationStore<Q>>>,
        stop: &AtomicBool,
    ) -> RunnerStep
    where
        Q: PublicationLog,
    {
        if stop.load(Ordering::Acquire) {
            return RunnerStep::Stop;
        }

        if self.lifecycle.is_terminal() {
            return RunnerStep::Stop;
        }

        if self.flush_cold_effects(shared) == RunnerStep::Stop {
            return RunnerStep::Stop;
        }

        if self.send_core.has_pending_reconnect() {
            return self.finish_pending_reconnect(shared, stop, Duration::ZERO, None);
        }

        // Re-register the whole symbol dictionary via a catch-up frame before the
        // first replay frame, when a reconnect armed it (delta mode). The manual
        // send path does the same in QwpWsSendCore::drive_send_available.
        match self.send_core.drive_catch_up() {
            Ok(()) => {}
            Err(CatchUpDriveError::Transport(failure)) => {
                return self.apply_transport_failure(shared, stop, failure);
            }
            Err(CatchUpDriveError::RetryConnection { error, pace }) => {
                return self.reconnect_with_policy(
                    shared,
                    stop,
                    ReconnectReason::RetryableFailure,
                    error,
                    pace,
                );
            }
            Err(CatchUpDriveError::Terminal(err)) => {
                // A terminal catch-up failure (the dictionary cannot be
                // re-registered -- resend required) is a storage/data-integrity
                // outcome, not a transport drop, so classify it the same as the
                // sibling torn-dictionary guard below.
                return self.store_shared_driver_error(shared, DriverError::Storage(err));
            }
        }

        let outbound = match self.send_core.next_outbound_sfa_frame(&self.progress) {
            Ok(outbound) => outbound,
            Err(err) => return self.store_shared_driver_error(shared, err),
        };
        // Torn-dictionary guard (file mode): a replayed delta frame whose base
        // exceeds the re-registered dictionary is unrecoverable -- fail loudly
        // rather than send the server a frame it cannot decode.
        if let Some(frame) = outbound.as_ref()
            && let Err(err) =
                frame.with_view(|view| self.send_core.guard_dict_not_torn(view.payload))
        {
            return self.store_shared_driver_error(shared, DriverError::Storage(err));
        }

        let send_step = match outbound {
            Some(outbound) => self.finish_send(shared, stop, outbound),
            None => self.finish_receive(shared, stop),
        };
        if send_step == RunnerStep::Stop {
            return RunnerStep::Stop;
        }

        let receive_step = self.drain_receive_ready(shared, stop);
        if receive_step == RunnerStep::Stop {
            return RunnerStep::Stop;
        }

        let storage_step = self.finish_storage_maintenance(shared);
        if storage_step == RunnerStep::Stop {
            return RunnerStep::Stop;
        }

        if send_step == RunnerStep::Continue
            || receive_step == RunnerStep::Continue
            || storage_step == RunnerStep::Continue
        {
            RunnerStep::Continue
        } else {
            self.finish_keepalive(shared, stop)
        }
    }

    fn finish_send<Q>(
        &mut self,
        shared: &Arc<Mutex<QwpWsPublicationStore<Q>>>,
        stop: &AtomicBool,
        outbound: OutboundFrame,
    ) -> RunnerStep
    where
        Q: PublicationLog,
    {
        let (frame, send_result) = self.send_core.send_frame(outbound);
        match send_result {
            Ok(send_result) => match self.send_core.finish_send_result_hot(frame, send_result) {
                Ok(QwpWsHotSendProgress::NoResponse { frame, replayed }) => {
                    self.cold_effects
                        .push_back(RunnerColdEffect::Sent { frame, replayed });
                    if self.flush_cold_effects(shared) == RunnerStep::Stop {
                        return RunnerStep::Stop;
                    }
                    let step = step_from_drive_outcome(DriveOutcome::Sent(frame));
                    self.backpressure.notify_all();
                    step
                }
                Ok(QwpWsHotSendProgress::Response {
                    frame,
                    replayed,
                    response,
                }) => {
                    self.cold_effects
                        .push_back(RunnerColdEffect::Sent { frame, replayed });
                    self.finish_response(shared, stop, response)
                }
                Ok(QwpWsHotSendProgress::TransportFailure {
                    frame,
                    replayed,
                    failure,
                }) => {
                    self.cold_effects
                        .push_back(RunnerColdEffect::Sent { frame, replayed });
                    if self.flush_cold_effects(shared) == RunnerStep::Stop {
                        return RunnerStep::Stop;
                    }
                    self.apply_transport_failure(shared, stop, failure)
                }
                Err(err) => self.store_shared_driver_error(shared, err),
            },
            Err(failure) => self.apply_transport_failure(shared, stop, failure),
        }
    }

    fn finish_receive<Q>(
        &mut self,
        shared: &Arc<Mutex<QwpWsPublicationStore<Q>>>,
        stop: &AtomicBool,
    ) -> RunnerStep
    where
        Q: PublicationLog,
    {
        match self.send_core.try_poll_response() {
            Ok(TransportPoll::Response(response)) => self.finish_response(shared, stop, response),
            Ok(TransportPoll::Progress) => RunnerStep::Continue,
            Ok(TransportPoll::Idle) => RunnerStep::Idle,
            Err(failure) => self.apply_transport_failure(shared, stop, failure),
        }
    }

    fn finish_response<Q>(
        &mut self,
        shared: &Arc<Mutex<QwpWsPublicationStore<Q>>>,
        stop: &AtomicBool,
        response: TransportResponse,
    ) -> RunnerStep
    where
        Q: PublicationLog,
    {
        match response {
            TransportResponse::Ack { wire_seq } => {
                match self
                    .send_core
                    .finish_ack_response_sfa(&self.progress, wire_seq)
                {
                    Ok(progress) => self.finish_hot_response_progress(shared, progress),
                    Err(err) => self.store_shared_driver_error(shared, err),
                }
            }
            TransportResponse::DurableOk {
                wire_seq,
                table_seq_txns,
            } => {
                match self.send_core.finish_durable_ok_response_sfa(
                    &self.progress,
                    wire_seq,
                    table_seq_txns,
                ) {
                    Ok(progress) => self.finish_hot_response_progress(shared, progress),
                    Err(err) => self.store_shared_driver_error(shared, err),
                }
            }
            TransportResponse::DurableAck { table_seq_txns } => {
                match self
                    .send_core
                    .finish_durable_ack_response_sfa(&self.progress, table_seq_txns)
                {
                    Ok(progress) => self.finish_hot_response_progress(shared, progress),
                    Err(err) => self.store_shared_driver_error(shared, err),
                }
            }
            response @ TransportResponse::Reject { .. } => {
                let outcome = {
                    let mut store = match shared.lock() {
                        Ok(store) => store,
                        Err(_) => return self.handle_poisoned_lock(),
                    };
                    self.flush_cold_effects_locked(&mut store);
                    match self
                        .send_core
                        .finish_response_defer_reconnect(&mut store, response)
                    {
                        Ok(outcome) => outcome,
                        Err(err) => return self.store_driver_error(&mut store, err),
                    }
                };
                match outcome {
                    DriveOutcome::ReconnectDelay {
                        sleep_for,
                        deadline,
                    } => self.finish_pending_reconnect(shared, stop, sleep_for, deadline),
                    DriveOutcome::Idle => {
                        self.backpressure.notify_all();
                        RunnerStep::Continue
                    }
                    outcome => {
                        let step = step_from_drive_outcome(outcome);
                        self.backpressure.notify_all();
                        step
                    }
                }
            }
        }
    }

    fn finish_hot_response_progress<Q>(
        &mut self,
        shared: &Arc<Mutex<QwpWsPublicationStore<Q>>>,
        progress: QwpWsHotResponseProgress,
    ) -> RunnerStep
    where
        Q: PublicationLog,
    {
        if let Some(fsn) = progress.ok_fsn {
            update_atomic_max(&self.ok_completed_upper, fsn.saturating_add(1));
        }
        self.enqueue_hot_response_events(progress.events);
        if self.flush_cold_effects(shared) == RunnerStep::Stop {
            return RunnerStep::Stop;
        }
        let step = if progress.outcome == DriveOutcome::Idle {
            RunnerStep::Continue
        } else {
            step_from_drive_outcome(progress.outcome)
        };
        self.backpressure.notify_all();
        step
    }

    fn enqueue_hot_response_events(&mut self, events: Vec<DriverEvent>) {
        for event in events {
            match event {
                DriverEvent::CompletedThrough { fsn, wire_seq } => {
                    self.cold_effects
                        .push_back(RunnerColdEffect::CompletedThrough { fsn, wire_seq });
                }
                event => self.cold_effects.push_back(RunnerColdEffect::Event(event)),
            }
        }
    }

    fn drain_receive_ready<Q>(
        &mut self,
        shared: &Arc<Mutex<QwpWsPublicationStore<Q>>>,
        stop: &AtomicBool,
    ) -> RunnerStep
    where
        Q: PublicationLog,
    {
        let mut step = RunnerStep::Idle;
        loop {
            match self.finish_receive(shared, stop) {
                RunnerStep::Continue => step = RunnerStep::Continue,
                RunnerStep::Idle => return step,
                RunnerStep::Stop => return RunnerStep::Stop,
            }
        }
    }

    fn finish_keepalive<Q>(
        &mut self,
        shared: &Arc<Mutex<QwpWsPublicationStore<Q>>>,
        stop: &AtomicBool,
    ) -> RunnerStep
    where
        Q: PublicationLog,
    {
        if self.lifecycle.is_terminal() {
            return RunnerStep::Stop;
        }
        let durable_ack_pending = self.send_core.has_pending_durable_ack();
        match self
            .send_core
            .send_durable_ack_keepalive_if_due(durable_ack_pending)
        {
            Ok(true) => RunnerStep::Idle,
            Ok(false) => RunnerStep::Idle,
            Err(failure) => self.apply_transport_failure(shared, stop, failure),
        }
    }

    fn finish_storage_maintenance<Q>(
        &mut self,
        shared: &Arc<Mutex<QwpWsPublicationStore<Q>>>,
    ) -> RunnerStep
    where
        Q: PublicationLog,
    {
        let task = {
            let mut store = match shared.lock() {
                Ok(store) => store,
                Err(_) => return self.handle_poisoned_lock(),
            };
            self.flush_cold_effects_locked(&mut store);
            if store.is_terminal() {
                return RunnerStep::Stop;
            }
            match store.take_storage_maintenance_step() {
                Ok(task) => task,
                Err(err) => return self.store_driver_error(&mut store, err),
            }
        };

        let Some(task) = task else {
            return RunnerStep::Idle;
        };
        let changed_before_io = task.changes_queue_before_io();
        if changed_before_io {
            self.backpressure.notify_all();
        }

        let result = match task.perform() {
            Ok(result) => result,
            Err(err) => {
                let mut store = match shared.lock() {
                    Ok(store) => store,
                    Err(_) => return self.handle_poisoned_lock(),
                };
                if let Err(completion_err) = store.complete_storage_maintenance() {
                    return self.store_driver_error(&mut store, completion_err);
                }
                return self.store_driver_error(&mut store, err.into());
            }
        };

        let finish = {
            let mut store = match shared.lock() {
                Ok(store) => store,
                Err(_) => return self.handle_poisoned_lock(),
            };
            self.flush_cold_effects_locked(&mut store);
            match store.finish_storage_maintenance(result) {
                Ok(finish) => finish,
                Err(err) => {
                    if let Err(completion_err) = store.complete_storage_maintenance() {
                        return self.store_driver_error(&mut store, completion_err);
                    }
                    return self.store_driver_error(&mut store, err);
                }
            }
        };

        let changed = changed_before_io || finish.did_change();
        if changed {
            self.backpressure.notify_all();
        }
        let cleanup_failure = finish.into_cleanup().and_then(|cleanup| cleanup.perform());
        let terminal = {
            let mut store = match shared.lock() {
                Ok(store) => store,
                Err(_) => return self.handle_poisoned_lock(),
            };
            if let Some(failure) = cleanup_failure
                && let Err(err) = store.record_storage_cleanup_failure(failure)
            {
                if let Err(completion_err) = store.complete_storage_maintenance() {
                    return self.store_driver_error(&mut store, completion_err);
                }
                return self.store_driver_error(&mut store, err);
            }
            if let Err(err) = store.complete_storage_maintenance() {
                return self.store_driver_error(&mut store, err);
            }
            store.is_terminal()
        };
        // Closing may be waiting solely for the task-wide maintenance lease,
        // including a successful task that made no queue-visible change.
        self.backpressure.notify_all();

        if terminal {
            RunnerStep::Stop
        } else if changed {
            RunnerStep::Continue
        } else {
            RunnerStep::Idle
        }
    }

    fn apply_transport_failure<Q>(
        &mut self,
        shared: &Arc<Mutex<QwpWsPublicationStore<Q>>>,
        stop: &AtomicBool,
        failure: TransportFailure,
    ) -> RunnerStep
    where
        Q: PublicationLog,
    {
        let action = {
            let mut store = match shared.lock() {
                Ok(store) => store,
                Err(_) => return self.handle_poisoned_lock(),
            };
            self.flush_cold_effects_locked(&mut store);
            self.send_core.transport_failure_action(&mut store, failure)
        };
        match action {
            QwpWsTransportFailureAction::Reconnect {
                reason,
                initial_error,
                pace,
            } => self.reconnect_with_policy(shared, stop, reason, initial_error, pace),
            QwpWsTransportFailureAction::Terminal(_error) => {
                self.backpressure.notify_all();
                RunnerStep::Stop
            }
        }
    }

    fn reconnect_with_policy<Q>(
        &mut self,
        shared: &Arc<Mutex<QwpWsPublicationStore<Q>>>,
        stop: &AtomicBool,
        reason: ReconnectReason,
        initial_error: crate::Error,
        pace: Duration,
    ) -> RunnerStep
    where
        Q: PublicationLog,
    {
        let mut reconnect = self
            .send_core
            .begin_reconnect("QWP/WebSocket reconnect", reason, initial_error)
            .with_pace(pace);
        self.finish_reconnect_state(shared, stop, &mut reconnect, Duration::ZERO, None)
    }

    fn finish_pending_reconnect<Q>(
        &mut self,
        shared: &Arc<Mutex<QwpWsPublicationStore<Q>>>,
        stop: &AtomicBool,
        sleep_for: Duration,
        deadline: Option<Instant>,
    ) -> RunnerStep
    where
        Q: PublicationLog,
    {
        let Some(mut reconnect) = self.send_core.take_pending_reconnect() else {
            return RunnerStep::Continue;
        };
        self.finish_reconnect_state(shared, stop, &mut reconnect, sleep_for, deadline)
    }

    fn finish_reconnect_state<Q>(
        &mut self,
        shared: &Arc<Mutex<QwpWsPublicationStore<Q>>>,
        stop: &AtomicBool,
        reconnect: &mut QwpWsReconnectState,
        mut sleep_for: Duration,
        mut deadline: Option<Instant>,
    ) -> RunnerStep
    where
        Q: PublicationLog,
    {
        if !self.recycle.enter_reconnect() {
            return RunnerStep::Stop;
        }
        while !stop.load(Ordering::Acquire) {
            if let Some(pace) = reconnect.take_first_attempt_pace() {
                sleep_for = pace;
                deadline = reconnect.deadline();
            }
            if !sleep_before_runner_reconnect(
                deadline.or_else(|| reconnect.deadline()),
                sleep_for,
                stop,
            ) && stop.load(Ordering::Acquire)
            {
                break;
            }

            // Bump the cumulative attempt counter before each call.
            // Brief lock — the reconnect path is the slow one (network
            // I/O, backoff sleeps), so this lock isn't on the hot path
            // and won't perceptibly contend with publishers.
            {
                let mut store = match shared.lock() {
                    Ok(store) => store,
                    Err(_) => return self.handle_poisoned_lock(),
                };
                store.record_reconnect_attempt();
            }
            match self.send_core.reconnect_once(reconnect) {
                Ok(QwpWsReconnectStep::Reconnected { reason }) => {
                    let mut store = match shared.lock() {
                        Ok(store) => store,
                        Err(_) => return self.handle_poisoned_lock(),
                    };
                    self.flush_cold_effects_locked(&mut store);
                    let outcome = self.send_core.finish_reconnect_success(&mut store, reason);
                    self.recycle.connected();
                    return step_from_drive_outcome(outcome);
                }
                Ok(QwpWsReconnectStep::RetryAfter {
                    sleep_for: retry_sleep,
                }) => {
                    deadline = reconnect.deadline();
                    sleep_for = retry_sleep;
                }
                Ok(QwpWsReconnectStep::Terminal(err)) => {
                    if reconnect_error_is_terminal(&err) {
                        return self.mark_store_terminal(shared, err);
                    }
                    sleep_for = reconnect.initial_backoff();
                    *reconnect = reconnect.next_after_retryable_terminal(err);
                    deadline = reconnect.deadline();
                }
                Err(err) => {
                    let mut store = match shared.lock() {
                        Ok(store) => store,
                        Err(_) => return self.handle_poisoned_lock(),
                    };
                    return self.store_driver_error(&mut store, err);
                }
            }
        }

        if stop.load(Ordering::Acquire) {
            RunnerStep::Stop
        } else {
            RunnerStep::Continue
        }
    }

    fn store_driver_error<Q>(
        &self,
        store: &mut QwpWsPublicationStore<Q>,
        err: DriverError,
    ) -> RunnerStep
    where
        Q: PublicationLog,
    {
        let err = driver_error_to_error_from_store(store, err);
        store.mark_terminal(Some(err));
        self.backpressure.notify_all();
        RunnerStep::Stop
    }

    fn flush_cold_effects<Q>(&mut self, shared: &Arc<Mutex<QwpWsPublicationStore<Q>>>) -> RunnerStep
    where
        Q: PublicationLog,
    {
        if self.cold_effects.is_empty() {
            return RunnerStep::Idle;
        }
        match shared.try_lock() {
            Ok(mut store) => {
                self.flush_cold_effects_locked(&mut store);
                RunnerStep::Continue
            }
            Err(TryLockError::WouldBlock) => RunnerStep::Idle,
            Err(TryLockError::Poisoned(_)) => self.handle_poisoned_lock(),
        }
    }

    fn flush_cold_effects_locked<Q>(&mut self, store: &mut QwpWsPublicationStore<Q>)
    where
        Q: PublicationLog,
    {
        while let Some(effect) = self.cold_effects.pop_front() {
            match effect {
                RunnerColdEffect::Sent { frame, replayed } => {
                    store.record_sent_event(frame, replayed);
                }
                RunnerColdEffect::Event(event) => store.record_driver_event(event),
                RunnerColdEffect::CompletedThrough { fsn, wire_seq } => {
                    store.record_completed_through_event(fsn, wire_seq);
                }
            }
        }
    }

    fn store_shared_driver_error<Q>(
        &self,
        shared: &Arc<Mutex<QwpWsPublicationStore<Q>>>,
        err: DriverError,
    ) -> RunnerStep
    where
        Q: PublicationLog,
    {
        let mut store = match shared.lock() {
            Ok(store) => store,
            Err(_) => return self.handle_poisoned_lock(),
        };
        self.store_driver_error(&mut store, err)
    }

    fn mark_store_terminal<Q>(
        &self,
        shared: &Arc<Mutex<QwpWsPublicationStore<Q>>>,
        err: crate::Error,
    ) -> RunnerStep
    where
        Q: PublicationLog,
    {
        let mut store = match shared.lock() {
            Ok(store) => store,
            Err(_) => return self.handle_poisoned_lock(),
        };
        store.mark_terminal(Some(err));
        self.backpressure.notify_all();
        RunnerStep::Stop
    }

    /// Handle a poisoned shared-store lock.
    ///
    /// Flips the lifecycle to `Terminal` via its own atomic, and wakes condvar
    /// waiters so any `publish_replay_payload` blocked on append-deadline
    /// backpressure observes the terminal state on its next loop iteration
    /// instead of timing out per submit. The store's `terminal_error` is left
    /// unset; publishers see a generic terminal error rather than a
    /// runner-specific one, but they fail fast.
    fn handle_poisoned_lock(&self) -> RunnerStep {
        self.lifecycle.terminalize();
        self.backpressure.notify_all();
        RunnerStep::Stop
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RunnerStep {
    Idle,
    Continue,
    Stop,
}

fn step_from_drive_outcome(outcome: DriveOutcome) -> RunnerStep {
    match outcome {
        DriveOutcome::Idle => RunnerStep::Idle,
        DriveOutcome::Terminal => RunnerStep::Stop,
        DriveOutcome::Sent(_)
        | DriveOutcome::Acked { .. }
        | DriveOutcome::Rejected { .. }
        | DriveOutcome::Reconnected { .. }
        | DriveOutcome::ReconnectDelay { .. }
        | DriveOutcome::Progress => RunnerStep::Continue,
    }
}

fn check_store_error<Q: PublicationLog>(store: &QwpWsPublicationStore<Q>) -> crate::Result<()> {
    store
        .check_durability()
        .map_err(driver_error_to_error_without_state)?;
    check_store_terminal_error(store)
}

fn check_store_terminal_error<Q: PublicationLog>(
    store: &QwpWsPublicationStore<Q>,
) -> crate::Result<()> {
    if let Some(err) = store.terminal_error() {
        return Err(err.clone());
    }
    if store.is_terminal() {
        return Err(error::fmt!(SocketError, "QWP/WebSocket sender is terminal"));
    }
    Ok(())
}

fn driver_error_to_error_from_store<Q: PublicationLog>(
    store: &QwpWsPublicationStore<Q>,
    err: DriverError,
) -> crate::Error {
    match err {
        DriverError::Terminal => store
            .terminal_error()
            .cloned()
            .unwrap_or_else(|| error::fmt!(SocketError, "QWP/WebSocket sender is terminal")),
        err => driver_error_to_error_without_state(err),
    }
}

fn runner_reconnect_deadline_expired(deadline: Option<Instant>) -> bool {
    deadline.is_some_and(|deadline| Instant::now() >= deadline)
}

fn backpressure_deadline_expired(deadline: Option<Instant>) -> bool {
    deadline.is_some_and(|deadline| Instant::now() >= deadline)
}

fn sleep_before_runner_reconnect(
    deadline: Option<Instant>,
    backoff: Duration,
    stop: &AtomicBool,
) -> bool {
    if backoff.is_zero() {
        return !stop.load(Ordering::Acquire) && !runner_reconnect_deadline_expired(deadline);
    }

    let sleep_for = match deadline {
        Some(deadline) => {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return false;
            }
            backoff.min(remaining)
        }
        None => backoff,
    };
    let sleep_started = Instant::now();
    while !stop.load(Ordering::Acquire) {
        let remaining = sleep_for.saturating_sub(sleep_started.elapsed());
        if remaining.is_zero() {
            break;
        }
        thread::sleep(remaining.min(Duration::from_millis(50)));
    }
    !stop.load(Ordering::Acquire) && !runner_reconnect_deadline_expired(deadline)
}

impl<Q> Drop for SyncQwpWsRunner<Q> {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Err(err) = self.traffic_gate.shutdown() {
            log::warn!("could not shut down QWP/WebSocket runner traffic: {err}");
        }
        if let Some(thread) = self.thread.take() {
            let timeout = if self
                .pending_recycle
                .as_ref()
                .is_some_and(|pending| pending.wait_spent)
            {
                Duration::ZERO
            } else {
                self.shutdown_timeout
            };
            if wait_for_runner_exit(&thread, timeout) {
                if thread.join().is_err() {
                    log::error!("QWP/WebSocket runner thread panicked during shutdown");
                }
            } else {
                log::error!(
                    "QWP/WebSocket runner did not stop within {:?}; detaching it while its \
                     publication store and slot lock remain retained by the worker",
                    timeout
                );
            }
        }
    }
}

fn wait_for_runner_exit(thread: &thread::JoinHandle<()>, timeout: Duration) -> bool {
    let started = Instant::now();
    while !thread.is_finished() {
        let remaining = timeout.saturating_sub(started.elapsed());
        if remaining.is_zero() {
            return false;
        }
        thread::sleep(remaining.min(QWP_WS_RUNNER_SHUTDOWN_POLL));
    }
    true
}

fn open_configured_qwp_ws_queue(qwp_ws: &QwpWsConfig) -> crate::Result<SfaSlotQueue> {
    if matches!(
        *qwp_ws.sf_durability,
        SfDurability::Flush | SfDurability::Append
    ) {
        let durability = qwp_ws.sf_durability.as_conf_value();
        return Err(error::fmt!(
            ConfigError,
            "sf_durability={durability} is not yet supported (use sf_durability=memory or periodic)"
        ));
    }

    let max_bytes = usize_from_config("sf_max_total_bytes", qwp_ws.sf_max_total_bytes())?;
    let periodic_sync_interval = qwp_ws.periodic_sync_interval();

    if let Some(sf_dir) = qwp_ws.sf_dir.as_ref() {
        return SfaSlotQueue::open(SfaSlotOptions {
            sf_dir: sf_dir.clone(),
            sender_id: qwp_ws.sender_id.to_string(),
            segment_size_bytes: *qwp_ws.sf_max_segment_bytes,
            max_bytes,
            periodic_sync_interval,
        })
        .map_err(|err| match err {
            SfaQueueError::SlotInUse { slot_dir, holder } => crate::Error::new(
                if qwp_ws.pool_managed_slot {
                    crate::ErrorCode::ConfigError
                } else {
                    crate::ErrorCode::SocketError
                },
                format!(
                    "QWP/WebSocket store-and-forward slot is already in use \
                     [slot={}, holder={}]. Another process or pool holds this \
                     slot; use a unique sender_id per producer.",
                    slot_dir.display(),
                    holder
                ),
            ),
            // Intentionally propagate once; the next construction revalidates
            // the healed chain.
            SfaQueueError::SanitizedResidue { path } => error::fmt!(
                SocketError,
                "QWP/WebSocket store-and-forward recovery repaired sealed residue at {}; retry sender construction once. A repeated recovery error requires operator intervention.",
                path.display()
            ),
            err => error::fmt!(
                SocketError,
                "Could not open QWP/WebSocket Store-and-Forward queue: {:?}",
                err
            ),
        });
    }

    if periodic_sync_interval.is_some() {
        return Err(error::fmt!(
            ConfigError,
            "sf_durability=periodic requires sf_dir"
        ));
    }
    SfaSlotQueue::open_memory(SfaMemoryQueueOptions {
        segment_size_bytes: *qwp_ws.sf_max_segment_bytes,
        max_bytes,
    })
    .map_err(|err| {
        error::fmt!(
            ConfigError,
            "Invalid QWP/WebSocket memory SFA queue configuration: {:?}",
            err
        )
    })
}

fn usize_from_config(name: &str, value: u64) -> crate::Result<usize> {
    usize::try_from(value).map_err(|_| {
        error::fmt!(
            ConfigError,
            "{name} value is too large for this platform [value={value}]"
        )
    })
}

// ---------- minimal SHA-1 for Sec-WebSocket-Accept ----------

// ---------- frame I/O ----------

fn random_mask() -> [u8; 4] {
    let mut mask = [0u8; 4];
    rand::rng().fill_bytes(&mut mask);
    mask
}

/// Write a single binary frame (FIN=1, opcode=0x2). Mask-bit set as required for
/// client → server frames. `out` is a scratch buffer; the frame is then written
/// to `stream` in one or more `write_all` calls.
pub(crate) fn write_binary_frame<W: Write>(
    stream: &mut W,
    out: &mut Vec<u8>,
    payload: &[u8],
) -> std::io::Result<()> {
    codec::write_frame_to_buf(out, Opcode::Binary, payload, random_mask());
    stream.write_all(out)
}

pub(crate) fn write_ping_frame<W: Write>(
    stream: &mut W,
    out: &mut Vec<u8>,
    payload: &[u8],
) -> std::io::Result<()> {
    codec::write_frame_to_buf(out, Opcode::Ping, payload, random_mask());
    stream.write_all(out)
}

/// Read one full WebSocket message into `out`. Reassembles fragmented frames.
/// Replies to PING with PONG and treats CLOSE as an error. Returns the opcode
/// of the first data frame (text/binary).
#[cfg(test)]
pub(crate) fn read_message<S: Read + Write>(
    stream: &mut S,
    scratch: &mut Vec<u8>,
    out: &mut Vec<u8>,
) -> crate::Result<u8> {
    read_message_with_close(stream, scratch, out).map_err(WsMessageError::into_error)
}

#[derive(Debug)]
pub(crate) struct WsCloseFrame {
    pub(crate) code: Option<u16>,
    pub(crate) reason: String,
}

impl WsCloseFrame {
    pub(crate) fn is_orderly(&self) -> bool {
        matches!(self.code, Some(1000 | 1001))
    }

    pub(crate) fn into_error(self) -> crate::Error {
        error::fmt!(
            SocketError,
            "WebSocket connection closed by server{}",
            self.display_suffix()
        )
    }

    fn display_suffix(&self) -> String {
        match (self.code, self.reason.is_empty()) {
            (Some(code), true) => format!(" (code={code})"),
            (Some(code), false) => format!(" (code={code}, reason={})", self.reason),
            (None, _) => String::new(),
        }
    }
}

#[derive(Debug)]
pub(crate) enum WsMessageError {
    Close(WsCloseFrame),
    ProtocolViolation(String),
    Error(crate::Error),
}

impl WsMessageError {
    #[cfg(test)]
    pub(crate) fn into_error(self) -> crate::Error {
        match self {
            Self::Close(close) => close.into_error(),
            Self::ProtocolViolation(reason) => {
                error::fmt!(SocketError, "WebSocket protocol violation: {reason}")
            }
            Self::Error(err) => err,
        }
    }
}

#[cfg(test)]
pub(crate) fn read_message_with_close<S: Read + Write>(
    stream: &mut S,
    scratch: &mut Vec<u8>,
    out: &mut Vec<u8>,
) -> Result<u8, WsMessageError> {
    out.clear();
    let mut first_opcode: Option<u8> = None;
    let mut control_payload = [0u8; MAX_CONTROL_FRAME_PAYLOAD_BYTES];
    loop {
        let header = read_frame_header(stream)?;
        match header.opcode {
            OPCODE_PING => {
                let payload = read_control_frame_payload(stream, header, &mut control_payload)?;
                codec::write_frame_to_buf(scratch, Opcode::Pong, payload, random_mask());
                stream.write_all(scratch).map_err(|io| {
                    WsMessageError::Error(error::fmt!(
                        SocketError,
                        "Could not send WebSocket PONG: {}",
                        io
                    ))
                })?;
                continue;
            }
            OPCODE_PONG => {
                read_control_frame_payload(stream, header, &mut control_payload)?;
                continue;
            }
            OPCODE_CLOSE => {
                let payload = read_control_frame_payload(stream, header, &mut control_payload)?;
                return match codec::parse_ws_close_payload(payload) {
                    Ok((code, reason)) => Err(WsMessageError::Close(WsCloseFrame { code, reason })),
                    Err(reason) => Err(WsMessageError::ProtocolViolation(reason)),
                };
            }
            OPCODE_TEXT | OPCODE_BINARY => {
                if first_opcode.is_some() {
                    return Err(WsMessageError::ProtocolViolation(
                        "Unexpected new data frame mid-message".to_string(),
                    ));
                }
                first_opcode = Some(header.opcode);
                read_payload_into(stream, out, header.payload_len)?;
            }
            OPCODE_CONTINUATION => {
                if first_opcode.is_none() {
                    return Err(WsMessageError::ProtocolViolation(
                        "Continuation frame without prior data frame".to_string(),
                    ));
                }
                read_payload_into(stream, out, header.payload_len)?;
            }
            other => {
                return Err(WsMessageError::ProtocolViolation(format!(
                    "Unknown WebSocket opcode: 0x{:x}",
                    other
                )));
            }
        }
        if header.fin {
            return Ok(first_opcode.unwrap());
        }
    }
}

pub(crate) struct WsFrameReader {
    input: Vec<u8>,
    read_pos: usize,
    fragment_opcode: Option<u8>,
    message: Vec<u8>,
    #[cfg(test)]
    max_message_bytes: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WsFrameRead {
    Message { opcode: u8 },
    Progress,
    Idle,
}

impl WsFrameReader {
    pub(crate) fn new() -> Self {
        Self {
            input: Vec::with_capacity(16 * 1024),
            read_pos: 0,
            fragment_opcode: None,
            message: Vec::with_capacity(16 * 1024),
            #[cfg(test)]
            max_message_bytes: MAX_INBOUND_MESSAGE_BYTES,
        }
    }

    pub(crate) fn with_initial_input(input: Vec<u8>) -> Self {
        let mut reader = Self::new();
        if !input.is_empty() {
            reader.input = input;
        }
        reader
    }

    #[cfg(test)]
    fn with_max_message_bytes_for_test(max_message_bytes: usize) -> Self {
        let mut reader = Self::new();
        reader.max_message_bytes = max_message_bytes;
        reader
    }

    pub(crate) fn message(&self) -> &[u8] {
        &self.message
    }

    pub(crate) fn clear_message(&mut self) {
        self.message.clear();
    }

    pub(crate) fn try_read_one(
        &mut self,
        stream: &mut WsStream,
        scratch: &mut Vec<u8>,
    ) -> Result<WsFrameRead, WsMessageError> {
        match self.try_parse_buffered_one(stream, scratch)? {
            WsFrameRead::Idle => {}
            read => return Ok(read),
        }

        let mut read_buf = [0u8; 8192];
        match stream.read_nonblocking_once(&mut read_buf) {
            Ok(0) => {
                return Err(WsMessageError::Error(error::fmt!(
                    SocketError,
                    "WebSocket connection closed by server"
                )));
            }
            Ok(n) => self.input.extend_from_slice(&read_buf[..n]),
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                return Ok(WsFrameRead::Idle);
            }
            Err(err) => {
                return Err(WsMessageError::Error(error::fmt!(
                    SocketError,
                    "Could not read WebSocket frame: {}",
                    err
                )));
            }
        }

        self.try_parse_buffered_one(stream, scratch)
    }

    #[cfg(test)]
    fn append_input_for_test(&mut self, input: &[u8]) {
        self.input.extend_from_slice(input);
    }

    #[cfg(test)]
    fn try_read_buffered_for_test<W: Write>(
        &mut self,
        writer: &mut W,
        scratch: &mut Vec<u8>,
    ) -> Result<WsFrameRead, WsMessageError> {
        self.try_parse_buffered_one(writer, scratch)
    }

    fn try_parse_buffered_one<W: Write>(
        &mut self,
        writer: &mut W,
        scratch: &mut Vec<u8>,
    ) -> Result<WsFrameRead, WsMessageError> {
        let Some(header) = self.peek_buffered_frame_header()? else {
            return Ok(WsFrameRead::Idle);
        };
        match header.opcode {
            OPCODE_PING => {
                let payload = self.payload_slice(header);
                codec::write_frame_to_buf(scratch, Opcode::Pong, payload, random_mask());
                writer.write_all(scratch).map_err(|io| {
                    WsMessageError::Error(error::fmt!(
                        SocketError,
                        "Could not send WebSocket PONG: {}",
                        io
                    ))
                })?;
                self.consume_frame(header.frame_end);
                Ok(WsFrameRead::Progress)
            }
            OPCODE_PONG => {
                self.consume_frame(header.frame_end);
                Ok(WsFrameRead::Progress)
            }
            OPCODE_CLOSE => {
                let parse_result = codec::parse_ws_close_payload(self.payload_slice(header));
                self.consume_frame(header.frame_end);
                match parse_result {
                    Ok((code, reason)) => Err(WsMessageError::Close(WsCloseFrame { code, reason })),
                    Err(reason) => Err(WsMessageError::ProtocolViolation(reason)),
                }
            }
            OPCODE_TEXT | OPCODE_BINARY => {
                if self.fragment_opcode.is_some() {
                    return Err(WsMessageError::ProtocolViolation(
                        "Unexpected new data frame mid-message".to_string(),
                    ));
                }
                self.message.clear();
                self.append_message_payload(header)?;
                self.consume_frame(header.frame_end);
                if header.fin {
                    Ok(WsFrameRead::Message {
                        opcode: header.opcode,
                    })
                } else {
                    self.fragment_opcode = Some(header.opcode);
                    Ok(WsFrameRead::Progress)
                }
            }
            OPCODE_CONTINUATION => {
                let Some(opcode) = self.fragment_opcode else {
                    return Err(WsMessageError::ProtocolViolation(
                        "Continuation frame without prior data frame".to_string(),
                    ));
                };
                self.append_message_payload(header)?;
                self.consume_frame(header.frame_end);
                if header.fin {
                    self.fragment_opcode = None;
                    Ok(WsFrameRead::Message { opcode })
                } else {
                    Ok(WsFrameRead::Progress)
                }
            }
            other => Err(WsMessageError::ProtocolViolation(format!(
                "Unknown WebSocket opcode: 0x{:x}",
                other
            ))),
        }
    }

    fn peek_buffered_frame_header(&self) -> Result<Option<BufferedFrameHeader>, WsMessageError> {
        let available = self.input.len().saturating_sub(self.read_pos);
        if available < 2 {
            return Ok(None);
        }
        let frame = &self.input[self.read_pos..];
        let fin = (frame[0] & 0x80) != 0;
        let opcode = frame[0] & 0x0F;
        if frame[0] & WS_RSV_MASK != 0 {
            return Err(WsMessageError::ProtocolViolation(
                "WebSocket RSV bits are set but no extensions were negotiated".to_string(),
            ));
        }
        let masked = (frame[1] & 0x80) != 0;
        if masked {
            return Err(WsMessageError::ProtocolViolation(
                "WebSocket server frame must not be masked".to_string(),
            ));
        }

        let len_short = frame[1] & 0x7F;
        let (header_len, payload_len) = match len_short {
            126 => {
                if available < 4 {
                    return Ok(None);
                }
                (4, u16::from_be_bytes([frame[2], frame[3]]) as u64)
            }
            127 => {
                if available < 10 {
                    return Ok(None);
                }
                (
                    10,
                    u64::from_be_bytes([
                        frame[2], frame[3], frame[4], frame[5], frame[6], frame[7], frame[8],
                        frame[9],
                    ]),
                )
            }
            n => (2, n as u64),
        };

        validate_payload_length_encoding(len_short, payload_len)?;
        if payload_len > MAX_INBOUND_FRAME_BYTES {
            return Err(WsMessageError::ProtocolViolation(format!(
                "WebSocket frame too large: {} bytes",
                payload_len
            )));
        }
        let payload_len = usize::try_from(payload_len).map_err(|_| {
            WsMessageError::ProtocolViolation(format!(
                "WebSocket frame too large for this platform: {} bytes",
                payload_len
            ))
        })?;
        validate_control_frame_header(fin, opcode, payload_len)?;
        let payload_start = self.read_pos + header_len;
        let frame_end = payload_start.checked_add(payload_len).ok_or_else(|| {
            WsMessageError::ProtocolViolation("WebSocket frame too large".to_string())
        })?;
        if self.input.len() < frame_end {
            return Ok(None);
        }
        Ok(Some(BufferedFrameHeader {
            fin,
            opcode,
            payload_start,
            frame_end,
        }))
    }

    fn payload_slice(&self, header: BufferedFrameHeader) -> &[u8] {
        &self.input[header.payload_start..header.frame_end]
    }

    fn append_message_payload(
        &mut self,
        header: BufferedFrameHeader,
    ) -> Result<(), WsMessageError> {
        let payload = &self.input[header.payload_start..header.frame_end];
        let new_len =
            checked_message_len(self.message.len(), payload.len(), self.max_message_bytes())?;
        self.message.extend_from_slice(payload);
        debug_assert_eq!(self.message.len(), new_len);
        Ok(())
    }

    fn max_message_bytes(&self) -> usize {
        #[cfg(test)]
        {
            self.max_message_bytes
        }
        #[cfg(not(test))]
        {
            MAX_INBOUND_MESSAGE_BYTES
        }
    }

    fn consume_frame(&mut self, frame_end: usize) {
        self.read_pos = frame_end;
        if self.read_pos == self.input.len() {
            self.input.clear();
            self.read_pos = 0;
        } else if self.read_pos >= 4096 && self.read_pos * 2 >= self.input.len() {
            self.input.drain(..self.read_pos);
            self.read_pos = 0;
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct BufferedFrameHeader {
    fin: bool,
    opcode: u8,
    payload_start: usize,
    frame_end: usize,
}

#[derive(Debug, Clone, Copy)]
#[cfg(test)]
struct FrameHeader {
    fin: bool,
    opcode: u8,
    payload_len: usize,
}

const MAX_CONTROL_FRAME_PAYLOAD_BYTES: usize = 125;
const MAX_INBOUND_MESSAGE_BYTES: usize = MAX_INBOUND_FRAME_BYTES as usize;
const WS_RSV_MASK: u8 = 0x70;

fn checked_message_len(
    current_len: usize,
    payload_len: usize,
    max_message_bytes: usize,
) -> Result<usize, WsMessageError> {
    let new_len = current_len.checked_add(payload_len).ok_or_else(|| {
        WsMessageError::ProtocolViolation("WebSocket message too large".to_string())
    })?;
    if new_len > max_message_bytes {
        return Err(WsMessageError::ProtocolViolation(format!(
            "WebSocket message too large: {} bytes",
            new_len
        )));
    }
    Ok(new_len)
}

fn validate_payload_length_encoding(len_short: u8, payload_len: u64) -> Result<(), WsMessageError> {
    match len_short {
        126 if payload_len <= 125 => Err(WsMessageError::ProtocolViolation(format!(
            "WebSocket frame length uses non-minimal 16-bit encoding: {} bytes",
            payload_len
        ))),
        127 if payload_len <= 0xffff => Err(WsMessageError::ProtocolViolation(format!(
            "WebSocket frame length uses non-minimal 64-bit encoding: {} bytes",
            payload_len
        ))),
        _ => Ok(()),
    }
}

fn validate_control_frame_header(
    fin: bool,
    opcode: u8,
    payload_len: usize,
) -> Result<(), WsMessageError> {
    if !matches!(opcode, OPCODE_PING | OPCODE_PONG | OPCODE_CLOSE) {
        return Ok(());
    }
    if !fin {
        return Err(WsMessageError::ProtocolViolation(
            "WebSocket control frame must not be fragmented".to_string(),
        ));
    }
    if payload_len > MAX_CONTROL_FRAME_PAYLOAD_BYTES {
        return Err(WsMessageError::ProtocolViolation(format!(
            "WebSocket control frame too large: {} bytes",
            payload_len
        )));
    }
    if opcode == OPCODE_CLOSE && payload_len == 1 {
        return Err(WsMessageError::ProtocolViolation(
            "WebSocket close frame payload length must be 0 or at least 2 bytes".to_string(),
        ));
    }
    Ok(())
}

#[cfg(test)]
fn read_frame_header<R: Read>(stream: &mut R) -> Result<FrameHeader, WsMessageError> {
    let mut hdr = [0u8; 2];
    read_exact_io(stream, &mut hdr, "WebSocket frame header").map_err(WsMessageError::Error)?;
    let fin = (hdr[0] & 0x80) != 0;
    let opcode = hdr[0] & 0x0F;
    if hdr[0] & WS_RSV_MASK != 0 {
        return Err(WsMessageError::ProtocolViolation(
            "WebSocket RSV bits are set but no extensions were negotiated".to_string(),
        ));
    }
    let masked = (hdr[1] & 0x80) != 0;
    if masked {
        return Err(WsMessageError::ProtocolViolation(
            "WebSocket server frame must not be masked".to_string(),
        ));
    }
    let len_short = hdr[1] & 0x7F;
    let payload_len: u64 = match len_short {
        126 => {
            let mut b = [0u8; 2];
            read_exact_io(stream, &mut b, "WebSocket frame length")
                .map_err(WsMessageError::Error)?;
            u16::from_be_bytes(b) as u64
        }
        127 => {
            let mut b = [0u8; 8];
            read_exact_io(stream, &mut b, "WebSocket frame length")
                .map_err(WsMessageError::Error)?;
            u64::from_be_bytes(b)
        }
        n => n as u64,
    };

    validate_payload_length_encoding(len_short, payload_len)?;
    if payload_len > MAX_INBOUND_FRAME_BYTES {
        return Err(WsMessageError::ProtocolViolation(format!(
            "WebSocket frame too large: {} bytes",
            payload_len
        )));
    }

    let payload_len = usize::try_from(payload_len).map_err(|_| {
        WsMessageError::ProtocolViolation(format!(
            "WebSocket frame too large for this platform: {} bytes",
            payload_len
        ))
    })?;
    validate_control_frame_header(fin, opcode, payload_len)?;
    Ok(FrameHeader {
        fin,
        opcode,
        payload_len,
    })
}

#[cfg(test)]
fn read_payload_into<R: Read>(
    stream: &mut R,
    out: &mut Vec<u8>,
    payload_len: usize,
) -> Result<(), WsMessageError> {
    let start = out.len();
    let end = checked_message_len(start, payload_len, MAX_INBOUND_MESSAGE_BYTES)?;
    out.resize(end, 0);
    if payload_len > 0 {
        read_exact_io(stream, &mut out[start..end], "WebSocket frame payload")
            .map_err(WsMessageError::Error)?;
    }
    Ok(())
}

#[cfg(test)]
fn read_control_frame_payload<'a, R: Read>(
    stream: &mut R,
    header: FrameHeader,
    payload: &'a mut [u8; MAX_CONTROL_FRAME_PAYLOAD_BYTES],
) -> Result<&'a [u8], WsMessageError> {
    let payload = &mut payload[..header.payload_len];
    if !payload.is_empty() {
        read_exact_io(stream, payload, "WebSocket control frame payload")
            .map_err(WsMessageError::Error)?;
    }
    Ok(payload)
}

#[cfg(test)]
fn read_exact_io<R: Read>(stream: &mut R, buf: &mut [u8], what: &str) -> crate::Result<()> {
    stream
        .read_exact(buf)
        .map_err(|io| error::fmt!(SocketError, "Could not read {}: {}", what, io))
}

// ---------- HTTP/1.1 upgrade ----------
//
// The actual RFC 6455 §4 client handshake (request build, response read,
// Sec-WebSocket-Accept validation) lives in `crate::ws::handshake`. The
// connect paths below drive `crate::ws::handshake::upgrade` directly and
// then apply the QWP-specific overlay (X-QWP-Version negotiation,
// durable-ack echo, role-reject classification) via the helpers in
// `codec::{qwp_extra_headers, validate_qwp_handshake_headers,
// handshake_error_to_ingress}`.

/// Test-only convenience wrapper used by the QWP replay / protocol probes
/// in `crate::tests::qwp_ws_*`. Mirrors the inline upgrade sequence the
/// connect paths use below, but in a single call so the probes don't need
/// to thread the extras-builder + validate-headers + error-mapper boilerplate
/// through every test harness.
#[cfg(all(test, feature = "_sender-http"))]
#[allow(clippy::too_many_arguments)]
pub(crate) fn perform_upgrade<S: Read + Write>(
    stream: &mut S,
    host_header: &str,
    auth_header: Option<&str>,
    max_version: u32,
    client_id: Option<&str>,
    request_durable_ack: bool,
) -> crate::Result<(u8, Vec<u8>)> {
    let extras = codec::qwp_extra_headers(auth_header, max_version, client_id, request_durable_ack);
    let handshake = crate::ws::handshake::upgrade(stream, host_header, codec::WS_PATH, &extras)
        .map_err(codec::handshake_error_to_ingress)?;
    let result = codec::validate_qwp_handshake_headers(
        &handshake.headers,
        max_version,
        request_durable_ack,
    )?;
    Ok((result.version, handshake.leftover))
}

// ---------- connect ----------

fn complete_qwp_ws_tls_handshake(
    conn: &mut rustls::ClientConnection,
    tcp: &mut NoSigpipeTcp,
    tls_timeout: Duration,
) -> crate::Result<()> {
    while conn.wants_write() || conn.is_handshaking() {
        conn.complete_io(tcp).map_err(|io| {
            if matches!(io.kind(), ErrorKind::TimedOut | ErrorKind::WouldBlock) {
                error::fmt!(
                    TlsError,
                    "Failed to complete TLS handshake: timed out waiting for server response after {:?}.",
                    tls_timeout
                )
            } else {
                error::fmt!(TlsError, "Failed to complete TLS handshake: {}", io)
            }
        })?;
    }
    Ok(())
}

fn resolve_qwp_ws_addrs(host: &str, port: &str) -> crate::Result<Vec<SocketAddr>> {
    use std::net::ToSocketAddrs;

    let port = port
        .parse::<u16>()
        .map_err(|_| error::fmt!(ConfigError, "Invalid port: {:?}", port))?;
    let addrs = (host, port)
        .to_socket_addrs()
        .map_err(|io| {
            error::fmt!(
                CouldNotResolveAddr,
                "Could not resolve {}:{}: {}",
                host,
                port,
                io
            )
        })?
        .collect::<Vec<_>>();
    if addrs.is_empty() {
        return Err(error::fmt!(
            CouldNotResolveAddr,
            "No address found for {}:{}",
            host,
            port
        ));
    }
    Ok(addrs)
}

fn connect_qwp_ws_tcp(
    host: &str,
    port: &str,
    request_timeout: Duration,
    connect_timeout: Option<Duration>,
    traffic_gate: Option<&TrafficGate>,
) -> crate::Result<NoSigpipeTcp> {
    let addrs = resolve_qwp_ws_addrs(host, port)?;
    connect_tcp_to_any_addr(
        host,
        port,
        &addrs,
        request_timeout,
        connect_timeout,
        traffic_gate,
    )
}

fn connect_tcp_to_any_addr(
    host: &str,
    port: &str,
    addrs: &[SocketAddr],
    request_timeout: Duration,
    connect_timeout: Option<Duration>,
    traffic_gate: Option<&TrafficGate>,
) -> crate::Result<NoSigpipeTcp> {
    let mut failures = Vec::new();
    // Stays true only while *every* attempted address failed specifically with
    // a connect timeout — lets us surface a distinct, retryable `ConnectTimeout`
    // rather than burying it under the generic `SocketError`.
    let mut all_timed_out = true;
    for addr in addrs {
        // A dial in flight cannot be interrupted (the fd only reaches the gate
        // after connect returns), so the timeout is per address: stop between
        // addresses once shutdown is requested rather than finishing the walk.
        if traffic_gate.is_some_and(TrafficGate::is_shutdown) {
            return Err(error::fmt!(
                SocketError,
                "QWP/WebSocket runner is shutting down during connect"
            ));
        }
        // `connect_timeout = None` keeps the OS-default blocking dial; `Some`
        // uses the native non-blocking connect + poll + SO_ERROR check that
        // `connect_timeout` implements per platform, bounded per address.
        let res = match connect_timeout {
            Some(d) => TcpStream::connect_timeout(addr, d),
            None => TcpStream::connect(addr),
        };
        match res {
            Ok(tcp) => {
                tcp.set_nodelay(true).ok();
                tcp.set_read_timeout(Some(request_timeout)).ok();
                tcp.set_write_timeout(Some(request_timeout)).ok();
                // macOS only: its default send buffer (~128KB, autotune ramp)
                // is smaller than a typical QWP chunk, so `write_all` blocks
                // mid-frame; an explicit 4MiB is honored there (maxsockbuf
                // 8MiB) and skips the ramp. On Linux an explicit SO_SNDBUF /
                // SO_RCVBUF is silently clamped to net.core.{w,r}mem_max
                // (208KiB stock, granted 2x = ~416KiB) and DISABLES kernel
                // autotuning, which left alone grows the buffers to
                // tcp_{w,r}mem[2] (>= the 4MiB requested here) — the explicit
                // set caps per-connection throughput at ~426KB/RTT on any
                // real-latency path.
                #[cfg(target_os = "macos")]
                {
                    let sock = socket2::SockRef::from(&tcp);
                    sock.set_send_buffer_size(4 * 1024 * 1024).ok();
                    sock.set_recv_buffer_size(4 * 1024 * 1024).ok();
                }
                match NoSigpipeTcp::new(tcp) {
                    Ok(wrapped) => return Ok(wrapped),
                    Err(err) => {
                        all_timed_out = false;
                        failures.push(format!("{addr}: SO_NOSIGPIPE setup failed: {err}"));
                        continue;
                    }
                }
            }
            Err(io) => {
                if io.kind() != std::io::ErrorKind::TimedOut {
                    all_timed_out = false;
                }
                failures.push(format!("{addr}: {io}"));
            }
        }
    }
    let msg = format!(
        "Could not connect to {}:{}; tried {}",
        host,
        port,
        failures.join(", ")
    );
    // A dial that burned its `connect_timeout` on every candidate surfaces as a
    // distinct `ConnectTimeout` (still retryable in the reconnect loop) so
    // callers can tell a timed-out dial apart from refused / reset.
    Err(if connect_timeout.is_some() && all_timed_out {
        error::fmt!(ConnectTimeout, "{}", msg)
    } else {
        error::fmt!(SocketError, "{}", msg)
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum QwpWsHostState {
    Healthy,
    HealthUnknown,
    TransientReject,
    FailedThisRound,
    RoleRejected,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum QwpWsZoneTier {
    Same,
    Unknown,
    Other,
}

#[derive(Debug, Clone)]
pub(crate) struct QwpWsHostHealthTracker {
    states: Vec<QwpWsHostState>,
    attempted_this_round: Vec<bool>,
    zone_tiers: Vec<QwpWsZoneTier>,
    last_success_epoch: Vec<u64>,
    success_epoch: u64,
}

impl QwpWsHostHealthTracker {
    pub(crate) fn new(host_count: usize) -> Self {
        assert!(host_count > 0, "host_count must be > 0");
        Self {
            states: vec![QwpWsHostState::HealthUnknown; host_count],
            attempted_this_round: vec![false; host_count],
            zone_tiers: vec![QwpWsZoneTier::Same; host_count],
            last_success_epoch: vec![0; host_count],
            success_epoch: 0,
        }
    }

    pub(super) fn begin_round(&mut self, forget_classifications: bool) {
        let mut sticky_idx = None;
        if forget_classifications {
            let mut best_epoch = 0;
            for idx in 0..self.states.len() {
                if self.states[idx] == QwpWsHostState::Healthy
                    && self.zone_tiers[idx] == QwpWsZoneTier::Same
                    && self.last_success_epoch[idx] > best_epoch
                {
                    best_epoch = self.last_success_epoch[idx];
                    sticky_idx = Some(idx);
                }
            }
        }

        self.attempted_this_round.fill(false);
        if forget_classifications {
            for idx in 0..self.states.len() {
                if Some(idx) != sticky_idx {
                    self.states[idx] = QwpWsHostState::HealthUnknown;
                }
            }
        }
    }

    pub(super) fn is_round_exhausted(&self) -> bool {
        self.attempted_this_round.iter().all(|attempted| *attempted)
    }

    pub(super) fn pick_next(&self) -> Option<usize> {
        const STATE_ORDER: [QwpWsHostState; 5] = [
            QwpWsHostState::Healthy,
            QwpWsHostState::HealthUnknown,
            QwpWsHostState::TransientReject,
            QwpWsHostState::FailedThisRound,
            QwpWsHostState::RoleRejected,
        ];
        const ZONE_ORDER: [QwpWsZoneTier; 3] = [
            QwpWsZoneTier::Same,
            QwpWsZoneTier::Unknown,
            QwpWsZoneTier::Other,
        ];
        for state in STATE_ORDER {
            for zone in ZONE_ORDER {
                for idx in 0..self.states.len() {
                    if !self.attempted_this_round[idx]
                        && self.states[idx] == state
                        && self.zone_tiers[idx] == zone
                    {
                        return Some(idx);
                    }
                }
            }
        }
        None
    }

    /// Like [`Self::pick_next`] but also marks the chosen endpoint
    /// `attempted_this_round` before returning. The pool drives the connect
    /// round through [`QwpWsHealthAccess`], releasing the health lock during
    /// the blocking `establish_connection`; claiming the endpoint while the
    /// lock is still held means concurrent borrows rotate to a *different*
    /// peer instead of piling onto the same slow / black-holed endpoint. The
    /// real outcome is still recorded by the matching `record_*` call once the
    /// attempt finishes (those also set `attempted_this_round`, so the early
    /// claim is idempotent).
    pub(super) fn pick_next_and_claim(&mut self) -> Option<usize> {
        let idx = self.pick_next()?;
        self.attempted_this_round[idx] = true;
        Some(idx)
    }

    pub(super) fn pick_next_and_claim_connect_round(
        &mut self,
        reset_if_exhausted: bool,
    ) -> Option<usize> {
        if reset_if_exhausted && self.is_round_exhausted() {
            self.begin_round(true);
        }
        self.pick_next_and_claim()
    }

    pub(super) fn record_success(&mut self, idx: usize) {
        self.states[idx] = QwpWsHostState::Healthy;
        self.attempted_this_round[idx] = true;
        self.success_epoch = self.success_epoch.saturating_add(1);
        self.last_success_epoch[idx] = self.success_epoch;
    }

    pub(super) fn record_transport_error(&mut self, idx: usize) {
        self.states[idx] = QwpWsHostState::FailedThisRound;
        self.attempted_this_round[idx] = true;
    }

    pub(super) fn record_role_reject(&mut self, idx: usize, transient: bool) {
        self.states[idx] = if transient {
            QwpWsHostState::TransientReject
        } else {
            QwpWsHostState::RoleRejected
        };
        self.attempted_this_round[idx] = true;
    }

    pub(crate) fn record_mid_stream_failure(
        &mut self,
        idx: usize,
        reason: Option<ReconnectReason>,
    ) {
        if reason == Some(ReconnectReason::NotWritable) {
            self.states[idx] = QwpWsHostState::RoleRejected;
        } else if self.states[idx] == QwpWsHostState::Healthy {
            self.states[idx] = QwpWsHostState::FailedThisRound;
        }
    }

    pub(super) fn record_zone(&mut self, _idx: usize, _zone: Option<&str>) {
        // Rust is still client-zone-blind, which matches the spec's zone-unset
        // path: every endpoint remains in the Same tier.
    }
}

/// How [`connect_qwp_ws_endpoint_round`] reaches the health tracker.
///
/// Every tracker mutation/read goes through [`Self::with_tracker`], so an
/// implementation backed by a `Mutex` (the connection pool) acquires and
/// releases the lock *per operation*. The blocking `establish_connection`
/// between those operations therefore runs with **no** health lock held —
/// the fix for the pool's head-of-line blocking, where a single slow /
/// black-holed connect used to stall every other borrow and every dead-sender
/// return that needed the same lock. Single-connection drivers that own the
/// tracker by value implement this as a direct in-place mutation with no
/// locking.
pub(crate) trait QwpWsHealthAccess {
    fn with_tracker<R>(&mut self, f: impl FnOnce(&mut QwpWsHostHealthTracker) -> R) -> R;
}

/// Owned-tracker accessor: the single-connection background / SFA / reconnect
/// drivers hold the tracker by value, so there is no lock to take.
impl QwpWsHealthAccess for &mut QwpWsHostHealthTracker {
    fn with_tracker<R>(&mut self, f: impl FnOnce(&mut QwpWsHostHealthTracker) -> R) -> R {
        f(self)
    }
}

/// Pool accessor: locks the shared tracker for the duration of a single
/// tracker operation only, never across the blocking connect.
pub(crate) struct LockedQwpWsHealth<'a> {
    mutex: &'a Mutex<QwpWsHostHealthTracker>,
}

impl<'a> LockedQwpWsHealth<'a> {
    pub(crate) fn new(mutex: &'a Mutex<QwpWsHostHealthTracker>) -> Self {
        Self { mutex }
    }
}

impl QwpWsHealthAccess for LockedQwpWsHealth<'_> {
    fn with_tracker<R>(&mut self, f: impl FnOnce(&mut QwpWsHostHealthTracker) -> R) -> R {
        // Poison-tolerant like the pool's other lock helpers: a panic in
        // another thread's short locked region must not turn every subsequent
        // borrow/return into a panic.
        let mut guard = self.mutex.lock().unwrap_or_else(|e| e.into_inner());
        f(&mut guard)
    }
}

pub(crate) struct QwpWsConnectRoundSuccess {
    pub(crate) endpoint_idx: usize,
    pub(crate) stream: WsStream,
    pub(crate) negotiated_version: u8,
    pub(crate) server_max_batch_size: usize,
    pub(crate) leftover: Vec<u8>,
}

pub(crate) fn qwp_ws_configured_endpoints(
    host: &str,
    port: &str,
    qwp_ws: &QwpWsConfig,
) -> Arc<[QwpWsEndpoint]> {
    if qwp_ws.endpoints.is_empty() {
        Arc::from([QwpWsEndpoint::new(host.to_string(), port.to_string())])
    } else {
        Arc::from(qwp_ws.endpoints.to_vec())
    }
}

pub(crate) fn is_qwp_ws_role_reject_error(err: &crate::Error) -> bool {
    err.qwp_ws_role_reject().is_some()
}

fn qwp_ws_role_reject_is_transient(err: &crate::Error) -> bool {
    err.qwp_ws_role_reject()
        .is_some_and(|role_reject| role_reject.is_transient())
}

fn qwp_ws_role_reject_zone(err: &crate::Error) -> Option<&str> {
    err.qwp_ws_role_reject()
        .and_then(|role_reject| role_reject.zone.as_deref())
}

fn qwp_ws_all_endpoints_unreachable_error(
    endpoints: &[QwpWsEndpoint],
    last_failure: Option<(usize, crate::Error)>,
) -> crate::Error {
    match last_failure {
        Some((idx, err)) => error::fmt!(
            SocketError,
            "QWP/WebSocket all endpoints unreachable; last endpoint {}:{} failed: {}",
            endpoints[idx].host,
            endpoints[idx].port,
            err
        ),
        None => error::fmt!(SocketError, "QWP/WebSocket all endpoints unreachable"),
    }
}

/// Establish a fresh QWP/WebSocket connection: TCP → optional TLS → HTTP
/// upgrade. Returns the connected stream, the version the server picked, and any
/// WebSocket bytes read after the HTTP upgrade response.
#[allow(clippy::too_many_arguments)]
pub(crate) fn establish_connection(
    host: &str,
    port: &str,
    use_tls: bool,
    tls_settings: Option<TlsSettings>,
    connect_kind: QwpWsConnectKind,
    qwp_ws: &QwpWsConfig,
    auth_header: Option<&str>,
    traffic_gate: Option<&TrafficGate>,
) -> crate::Result<(WsStream, codec::QwpWsHandshakeResult, Vec<u8>)> {
    let auth_timeout = *qwp_ws.auth_timeout;
    let request_timeout = *qwp_ws.request_timeout;
    let connect_timeout =
        effective_connect_timeout(connect_kind.bounded_dial(), *qwp_ws.connect_timeout);

    // Windows safety invariant: while the gate stores tcp's raw socket,
    // traffic_registration must drop before tcp. Keep tcp in this outer scope
    // until every fallible TLS/WebSocket setup step has completed.
    let mut tcp = connect_qwp_ws_tcp(host, port, request_timeout, connect_timeout, traffic_gate)?;
    let traffic_registration = traffic_gate
        .map(|gate| gate.register(tcp.tcp()))
        .transpose()
        .map_err(|io| {
            error::fmt!(
                SocketError,
                "Could not register QWP/WebSocket traffic shutdown handle: {}",
                io
            )
        })?;

    // RFC 9110: an IPv6 literal in a Host header must be bracketed.
    let header_host = if host.contains(':') {
        format!("[{host}]")
    } else {
        host.to_string()
    };
    let host_header = if (use_tls && port == "443") || (!use_tls && port == "80") {
        header_host
    } else {
        format!("{header_host}:{port}")
    };

    let max_version = *qwp_ws.max_protocol_version;
    let client_id = qwp_ws.client_id.as_deref();
    let request_durable_ack = *qwp_ws.request_durable_ack;

    let (stream, handshake_result, leftover) = if use_tls {
        let tls = tls_settings.ok_or_else(|| {
            error::fmt!(ConfigError, "TLS settings missing for QWP/WebSocket Secure")
        })?;
        let cfg: Arc<rustls::ClientConfig> = configure_tls(tls)?;
        let server_name = host
            .to_string()
            .try_into()
            .map_err(|e| error::fmt!(TlsError, "Invalid TLS server name {:?}: {}", host, e))?;
        let mut conn = rustls::ClientConnection::new(cfg, server_name)
            .map_err(|e| error::fmt!(TlsError, "TLS handshake setup failed: {}", e))?;
        tcp.tcp()
            .set_read_timeout(Some(QWP_WS_TLS_HANDSHAKE_TIMEOUT))
            .ok();
        tcp.tcp()
            .set_write_timeout(Some(QWP_WS_TLS_HANDSHAKE_TIMEOUT))
            .ok();
        complete_qwp_ws_tls_handshake(&mut conn, &mut tcp, QWP_WS_TLS_HANDSHAKE_TIMEOUT)?;
        tcp.tcp().set_read_timeout(Some(request_timeout)).ok();
        tcp.tcp().set_write_timeout(Some(request_timeout)).ok();
        // The shared `upgrade()` does both the request write and the
        // response read in one call. Switch SO_RCVTIMEO to `auth_timeout`
        // first: the write happens immediately (doesn't depend on
        // read_timeout), and the response read is what auth_timeout bounds.
        tcp.tcp().set_read_timeout(Some(auth_timeout)).ok();
        let extras =
            codec::qwp_extra_headers(auth_header, max_version, client_id, request_durable_ack);
        let mut tls_stream = rustls::Stream::new(&mut conn, &mut tcp);
        let handshake =
            crate::ws::handshake::upgrade(&mut tls_stream, &host_header, codec::WS_PATH, &extras)
                .map_err(codec::handshake_error_to_ingress)?;
        let handshake_result = codec::validate_qwp_handshake_headers(
            &handshake.headers,
            max_version,
            request_durable_ack,
        )?;
        let leftover = handshake.leftover;
        (
            WsStream::Tls(Box::new(rustls::StreamOwned::new(conn, tcp))),
            handshake_result,
            leftover,
        )
    } else {
        tcp.tcp().set_read_timeout(Some(auth_timeout)).ok();
        let extras =
            codec::qwp_extra_headers(auth_header, max_version, client_id, request_durable_ack);
        let handshake =
            crate::ws::handshake::upgrade(&mut tcp, &host_header, codec::WS_PATH, &extras)
                .map_err(codec::handshake_error_to_ingress)?;
        let handshake_result = codec::validate_qwp_handshake_headers(
            &handshake.headers,
            max_version,
            request_durable_ack,
        )?;
        let leftover = handshake.leftover;
        (WsStream::Plain(tcp), handshake_result, leftover)
    };

    stream
        .set_timeouts(Some(request_timeout), Some(request_timeout))
        .ok();

    if let Some(registration) = traffic_registration {
        registration.keep();
    }
    Ok((stream, handshake_result, leftover))
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn connect_qwp_ws_endpoint_round<A: QwpWsHealthAccess>(
    endpoints: &Arc<[QwpWsEndpoint]>,
    mut health: A,
    previous_idx: &mut Option<usize>,
    previous_failure: Option<ReconnectReason>,
    use_tls: bool,
    tls_settings: Option<TlsSettings>,
    connect_kind: QwpWsConnectKind,
    qwp_ws: &QwpWsConfig,
    auth_header: Option<&str>,
    events: Option<&crate::ingress::conn_events::ConnectionEventSource>,
    traffic_gate: Option<&TrafficGate>,
) -> crate::Result<QwpWsConnectRoundSuccess> {
    // Background (orphan-drainer) walks never narrate: reporting their
    // failures would claim an outage against an endpoint the foreground
    // may be healthily using. Mirrors the Java sender's `if (!background)`
    // guards; health tracking is recorded either way.
    let events = if connect_kind.is_background() {
        None
    } else {
        events
    };
    if let Some(idx) = previous_idx.take() {
        health.with_tracker(|t| t.record_mid_stream_failure(idx, previous_failure));
    }
    let mut last_role_mismatch = None;
    let mut last_transport_failure: Option<(usize, crate::Error)> = None;
    let mut role_reject_count = 0usize;
    let mut version_reject_count = 0usize;
    let mut last_version_reject = None;

    // Pick + claim under the lock, then drop it for the blocking connect, then
    // re-acquire only to record the outcome. The lock is never held across
    // `establish_connection`.
    //
    // Reset and claim under one tracker lock. Otherwise a single-endpoint
    // contender can claim the just-reset round before this caller does.
    // Do this only for the first pick so failed attempts terminate normally.
    let mut first_pick = true;
    while let Some(idx) = health.with_tracker(|t| t.pick_next_and_claim_connect_round(first_pick)) {
        first_pick = false;
        let endpoint = &endpoints[idx];
        let connected = establish_connection(
            &endpoint.host,
            &endpoint.port,
            use_tls,
            tls_settings.clone(),
            connect_kind,
            qwp_ws,
            auth_header,
            traffic_gate,
        );
        if traffic_gate.is_some_and(TrafficGate::is_shutdown) {
            return Err(match connected {
                Ok(_) => error::fmt!(
                    SocketError,
                    "QWP/WebSocket runner is shutting down during connect"
                ),
                Err(err) => err,
            });
        }
        match connected {
            Ok((stream, handshake_result, leftover)) => {
                health.with_tracker(|t| t.record_success(idx));
                *previous_idx = Some(idx);
                return Ok(QwpWsConnectRoundSuccess {
                    endpoint_idx: idx,
                    stream,
                    negotiated_version: handshake_result.version,
                    server_max_batch_size: handshake_result.server_max_batch_size,
                    leftover,
                });
            }
            Err(err) if err.code() == crate::ErrorCode::AuthError => {
                if let Some(events) = events {
                    events.auth_failed(&endpoint.host, &endpoint.port, &err, events.next_attempt());
                }
                return Err(err);
            }
            Err(err) if is_qwp_ws_role_reject_error(&err) => {
                role_reject_count += 1;
                let role_reject = err.qwp_ws_role_reject().cloned();
                let zone = qwp_ws_role_reject_zone(&err).map(str::to_string);
                let transient = qwp_ws_role_reject_is_transient(&err);
                health.with_tracker(|t| {
                    t.record_zone(idx, zone.as_deref());
                    t.record_role_reject(idx, transient);
                });
                let mut err = error::fmt!(
                    RoleMismatch,
                    "QWP/WebSocket role mismatch at {}:{}: {}",
                    endpoint.host,
                    endpoint.port,
                    err
                );
                if let Some(role_reject) = role_reject {
                    err = err.with_qwp_ws_role_reject(role_reject);
                }
                if let Some(events) = events {
                    events.connect_attempt_failed(
                        &endpoint.host,
                        &endpoint.port,
                        &err,
                        events.next_attempt(),
                    );
                }
                last_role_mismatch = Some(err);
            }
            Err(err) => {
                health.with_tracker(|t| t.record_transport_error(idx));
                if let Some(events) = events {
                    events.connect_attempt_failed(
                        &endpoint.host,
                        &endpoint.port,
                        &err,
                        events.next_attempt(),
                    );
                }
                if err.code() == crate::ErrorCode::ProtocolVersionError {
                    version_reject_count += 1;
                    last_version_reject = Some(err);
                } else {
                    last_transport_failure = Some((idx, err));
                }
            }
        }
    }

    // ProtocolVersionError is terminal, so it wins only when every configured
    // endpoint failed with it in THIS round -- counted against endpoints.len()
    // because rounds can be partial (a reconnect round skips the endpoint whose
    // mid-stream failure triggered it). Anything less -- a rolling upgrade
    // where the rest of the fleet is transiently down -- must stay retryable.
    if version_reject_count == endpoints.len()
        && let Some(err) = last_version_reject
    {
        return Err(err);
    }
    if *qwp_ws.request_durable_ack && role_reject_count == endpoints.len() {
        let role_reject = last_role_mismatch
            .as_ref()
            .and_then(|err| err.qwp_ws_role_reject().cloned());
        let mut err = error::fmt!(
            ProtocolVersionError,
            "WebSocket upgrade failed: server did not enable durable ACK; all endpoints rejected by role"
        );
        if let Some(role_reject) = role_reject {
            err = err.with_qwp_ws_role_reject(role_reject);
        }
        return Err(err);
    }
    if let Some(err) = last_role_mismatch {
        return Err(err);
    }
    let err = qwp_ws_all_endpoints_unreachable_error(endpoints, last_transport_failure);
    if let Some(events) = events {
        events.all_endpoints_unreachable(&err);
    }
    Err(err)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn connect_qwp_ws(
    host: &str,
    port: &str,
    use_tls: bool,
    tls_settings: Option<TlsSettings>,
    qwp_ws: &QwpWsConfig,
    auth_header: Option<String>,
) -> crate::Result<SyncProtocolHandler> {
    let mut state =
        connect_qwp_ws_background_state(host, port, use_tls, tls_settings, qwp_ws, auth_header)?;
    // Row background sender: the encoder is the delta encode surface, so it owns
    // the slot's persisted symbol dictionary for write-ahead. (The column sender
    // claims it in new_store_and_forward instead; the two are mutually exclusive.)
    let persisted = state.persisted_symbol_dict.take();
    state
        .encoder
        .as_mut()
        .unwrap()
        .set_persisted_symbol_dict(persisted);
    // The row encoder was already seeded from the recovered entries inside
    // connect_qwp_ws_background_state (and the driver mirror seeds from the send
    // core / pending_connect, not from here), so the copy kept in the handler
    // state is dead weight for the row path -- free it.
    let _ = std::mem::take(&mut state.recovered_dict_entries);
    Ok(SyncProtocolHandler::SyncQwpWs(Box::new(state)))
}

/// Fallible copy of a recovered-dictionary byte region. A ~2 GiB recovery must
/// surface an error, not abort the host via an infallible `to_vec`/`clone` -- that
/// would defeat the fallible `try_reserve`/`MAX_FILE_LEN` guard the side-file
/// reader already applies.
pub(super) fn try_dup_recovered(src: &[u8]) -> crate::Result<Vec<u8>> {
    #[cfg(test)]
    if should_fail_recovered_dict_copy_for_test() {
        return Err(error::fmt!(
            SocketError,
            "injected recovered symbol dictionary allocation failure"
        ));
    }
    let mut v = Vec::new();
    v.try_reserve_exact(src.len()).map_err(|_| {
        error::fmt!(
            SocketError,
            "recovered symbol dictionary is too large to allocate ({} bytes)",
            src.len()
        )
    })?;
    v.extend_from_slice(src);
    Ok(v)
}

pub(crate) fn connect_qwp_ws_background_state(
    host: &str,
    port: &str,
    use_tls: bool,
    tls_settings: Option<TlsSettings>,
    qwp_ws: &QwpWsConfig,
    auth_header: Option<String>,
) -> crate::Result<SyncQwpWsHandlerState> {
    let orphan_config = OrphanDrainerConfig::new(
        host,
        port,
        use_tls,
        tls_settings.clone(),
        qwp_ws,
        auth_header.clone(),
    );
    let server_max_batch_size = Arc::new(AtomicUsize::new(0));
    let traffic_gate = Arc::new(TrafficGate::default());
    let (
        runner,
        encoder,
        delta_dict_enabled,
        recovered_dict_entries,
        recovered_dict_count,
        persisted_symbol_dict,
    ) = if *qwp_ws.initial_connect_retry == QwpWsInitialConnectMode::Async {
        let mut queue = open_configured_qwp_ws_queue(qwp_ws)?;
        // Pull the slot's delta-dict state out of the queue before it moves into
        // the runner: whether delta is on, the recovered entries (to seed the
        // foreground dict + the I/O thread's catch-up mirror), and the side-file
        // handle (routed to the owning foreground for write-ahead).
        let delta_dict_enabled = queue.is_delta_dict_enabled();
        let recovered_dict_entries = try_dup_recovered(queue.recovered_symbol_dict_entries())?;
        let recovered_dict_count = queue.recovered_symbol_dict_count();
        let persisted_symbol_dict = queue.take_persisted_symbol_dict();
        // Async connect builds the send core lazily on the I/O thread; the driver
        // enables its catch-up mirror there (see drive_step). The encoder (used by
        // standalone ingress sender; dormant for the pooled core) delta-encodes on the same
        // condition, seeded from the recovered dictionary so new ids continue above
        // it. The side-file is left in the handler state for the owning foreground
        // to claim (standalone: connect_qwp_ws; pooled: new_store_and_forward).
        //
        // Validate the recovered dictionary SYNCHRONOUSLY here, *before* the runner
        // is spawned. `seed_global_dict` is the fallible validator
        // (`SymbolGlobalDict::seed`: duplicate / torn-tail rejection), and the
        // catch-up mirror the runner arms on connect seeds the SAME recovered bytes
        // verbatim (`SentDictMirror::seed` does not re-validate). A corrupt
        // dictionary must be rejected now -- before the I/O thread connects and
        // replays queued frames -- so the caller's `StoreResendRequired`
        // (`in_doubt == false`, "re-ingest from source") cannot surface only after
        // frames were already committed on the server, which would duplicate them.
        // This mirrors the pre-arm validation the orphan drainer already performs
        // (`qwp_ws_orphan.rs`) -- but note the two diverge on what they do with a
        // failure: this one fails construction, the drainer discards the rejected
        // entries and arms its mirror EMPTY so the drain bootstraps from the
        // stored frames' own delta sections (neither degrades to dense).
        // That asymmetry is deliberate and argued in `SymbolGlobalDict::seed`'s
        // docs; the short of it is that this path has a PRODUCER that would
        // otherwise mint ids the stored frames already reference, while
        // replay-only has none. `seed` can fail `SymbolDictFull` here as well as
        // `StoreResendRequired` -- a well-formed side-file written by a
        // higher-capped client -- and it leaves the dictionary partially seeded
        // either way, so continuing with it is never an option. Failing now
        // leaves the slot intact on disk for a client that can hold it
        // (`store_and_forward_file_mode_recovery_fails_when_the_recovered_dict_
        // exceeds_the_cap`).
        let mut encoder = QwpWsReplayEncoder::new(1);
        encoder.set_delta_dict_enabled(delta_dict_enabled);
        if delta_dict_enabled {
            encoder.seed_global_dict(&recovered_dict_entries, recovered_dict_count)?;
        }
        let pending_connect = QwpWsPendingConnect::new(
            host,
            port,
            use_tls,
            tls_settings,
            qwp_ws,
            auth_header,
            *qwp_ws.request_durable_ack,
            Arc::clone(&server_max_batch_size),
            Arc::clone(&traffic_gate),
            delta_dict_enabled,
            try_dup_recovered(&recovered_dict_entries)?,
            recovered_dict_count,
        );
        let runner = SyncQwpWsRunner::start_pending_connect(
            queue,
            pending_connect,
            *qwp_ws.sf_append_deadline,
            *qwp_ws.error_inbox_capacity,
            qwp_ws.rejection_sink.clone(),
        );
        (
            runner,
            encoder,
            delta_dict_enabled,
            recovered_dict_entries,
            recovered_dict_count,
            persisted_symbol_dict,
        )
    } else {
        let mut parts = open_qwp_ws_parts(
            host,
            port,
            use_tls,
            tls_settings,
            qwp_ws,
            auth_header,
            Arc::clone(&server_max_batch_size),
            Some(Arc::clone(&traffic_gate)),
        )?;
        // Delta symbol dictionaries: memory mode always (the in-process ring is
        // replayed and the I/O thread re-registers the whole dictionary via a
        // catch-up frame on reconnect); file mode iff the persisted side-file
        // opened (its recovered entries seed the encoder dict + driver mirror so
        // ids continue above them). This branch runs for the standalone
        // ingress sender and for pool borrows whose initial connect is not
        // forced async — any non-lazy pool, including the default Off mode;
        // the encoder is live only for the standalone sender and stays
        // dormant for the pooled core.
        // Encoder and mirror enable together to stay in lockstep.
        let delta_dict_enabled = parts.delta_dict_enabled;
        parts.encoder.set_delta_dict_enabled(delta_dict_enabled);
        if delta_dict_enabled {
            parts
                .encoder
                .seed_global_dict(&parts.recovered_dict_entries, parts.recovered_dict_count)?;
            parts
                .send_core
                .enable_delta_dict(&parts.recovered_dict_entries, parts.recovered_dict_count);
        }
        let runner = SyncQwpWsRunner::start_with_append_deadline(
            parts.store,
            parts.send_core,
            *qwp_ws.sf_append_deadline,
            traffic_gate,
        );
        (
            runner,
            parts.encoder,
            delta_dict_enabled,
            parts.recovered_dict_entries,
            parts.recovered_dict_count,
            parts.persisted_symbol_dict,
        )
    };
    let orphan_candidates = orphan_candidates(qwp_ws);
    let orphan_pool = OrphanDrainerPool::start(
        orphan_candidates,
        *qwp_ws.max_background_drainers,
        orphan_config,
    );

    Ok(SyncQwpWsHandlerState {
        encoder: Some(encoder),
        publication_recycle: Some(PublicationRecycle::new(qwp_ws.recycle_settings())),
        runner,
        server_max_batch_size,
        request_durable_ack: *qwp_ws.request_durable_ack,
        sfa_frame_payload_cap: segment_payload_capacity(*qwp_ws.sf_max_segment_bytes),
        sfa_frame_split_target: two_frame_segment_payload_capacity(*qwp_ws.sf_max_segment_bytes),
        orphan_pool,
        close_drain_timeout: *qwp_ws.close_flush_timeout,
        delta_dict_enabled,
        recovered_dict_entries,
        recovered_dict_count,
        persisted_symbol_dict,
        sfa_split_deferral_enabled: qwp_ws.sf_dir.is_none(),
    })
}

fn orphan_candidates(qwp_ws: &QwpWsConfig) -> Vec<std::path::PathBuf> {
    let Some(sf_dir) = qwp_ws.sf_dir.as_ref() else {
        return Vec::new();
    };
    let mut candidates = if *qwp_ws.drain_orphans {
        scan_orphan_slots(
            sf_dir,
            qwp_ws.sender_id.as_str(),
            &qwp_ws.orphan_exclude_managed_slots,
        )
    } else {
        Vec::new()
    };
    let own_slot = sf_dir.join(qwp_ws.sender_id.as_str());
    for slot in &qwp_ws.orphan_extra_slots {
        if slot != &own_slot && is_candidate_orphan(slot) && !candidates.iter().any(|s| s == slot) {
            candidates.push(slot.clone());
        }
    }
    candidates
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn open_manual_qwp_ws(
    host: &str,
    port: &str,
    use_tls: bool,
    tls_settings: Option<TlsSettings>,
    qwp_ws: &QwpWsConfig,
    auth_header: Option<String>,
) -> crate::Result<ManualQwpWsHandlerState> {
    let orphan_config = OrphanDrainerConfig::new(
        host,
        port,
        use_tls,
        tls_settings.clone(),
        qwp_ws,
        auth_header.clone(),
    );
    let server_max_batch_size = Arc::new(AtomicUsize::new(0));
    let traffic_gate = Arc::new(TrafficGate::default());
    let mut parts = open_qwp_ws_parts(
        host,
        port,
        use_tls,
        tls_settings,
        qwp_ws,
        auth_header,
        Arc::clone(&server_max_batch_size),
        Some(Arc::clone(&traffic_gate)),
    )?;
    // Delta symbol dictionaries: the encoder ships only ids new since the dict
    // last grew, and the driver re-registers the whole dictionary via a catch-up
    // frame on reconnect. Enabled in memory mode always, and in file mode once the
    // persisted side-file opened -- then the recovered entries seed the encoder
    // dict + driver mirror (ids continue above them) and the encoder owns the
    // side-file for write-ahead. Manual progress is row-only, so the encoder is
    // the live surface. Encoder and mirror enable together to stay in lockstep.
    let delta_dict_enabled = parts.delta_dict_enabled;
    parts.encoder.set_delta_dict_enabled(delta_dict_enabled);
    if delta_dict_enabled {
        parts
            .encoder
            .seed_global_dict(&parts.recovered_dict_entries, parts.recovered_dict_count)?;
        parts
            .encoder
            .set_persisted_symbol_dict(parts.persisted_symbol_dict.take());
        parts
            .send_core
            .enable_delta_dict(&parts.recovered_dict_entries, parts.recovered_dict_count);
    }
    let orphan_drainers = ManualOrphanDrainers::new(
        orphan_candidates(qwp_ws),
        *qwp_ws.max_background_drainers,
        orphan_config,
    );
    Ok(ManualQwpWsHandlerState {
        recycle: ManualRecycle::new(traffic_gate),
        encoder: Some(parts.encoder),
        publication_recycle: Some(PublicationRecycle::new(qwp_ws.recycle_settings())),
        store: parts.store,
        send_core: parts.send_core,
        server_max_batch_size,
        request_durable_ack: *qwp_ws.request_durable_ack,
        orphan_drainers,
        append_deadline: *qwp_ws.sf_append_deadline,
        close_drain_timeout: *qwp_ws.close_flush_timeout,
    })
}

#[allow(clippy::too_many_arguments)]
fn open_qwp_ws_parts(
    host: &str,
    port: &str,
    use_tls: bool,
    tls_settings: Option<TlsSettings>,
    qwp_ws: &QwpWsConfig,
    auth_header: Option<String>,
    server_max_batch_size: Arc<AtomicUsize>,
    traffic_gate: Option<Arc<TrafficGate>>,
) -> crate::Result<QwpWsConnectedParts> {
    let mut queue = open_configured_qwp_ws_queue(qwp_ws)?;
    let transport = connect_blocking_transport(
        host,
        port,
        use_tls,
        tls_settings,
        qwp_ws,
        auth_header,
        Arc::clone(&server_max_batch_size),
        traffic_gate,
    )?;
    let negotiated_version = transport.negotiated_version();
    // Extract the slot's delta-dict state before the queue moves into the store:
    // whether delta is on, the recovered entries (to seed the producer dict + the
    // driver mirror), and the side-file handle (for the foreground's write-ahead).
    let delta_dict_enabled = queue.is_delta_dict_enabled();
    // Fallible copy: a large recovered dictionary (up to ~2 GiB for a crafted
    // CRC-valid side-file) must surface an error, not abort the host via an
    // infallible `to_vec` -- exactly the guard `try_dup_recovered` documents and the
    // async connect path already applies.
    let recovered_dict_entries = try_dup_recovered(queue.recovered_symbol_dict_entries())?;
    let recovered_dict_count = queue.recovered_symbol_dict_count();
    let persisted_symbol_dict = queue.take_persisted_symbol_dict();
    let mut store = QwpWsPublicationStore::new(queue, *qwp_ws.error_inbox_capacity);
    store.set_rejection_sink(qwp_ws.rejection_sink.clone());
    let send_core = QwpWsSendCore::new_with_durable_ack_and_rejection_limit(
        transport,
        ReconnectPolicy::bounded(
            *qwp_ws.reconnect_max_duration,
            *qwp_ws.reconnect_initial_backoff,
            *qwp_ws.reconnect_max_backoff,
        ),
        *qwp_ws.request_durable_ack,
        *qwp_ws.max_frame_rejections,
        *qwp_ws.poison_min_escalation_window,
    );

    Ok(QwpWsConnectedParts {
        encoder: QwpWsReplayEncoder::new(negotiated_version),
        store,
        send_core,
        delta_dict_enabled,
        recovered_dict_entries,
        recovered_dict_count,
        persisted_symbol_dict,
    })
}

#[allow(clippy::too_many_arguments)]
fn connect_blocking_transport(
    host: &str,
    port: &str,
    use_tls: bool,
    tls_settings: Option<TlsSettings>,
    qwp_ws: &QwpWsConfig,
    auth_header: Option<String>,
    server_max_batch_size: Arc<AtomicUsize>,
    traffic_gate: Option<Arc<TrafficGate>>,
) -> crate::Result<BlockingQwpWsTransport> {
    match *qwp_ws.initial_connect_retry {
        QwpWsInitialConnectMode::Off => BlockingQwpWsTransport::connect(
            host,
            port,
            use_tls,
            tls_settings,
            QwpWsConnectKind::Foreground,
            qwp_ws.clone(),
            auth_header,
            server_max_batch_size,
            traffic_gate,
        ),
        QwpWsInitialConnectMode::Sync | QwpWsInitialConnectMode::Async => {
            connect_blocking_transport_with_retry(
                host,
                port,
                use_tls,
                tls_settings,
                qwp_ws,
                auth_header,
                server_max_batch_size,
                traffic_gate,
            )
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn connect_blocking_transport_with_retry(
    host: &str,
    port: &str,
    use_tls: bool,
    tls_settings: Option<TlsSettings>,
    qwp_ws: &QwpWsConfig,
    auth_header: Option<String>,
    server_max_batch_size: Arc<AtomicUsize>,
    traffic_gate: Option<Arc<TrafficGate>>,
) -> crate::Result<BlockingQwpWsTransport> {
    let started = Instant::now();
    let deadline = started.checked_add(*qwp_ws.reconnect_max_duration);
    let endpoints = qwp_ws_configured_endpoints(host, port, qwp_ws);
    let mut tracker = QwpWsHostHealthTracker::new(endpoints.len());
    let mut previous_idx = None;
    let mut attempts = 0usize;
    let mut backoff = *qwp_ws.reconnect_initial_backoff;
    let mut last_error = None;

    // Always run one full endpoint round: a very short connect budget can
    // already be used up by the time setup finishes.
    while attempts == 0 || deadline.is_none_or(|deadline| Instant::now() < deadline) {
        attempts += 1;
        match connect_qwp_ws_endpoint_round(
            &endpoints,
            &mut tracker,
            &mut previous_idx,
            None,
            use_tls,
            tls_settings.clone(),
            QwpWsConnectKind::Foreground,
            qwp_ws,
            auth_header.as_deref(),
            qwp_ws.conn_events.as_deref(),
            traffic_gate.as_deref(),
        ) {
            Ok(connected) => {
                return Ok(BlockingQwpWsTransport::from_connected(
                    Arc::clone(&endpoints),
                    tracker,
                    use_tls,
                    tls_settings,
                    QwpWsConnectKind::Foreground,
                    qwp_ws.clone(),
                    auth_header,
                    server_max_batch_size,
                    traffic_gate.clone(),
                    connected,
                ));
            }
            Err(err) if reconnect_error_is_terminal(&err) => return Err(err),
            Err(err) => {
                let role_reject = is_qwp_ws_role_reject_error(&err);
                last_error = Some(err);

                let sleep_for = reconnect_sleep_duration(
                    role_reject,
                    *qwp_ws.reconnect_initial_backoff,
                    backoff,
                );
                let Some(deadline) = deadline else {
                    thread::sleep(sleep_for);
                    backoff = if role_reject {
                        *qwp_ws.reconnect_initial_backoff
                    } else {
                        double_duration(backoff).min(*qwp_ws.reconnect_max_backoff)
                    };
                    continue;
                };
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    break;
                }
                thread::sleep(sleep_for.min(remaining));
                backoff = if role_reject {
                    *qwp_ws.reconnect_initial_backoff
                } else {
                    double_duration(backoff).min(*qwp_ws.reconnect_max_backoff)
                };
            }
        }
    }

    Err(retry_budget_exhausted_error(
        "QWP/WebSocket initial connect",
        attempts,
        started,
        last_error,
    ))
}

// ---------- send / receive ----------

/// Public flush entry point: publish through the replay queue and return once
/// the frame is locally accepted. A sender-owned runner advances WebSocket I/O.
pub(crate) fn flush_qwp_ws(
    state: &mut SyncQwpWsHandlerState,
    buffer: &QwpWsColumnarBuffer,
    max_buf_size: usize,
) -> crate::Result<Option<u64>> {
    let mut encoder = state.encoder.take().expect("standalone foreground");
    let result = (|| {
        state.before_publication(&mut encoder, !buffer.is_empty(), false)?;
        if buffer.is_empty() {
            return Ok(None);
        }
        state.runner.check_publication_open()?;
        let result = publish_qwp_ws_buffer(&mut encoder, buffer, max_buf_size, |payload| {
            state.runner.publish_replay_payload(payload)
        })?;
        state.after_publication(encoder.symbol_count());
        Ok(result)
    })();
    state.encoder = Some(encoder);
    result
}

pub(crate) fn publish_qwp_ws_payload_background(
    state: &mut SyncQwpWsHandlerState,
    payload: &[u8],
    max_buf_size: usize,
) -> crate::Result<u64> {
    if payload.is_empty() {
        return Err(error::fmt!(
            InvalidApiCall,
            "Could not flush buffer: QWP/WebSocket encoded message is empty."
        ));
    }
    if payload.len() > max_buf_size {
        return Err(qwp_ws_encoded_message_size_error(
            payload.len(),
            max_buf_size,
        ));
    }
    state.runner.publish_replay_payload(payload)
}

/// Whether a deferred frame may be published without stranding the frame that
/// will commit it.
///
/// A deferred frame is never acked, so the queue storage it occupies is never
/// reclaimed. Publishing one that consumes the slot's last byte budget would
/// leave the committing frame unable to publish at all: it would block on
/// back-pressure until the append deadline and then fail, with the deferred
/// prefix durably queued and nothing able to commit it. This is the
/// store-and-forward counterpart of the direct backend's
/// `Conn::has_sync_commit_slot`.
///
/// Normally answered from the foreground's own producer handle, which takes the
/// engine's state lock briefly. The `try_lock` fallback only applies once the
/// producer has been handed off (close drain), and answers conservatively
/// (`false`) there: committing a frame that could have been deferred costs
/// throughput, deferring one that should have committed costs liveness.
pub(crate) fn sfa_has_deferred_commit_slot(state: &SyncQwpWsHandlerState) -> bool {
    state.sfa_split_deferral_enabled && state.runner.has_deferred_commit_headroom().unwrap_or(false)
}

pub(crate) fn flush_qwp_ws_manual(
    state: &mut ManualQwpWsHandlerState,
    buffer: &QwpWsColumnarBuffer,
    max_buf_size: usize,
) -> crate::Result<Option<u64>> {
    let mut encoder = state.encoder.take().expect("standalone foreground");
    let result = (|| {
        state.before_publication(&mut encoder, !buffer.is_empty(), false)?;
        if buffer.is_empty() {
            return Ok(None);
        }
        let result = publish_qwp_ws_buffer(&mut encoder, buffer, max_buf_size, |payload| {
            manual_submit_with_drive_deadline(
                &mut state.store,
                &mut state.send_core,
                payload,
                state.append_deadline,
            )
            .map_err(|err| driver_error_to_error_from_store(&state.store, err))
        })?;
        state.after_publication(encoder.symbol_count());
        Ok(result)
    })();
    state.encoder = Some(encoder);
    result
}

fn publish_qwp_ws_buffer(
    encoder: &mut QwpWsReplayEncoder,
    buffer: &QwpWsColumnarBuffer,
    max_buf_size: usize,
    publish: impl FnOnce(&[u8]) -> crate::Result<u64>,
) -> crate::Result<Option<u64>> {
    // `encode_and_publish` rolls the dict + side-file back if `publish` fails, so a
    // recoverable publish failure (e.g. `SubmitTimedOut` back-pressure) does not
    // leave the encoder dict ahead of the driver's send mirror and trip the
    // torn-dict guard on the next frame (which would abandon all queued data).
    encoder
        .encode_and_publish(buffer, max_buf_size, publish)
        .map(Some)
}

pub(crate) fn qwp_ws_drive_once(state: &mut ManualQwpWsHandlerState) -> crate::Result<bool> {
    if state.recycle.pending.is_some() {
        return Err(error::fmt!(
            SocketError,
            "QWP/WebSocket publication is parked for dictionary recycling"
        ));
    }
    let outcome = state.send_core.drive_once(&mut state.store);
    let foreground_progress = match outcome {
        Ok(DriveOutcome::Idle) => Ok(false),
        Ok(DriveOutcome::Terminal) => qwp_ws_manual_terminal_error(state),
        Ok(DriveOutcome::ReconnectDelay {
            sleep_for,
            deadline,
        }) => {
            sleep_before_manual_reconnect(deadline, sleep_for, None);
            Ok(true)
        }
        Ok(
            DriveOutcome::Sent(_)
            | DriveOutcome::Acked { .. }
            | DriveOutcome::Rejected { .. }
            | DriveOutcome::Reconnected { .. }
            | DriveOutcome::Progress,
        ) => Ok(true),
        Err(err) => Err(driver_error_to_error_from_store(&state.store, err)),
    }?;
    let orphan_progress = state
        .orphan_drainers
        .as_mut()
        .is_some_and(ManualOrphanDrainers::drive_once);
    Ok(foreground_progress || orphan_progress)
}

pub(crate) fn qwp_ws_published_fsn_background(
    state: &SyncQwpWsHandlerState,
) -> crate::Result<Option<u64>> {
    state.runner.published_fsn()
}

pub(crate) fn qwp_ws_acked_fsn_background(
    state: &SyncQwpWsHandlerState,
) -> crate::Result<Option<u64>> {
    state.runner.acked_fsn()
}

pub(crate) fn qwp_ws_ok_fsn_background(
    state: &SyncQwpWsHandlerState,
) -> crate::Result<Option<u64>> {
    state.runner.ok_fsn()
}

pub(crate) fn qwp_ws_published_fsn_manual(
    state: &ManualQwpWsHandlerState,
) -> crate::Result<Option<u64>> {
    check_manual_driver_error(state)?;
    Ok(state.store.published_fsn())
}

pub(crate) fn qwp_ws_acked_fsn_manual(
    state: &ManualQwpWsHandlerState,
) -> crate::Result<Option<u64>> {
    check_manual_driver_error(state)?;
    Ok(state.store.completed_fsn())
}

/// Manual-mode OK watermark. Manual progress keeps no separate OK tracker,
/// so this is the completed watermark: under `request_durable_ack=on` it
/// advances on the durable ACK, not on the server's ordinary OK.
pub(crate) fn qwp_ws_ok_fsn_manual(state: &ManualQwpWsHandlerState) -> crate::Result<Option<u64>> {
    check_manual_driver_error(state)?;
    Ok(state.store.completed_fsn())
}

pub(crate) fn qwp_ws_check_error_background(state: &SyncQwpWsHandlerState) -> crate::Result<()> {
    state.runner.check_error()
}

pub(crate) fn qwp_ws_check_error_manual(state: &ManualQwpWsHandlerState) -> crate::Result<()> {
    check_manual_driver_error(state)
}

pub(crate) fn qwp_ws_poll_sender_error_background(
    state: &SyncQwpWsHandlerState,
) -> crate::Result<Option<QwpWsSenderError>> {
    state.runner.poll_sender_error()
}

pub(crate) fn qwp_ws_poll_sender_error_notification_background(
    state: &SyncQwpWsHandlerState,
) -> crate::Result<Option<QwpWsSenderError>> {
    state.runner.poll_sender_error_notification()
}

pub(crate) fn qwp_ws_poll_sender_error_manual(
    state: &mut ManualQwpWsHandlerState,
) -> crate::Result<Option<QwpWsSenderError>> {
    Ok(state.store.poll_sender_error())
}

pub(crate) fn qwp_ws_poll_sender_error_notification_manual(
    state: &mut ManualQwpWsHandlerState,
) -> crate::Result<Option<QwpWsSenderError>> {
    Ok(state.store.poll_sender_error_notification())
}

pub(crate) fn qwp_ws_terminal_sender_error_background(
    state: &SyncQwpWsHandlerState,
) -> crate::Result<Option<QwpWsSenderError>> {
    state.runner.terminal_sender_error()
}

pub(crate) fn qwp_ws_terminal_sender_error_manual(
    state: &ManualQwpWsHandlerState,
) -> crate::Result<Option<QwpWsSenderError>> {
    Ok(state.store.terminal_sender_error().cloned())
}

pub(crate) fn qwp_ws_is_terminal_background(state: &SyncQwpWsHandlerState) -> bool {
    state.runner.lifecycle_is_terminal()
}

pub(crate) fn qwp_ws_is_terminal_manual(state: &ManualQwpWsHandlerState) -> bool {
    state.store.is_terminal()
}

pub(crate) fn qwp_ws_sender_errors_dropped_background(
    state: &SyncQwpWsHandlerState,
) -> crate::Result<u64> {
    state.runner.sender_errors_dropped_total()
}

pub(crate) fn qwp_ws_sender_errors_dropped_manual(
    state: &ManualQwpWsHandlerState,
) -> crate::Result<u64> {
    Ok(state.store.sender_errors_dropped_total())
}

pub(crate) fn qwp_ws_counters_background(
    state: &SyncQwpWsHandlerState,
) -> crate::Result<QwpWsCounters> {
    state.runner.counters()
}

pub(crate) fn qwp_ws_counters_manual(
    state: &ManualQwpWsHandlerState,
) -> crate::Result<QwpWsCounters> {
    Ok(state.store.counters())
}

pub(crate) fn qwp_ws_close_drain_background(
    state: &mut SyncQwpWsHandlerState,
) -> crate::Result<()> {
    let result = state.runner.close_drain(state.close_drain_timeout);
    if let Some(mut orphan_pool) = state.orphan_pool.take() {
        orphan_pool.close();
    }
    result
}

/// Non-blocking: stop accepting new publications and wake the runner to flush
/// what is queued. The unified sender pool signals every connection being
/// retired before waiting on any, so a batched close drains in parallel.
pub(crate) fn qwp_ws_begin_close_background(state: &SyncQwpWsHandlerState) {
    state.runner.begin_close();
}

/// Wait (until `deadline`) for the background runner to deliver every published
/// frame, then close the queue and the orphan-drainer pool. A `None` deadline
/// waits indefinitely; an already-elapsed deadline fails fast. Pairs with
/// [`qwp_ws_begin_close_background`].
pub(crate) fn qwp_ws_drain_to_deadline_background(
    state: &mut SyncQwpWsHandlerState,
    deadline: Option<Instant>,
) -> crate::Result<()> {
    let result = state.runner.drain_to_deadline(deadline);
    if let Some(mut orphan_pool) = state.orphan_pool.take() {
        orphan_pool.close();
    }
    result
}

pub(crate) fn qwp_ws_close_drain_manual(state: &mut ManualQwpWsHandlerState) -> crate::Result<()> {
    state.recycle.producer.take();
    if state.close_drain_timeout.is_zero() {
        state.store.set_closing();
        return Ok(());
    }
    let deadline = Instant::now().checked_add(state.close_drain_timeout);
    loop {
        match state.send_core.close_drain_ready_once(&mut state.store) {
            Ok(CloseOutcome::Drained) => return Ok(()),
            Ok(CloseOutcome::Terminal) => return qwp_ws_manual_terminal_error(state),
            Ok(CloseOutcome::Waiting {
                sleep_for,
                deadline: reconnect_deadline,
            }) => {
                sleep_before_manual_reconnect(reconnect_deadline, sleep_for, deadline);
            }
            Ok(CloseOutcome::Timeout) => {
                if backpressure_deadline_expired(deadline) {
                    return Err(error::fmt!(
                        SocketError,
                        "QWP/WebSocket close drain timed out before all published frames were acknowledged"
                    ));
                }
                thread::sleep(BACKPRESSURE_PARK);
            }
            Err(err) => return Err(driver_error_to_error_from_store(&state.store, err)),
        }
    }
}

fn manual_submit_with_drive_deadline<Q, T>(
    store: &mut QwpWsPublicationStore<Q>,
    send_core: &mut QwpWsSendCore<T>,
    payload: &[u8],
    append_deadline: Duration,
) -> Result<u64, DriverError>
where
    Q: PublicationLog,
    T: QwpWsCoreTransport,
{
    let deadline = Instant::now().checked_add(append_deadline);
    loop {
        if store.is_terminal() {
            return Err(DriverError::Terminal);
        }
        match store.try_submit(payload) {
            Ok(receipt) => return Ok(receipt.fsn),
            Err(err) => {
                let Some(backpressure) = driver_error_backpressure_queue(&err) else {
                    return Err(err);
                };
                if backpressure_deadline_expired(deadline) {
                    return Err(DriverError::SubmitTimedOut {
                        backpressure: Some(backpressure),
                    });
                }
                match send_core.drive_once(store)? {
                    DriveOutcome::Idle => sleep_until_backpressure_deadline(deadline),
                    DriveOutcome::ReconnectDelay {
                        sleep_for,
                        deadline: reconnect_deadline,
                    } => sleep_before_manual_reconnect(reconnect_deadline, sleep_for, deadline),
                    _ => {}
                }
            }
        }
    }
}

fn sleep_until_backpressure_deadline(deadline: Option<Instant>) {
    let sleep_for = match deadline {
        Some(deadline) => deadline
            .saturating_duration_since(Instant::now())
            .min(BACKPRESSURE_PARK),
        None => BACKPRESSURE_PARK,
    };
    if !sleep_for.is_zero() {
        thread::sleep(sleep_for);
    }
}

fn sleep_before_manual_reconnect(
    reconnect_deadline: Option<Instant>,
    sleep_for: Duration,
    outer_deadline: Option<Instant>,
) {
    let mut sleep_for = sleep_for;
    if let Some(deadline) = reconnect_deadline {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return;
        }
        sleep_for = sleep_for.min(remaining);
    }
    if let Some(deadline) = outer_deadline {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return;
        }
        sleep_for = sleep_for.min(remaining);
    }
    if !sleep_for.is_zero() {
        thread::sleep(sleep_for);
    }
}

fn check_manual_driver_error(state: &ManualQwpWsHandlerState) -> crate::Result<()> {
    state
        .store
        .check_durability()
        .map_err(driver_error_to_error_without_state)?;
    if let Some(err) = state.store.terminal_error() {
        return Err(err.clone());
    }
    if state.store.is_terminal() {
        return Err(error::fmt!(SocketError, "QWP/WebSocket sender is terminal"));
    }
    Ok(())
}

fn qwp_ws_manual_terminal_error<T>(state: &ManualQwpWsHandlerState) -> crate::Result<T> {
    Err(state
        .store
        .terminal_error()
        .cloned()
        .unwrap_or_else(|| error::fmt!(SocketError, "QWP/WebSocket sender is terminal")))
}

fn double_duration(duration: Duration) -> Duration {
    duration.checked_mul(2).unwrap_or(Duration::MAX)
}

fn driver_error_to_error_without_state(err: DriverError) -> crate::Error {
    match err {
        DriverError::Transport(err) | DriverError::Storage(err) => err,
        DriverError::Queue(err) => error::fmt!(
            InvalidApiCall,
            "QWP/WebSocket queue rejected publication: {:?}",
            err
        ),
        DriverError::SubmitTimedOut { backpressure } => submit_timeout_error(backpressure),
        DriverError::Terminal => error::fmt!(SocketError, "QWP/WebSocket sender is terminal"),
        DriverError::Closing => error::fmt!(InvalidApiCall, "QWP/WebSocket sender is closing"),
        DriverError::UnknownReceipt { fsn } => error::fmt!(
            InvalidApiCall,
            "QWP/WebSocket receipt is unknown [fsn={fsn}]"
        ),
    }
}

fn driver_error_is_backpressure(err: &DriverError) -> bool {
    driver_error_backpressure_queue(err).is_some()
}

fn driver_error_backpressure_queue(err: &DriverError) -> Option<super::qwp_ws_queue::QueueError> {
    use super::qwp_ws_queue::QueueError;
    match err {
        DriverError::Queue(
            err @ (QueueError::FrameCapacityFull { .. }
            | QueueError::ByteCapacityFull { .. }
            | QueueError::StorageSpareNotReady { .. }
            | QueueError::StorageSegmentCapFull { .. }),
        ) => Some(*err),
        _ => None,
    }
}

fn submit_timeout_error(backpressure: Option<super::qwp_ws_queue::QueueError>) -> crate::Error {
    use super::qwp_ws_queue::QueueError;
    match backpressure {
        Some(QueueError::StorageSpareNotReady {
            segment_size_bytes,
            allocated_segment_bytes,
            max_total_bytes,
        }) => error::fmt!(
            SocketError,
            "QWP/WebSocket Store-and-Forward append timed out waiting for a prepared segment spare [segment_size_bytes={segment_size_bytes}, allocated_segment_bytes={allocated_segment_bytes}, max_total_bytes={max_total_bytes}]"
        ),
        Some(QueueError::StorageSegmentCapFull {
            segment_size_bytes,
            allocated_segment_bytes,
            max_total_bytes,
        }) => error::fmt!(
            SocketError,
            "QWP/WebSocket Store-and-Forward append timed out waiting for ACK-driven segment trim; increase sf_max_total_bytes or drive pending acknowledgements [segment_size_bytes={segment_size_bytes}, allocated_segment_bytes={allocated_segment_bytes}, max_total_bytes={max_total_bytes}]"
        ),
        _ => error::fmt!(
            SocketError,
            "QWP/WebSocket flush timed out waiting for local queue capacity"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::super::qwp_ws_driver::{
        DriverError, DriverEvent, FakeOrderedServer, ReconnectReason, TableSeqTxn,
        TransportFailure, TransportPoll, TransportResponse, TransportSendResult,
    };
    use super::super::qwp_ws_queue::{OutboundFrameView, SentFrame};
    use super::super::qwp_ws_sfa_queue::{
        SfaFrameQueue, SfaMemoryQueueOptions, SfaQueueOptions, SfaStorageStep,
    };
    use super::*;
    use std::sync::{Arc, mpsc};
    use tempfile::TempDir;

    fn memory_queue(max_bytes: usize) -> SfaFrameQueue {
        SfaFrameQueue::open_memory(SfaMemoryQueueOptions {
            segment_size_bytes: 256,
            max_bytes,
        })
        .unwrap()
    }

    #[cfg(any(unix, windows))]
    fn periodic_qwp_ws_config(sf_dir: &std::path::Path, sender_id: &str) -> QwpWsConfig {
        crate::ingress::SenderBuilder::from_conf(format!(
            "ws::addr=127.0.0.1:1;sf_dir={};sender_id={sender_id};\
             sf_max_segment_bytes=256;sf_max_total_bytes=1024;\
             sf_durability=periodic;sf_sync_interval_millis=3600000;",
            sf_dir.display()
        ))
        .unwrap()
        .qwp_ws
        .unwrap()
    }

    #[test]
    fn ws_close_frame_orderly_detection() {
        assert!(
            WsCloseFrame {
                code: Some(1000),
                reason: String::new(),
            }
            .is_orderly()
        );
        assert!(
            WsCloseFrame {
                code: Some(1001),
                reason: String::new(),
            }
            .is_orderly()
        );
        assert!(
            !WsCloseFrame {
                code: Some(1002),
                reason: String::new(),
            }
            .is_orderly()
        );
        assert!(
            !WsCloseFrame {
                code: None,
                reason: String::new(),
            }
            .is_orderly()
        );
    }

    #[test]
    fn host_tracker_picks_by_state_zone_then_configured_order() {
        let mut tracker = QwpWsHostHealthTracker::new(3);
        tracker.zone_tiers[0] = QwpWsZoneTier::Other;
        tracker.zone_tiers[1] = QwpWsZoneTier::Same;
        tracker.zone_tiers[2] = QwpWsZoneTier::Unknown;

        assert_eq!(tracker.pick_next(), Some(1));
        tracker.record_transport_error(1);
        assert_eq!(tracker.pick_next(), Some(2));
        tracker.record_transport_error(2);
        assert_eq!(tracker.pick_next(), Some(0));
    }

    #[test]
    fn host_tracker_demotes_midstream_failure_without_marking_attempted() {
        let mut tracker = QwpWsHostHealthTracker::new(2);
        tracker.record_success(0);
        tracker.begin_round(true);

        tracker.record_mid_stream_failure(0, Some(ReconnectReason::RetryableFailure));

        assert_eq!(tracker.states[0], QwpWsHostState::FailedThisRound);
        assert!(!tracker.attempted_this_round[0]);
        assert_eq!(tracker.pick_next(), Some(1));
    }

    #[test]
    fn host_tracker_marks_midstream_not_writable_as_role_reject_without_marking_attempted() {
        let mut tracker = QwpWsHostHealthTracker::new(2);
        tracker.record_success(0);
        tracker.begin_round(true);

        tracker.record_mid_stream_failure(0, Some(ReconnectReason::NotWritable));

        assert_eq!(tracker.states[0], QwpWsHostState::RoleRejected);
        assert!(!tracker.attempted_this_round[0]);
        assert_eq!(tracker.pick_next(), Some(1));
    }

    #[test]
    fn host_tracker_round_reset_preserves_only_latest_same_zone_healthy_state() {
        let mut tracker = QwpWsHostHealthTracker::new(4);
        tracker.record_success(0);
        tracker.record_success(2);
        tracker.record_success(1);
        tracker.zone_tiers[1] = QwpWsZoneTier::Other;
        tracker.record_role_reject(3, false);

        tracker.begin_round(true);

        assert_eq!(tracker.states[0], QwpWsHostState::HealthUnknown);
        assert_eq!(tracker.states[1], QwpWsHostState::HealthUnknown);
        assert_eq!(tracker.states[2], QwpWsHostState::Healthy);
        assert_eq!(tracker.states[3], QwpWsHostState::HealthUnknown);
        assert_eq!(tracker.pick_next(), Some(2));
    }

    #[test]
    fn locked_health_access_never_holds_lock_between_operations() {
        // The pool's head-of-line fix relies on this: the connect round only
        // touches the shared tracker inside `with_tracker`, and the blocking
        // `establish_connection` runs *between* those calls. So the lock must
        // be fully released the instant each `with_tracker` returns — a
        // returning sender recording a transport failure, or a concurrent
        // cold-start borrow, must never stall behind one slow / black-holed
        // connect.
        let mutex = std::sync::Mutex::new(QwpWsHostHealthTracker::new(2));
        let mut access = LockedQwpWsHealth::new(&mutex);

        let idx = access.with_tracker(|t| t.pick_next_and_claim()).unwrap();
        assert!(
            mutex.try_lock().is_ok(),
            "health lock must be released after pick+claim, not held across the connect"
        );

        access.with_tracker(|t| t.record_success(idx));
        assert!(
            mutex.try_lock().is_ok(),
            "health lock must be released after recording the outcome"
        );
    }

    #[test]
    fn locked_health_access_lets_another_thread_lock_between_operations() {
        // Concrete proof that a second actor (a returning sender / another
        // borrow) can take `inner.health` while a connect round is mid-flight
        // between its pick and its record steps.
        let mutex = Arc::new(std::sync::Mutex::new(QwpWsHostHealthTracker::new(2)));
        let mut access = LockedQwpWsHealth::new(&mutex);

        let idx = access.with_tracker(|t| t.pick_next_and_claim()).unwrap();

        // Simulates the gap during which `establish_connection` blocks: no
        // health lock is held here, so another thread grabs it freely.
        let other = Arc::clone(&mutex);
        std::thread::spawn(move || {
            other
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .record_mid_stream_failure(1, Some(ReconnectReason::RetryableFailure));
        })
        .join()
        .unwrap();

        access.with_tracker(|t| t.record_transport_error(idx));
    }

    #[test]
    fn pick_next_and_claim_rotates_concurrent_picks_off_the_same_endpoint() {
        // Claiming the endpoint *while the lock is still held* means a second
        // borrow that picks before the first has recorded its outcome rotates
        // to a different peer instead of piling onto the same slow endpoint.
        let mut tracker = QwpWsHostHealthTracker::new(2);
        let a = tracker.pick_next_and_claim().unwrap();
        let b = tracker.pick_next_and_claim().unwrap();
        assert_ne!(a, b, "concurrent claims must target distinct endpoints");
        assert!(tracker.is_round_exhausted());
        assert_eq!(tracker.pick_next_and_claim(), None);

        // A fresh round re-probes from scratch.
        tracker.begin_round(true);
        assert!(tracker.pick_next_and_claim().is_some());
    }

    #[test]
    fn connect_round_start_resets_and_claims_single_endpoint_atomically() {
        let mut tracker = QwpWsHostHealthTracker::new(1);
        tracker.record_success(0);
        assert!(tracker.is_round_exhausted());

        assert_eq!(tracker.pick_next_and_claim(), None);
        assert_eq!(tracker.pick_next_and_claim_connect_round(true), Some(0));
        assert!(tracker.is_round_exhausted());

        tracker.record_transport_error(0);
        assert_eq!(tracker.pick_next_and_claim_connect_round(false), None);
        assert_eq!(tracker.pick_next_and_claim_connect_round(true), Some(0));
    }

    #[test]
    fn role_reject_helpers_use_structured_error_not_message_prefix() {
        let string_only = crate::Error::new(
            crate::ErrorCode::SocketError,
            "QWP/WebSocket upgrade rejected by role=PRIMARY_CATCHUP zone=az-a",
        );
        assert!(!is_qwp_ws_role_reject_error(&string_only));
        assert!(!qwp_ws_role_reject_is_transient(&string_only));
        assert_eq!(qwp_ws_role_reject_zone(&string_only), None);

        let structured = crate::Error::new(crate::ErrorCode::SocketError, "unrelated message")
            .with_qwp_ws_role_reject(crate::ingress::QwpWsRoleReject::new(
                "primary_catchup",
                Some("az-a"),
            ));
        assert!(is_qwp_ws_role_reject_error(&structured));
        assert!(qwp_ws_role_reject_is_transient(&structured));
        assert_eq!(qwp_ws_role_reject_zone(&structured), Some("az-a"));
    }

    #[test]
    fn backpressure_notifier_remembers_progress_before_wait() {
        let notifier = BackpressureNotifier::new();
        let generation = notifier.generation();

        notifier.notify_all();

        assert!(notifier.wait_for_change(generation, Some(Instant::now())));
    }

    #[test]
    fn backpressure_notifier_deadline_expires_without_progress() {
        let notifier = BackpressureNotifier::new();
        let generation = notifier.generation();

        assert!(!notifier.wait_for_change(generation, Some(Instant::now())));
    }

    #[test]
    fn effective_connect_timeout_defaults_only_for_bounded_dials() {
        let explicit = Some(Duration::from_millis(250));

        assert_eq!(
            effective_connect_timeout(true, None),
            Some(Duration::from_secs(15))
        );
        assert_eq!(effective_connect_timeout(true, explicit), explicit);
        assert_eq!(effective_connect_timeout(false, None), None);
        assert_eq!(effective_connect_timeout(false, explicit), explicit);
    }

    #[test]
    fn connect_kind_bounds_reconnects_and_background_dials() {
        assert!(!QwpWsConnectKind::Foreground.bounded_dial());
        assert!(QwpWsConnectKind::ForegroundBounded.bounded_dial());
        assert!(QwpWsConnectKind::BackgroundDrainer.bounded_dial());
        assert_eq!(
            QwpWsConnectKind::Foreground.for_reconnect(),
            QwpWsConnectKind::ForegroundBounded
        );
        assert_eq!(
            QwpWsConnectKind::ForegroundBounded.for_reconnect(),
            QwpWsConnectKind::ForegroundBounded
        );
        assert_eq!(
            QwpWsConnectKind::BackgroundDrainer.for_reconnect(),
            QwpWsConnectKind::BackgroundDrainer
        );
    }

    #[test]
    fn traffic_gate_shutdown_is_sticky_across_socket_registration() {
        use std::net::{Ipv4Addr, TcpListener};

        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (mut peer, _) = listener.accept().unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(1))).unwrap();

        let gate = TrafficGate::default();
        gate.register(&client).unwrap().keep();
        gate.shutdown().unwrap();

        let mut byte = [0u8; 1];
        assert_eq!(peer.read(&mut byte).unwrap(), 0);

        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (mut peer, _) = listener.accept().unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(1))).unwrap();

        let err = match gate.register(&client) {
            Ok(_) => panic!("a socket registered after shutdown must be interrupted"),
            Err(err) => err,
        };
        assert_eq!(err.kind(), ErrorKind::Interrupted);
        assert_eq!(peer.read(&mut byte).unwrap(), 0);
    }

    fn reject_websocket_upgrade(stream: &mut (impl Read + Write)) {
        let mut request = Vec::new();
        let mut chunk = [0u8; 256];
        while !request.windows(4).any(|window| window == b"\r\n\r\n") {
            let read = stream.read(&mut chunk).unwrap();
            assert!(read > 0, "client closed before sending the upgrade request");
            request.extend_from_slice(&chunk[..read]);
        }
        stream
            .write_all(
                b"HTTP/1.1 101 Switching Protocols\r\n\
                  Upgrade: websocket\r\n\
                  Connection: Upgrade\r\n\
                  Sec-WebSocket-Accept: invalid\r\n\
                  \r\n",
            )
            .unwrap();
        stream.flush().unwrap();
    }

    fn test_tls_server_config() -> Arc<rustls::ServerConfig> {
        use rustls_pki_types::pem::PemObject;
        use rustls_pki_types::{CertificateDer, PrivateKeyDer};
        use std::fs::File;

        let mut certs_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        certs_dir.pop();
        certs_dir.push("tls_certs");
        let cert_file = File::open(certs_dir.join("server.crt")).unwrap();
        let key_file = File::open(certs_dir.join("server.key")).unwrap();
        let certs = CertificateDer::pem_reader_iter(cert_file)
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let key = PrivateKeyDer::from_pem_reader(key_file).unwrap();
        Arc::new(
            rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(certs, key)
                .unwrap(),
        )
    }

    #[test]
    fn recycle_tls_deadline_bounds_stalled_data_and_pong() {
        use std::net::TcpListener;
        for pong in [false, true] {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            socket2::SockRef::from(&listener)
                .set_recv_buffer_size(1024)
                .unwrap();
            let port = listener.local_addr().unwrap().port();
            let config = test_tls_server_config();
            let (release, released) = mpsc::channel();
            let peer = thread::spawn(move || {
                let (mut tcp, _) = listener.accept().unwrap();
                tcp.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
                let mut conn = rustls::ServerConnection::new(config).unwrap();
                while conn.is_handshaking() {
                    conn.complete_io(&mut tcp).unwrap();
                }
                released.recv_timeout(Duration::from_secs(10)).unwrap();
            });
            let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .parent()
                .unwrap()
                .join("tls_certs/server_rootCA.pem");
            let builder = crate::ingress::SenderBuilder::from_conf(format!(
                "wss::addr=localhost:{port};tls_roots={};",
                root.display()
            ))
            .unwrap();
            let (_, tls, _, _) = builder.resolve_qwp_ws_ingredients().unwrap();
            let cfg = configure_tls(tls.unwrap()).unwrap();
            let mut conn =
                rustls::ClientConnection::new(cfg, "localhost".try_into().unwrap()).unwrap();
            let tcp = TcpStream::connect(("127.0.0.1", port)).unwrap();
            socket2::SockRef::from(&tcp)
                .set_send_buffer_size(4096)
                .unwrap();
            let mut tcp = NoSigpipeTcp::new(tcp).unwrap();
            complete_qwp_ws_tls_handshake(&mut conn, &mut tcp, Duration::from_secs(5)).unwrap();
            let mut stream = WsStream::Tls(Box::new(rustls::StreamOwned::new(conn, tcp)));
            let bytes = vec![0; 16 * 1024 * 1024];
            if pong {
                stream.tcp_stream().set_nonblocking(true).unwrap();
                while stream.write(&bytes).is_ok() {}
                stream.tcp_stream().set_nonblocking(false).unwrap();
            }
            stream
                .set_timeouts(Some(Duration::from_secs(3)), Some(Duration::from_secs(3)))
                .unwrap();
            let started = Instant::now();
            let saved = stream
                .begin_io_deadline(started + Duration::from_millis(20))
                .unwrap();
            let mut scratch = Vec::new();
            if pong {
                let mut reader = WsFrameReader::new();
                loop {
                    reader.append_input_for_test(&[0x89, 0]);
                    if reader.try_read_one(&mut stream, &mut scratch).is_err() {
                        break;
                    }
                }
            } else {
                assert!(write_binary_frame(&mut stream, &mut scratch, &bytes).is_err());
            }
            assert!(
                started.elapsed() < Duration::from_millis(500),
                "TLS internal IO must share the recycle deadline"
            );
            stream.end_io_deadline(saved).unwrap();
            assert_eq!(
                stream.tcp_stream().write_timeout().unwrap(),
                Some(Duration::from_secs(3))
            );
            assert_eq!(
                stream.tcp_stream().read_timeout().unwrap(),
                Some(Duration::from_secs(3))
            );
            release.send(()).unwrap();
            peer.join().unwrap();
        }
    }

    #[test]
    fn failed_upgrade_clears_traffic_gate_before_original_socket_closes() {
        use std::net::{Ipv4Addr, TcpListener};

        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            let (mut peer, _) = listener.accept().unwrap();
            peer.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            reject_websocket_upgrade(&mut peer);
        });

        let qwp_ws =
            crate::ingress::SenderBuilder::from_conf(format!("ws::addr=127.0.0.1:{port};"))
                .unwrap()
                .qwp_ws
                .unwrap();
        let gate = TrafficGate::default();
        let result = establish_connection(
            "127.0.0.1",
            &port.to_string(),
            false,
            None,
            QwpWsConnectKind::Foreground,
            &qwp_ws,
            None,
            Some(&gate),
        );

        assert!(result.is_err());
        server.join().unwrap();
    }

    #[test]
    fn failed_tls_upgrade_clears_traffic_gate_before_original_socket_closes() {
        use std::net::{Ipv4Addr, TcpListener};

        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let server_config = test_tls_server_config();
        let server = std::thread::spawn(move || {
            let (mut peer, _) = listener.accept().unwrap();
            peer.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            let mut conn = rustls::ServerConnection::new(server_config).unwrap();
            let mut tls_stream = rustls::Stream::new(&mut conn, &mut peer);
            reject_websocket_upgrade(&mut tls_stream);
        });

        let mut root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        root.pop();
        root.push("tls_certs/server_rootCA.pem");
        let builder = crate::ingress::SenderBuilder::from_conf(format!(
            "wss::addr=localhost:{port};tls_roots={};",
            root.display()
        ))
        .unwrap();
        let (use_tls, tls_settings, qwp_ws, auth_header) =
            builder.resolve_qwp_ws_ingredients().unwrap();
        let gate = TrafficGate::default();
        let result = establish_connection(
            "localhost",
            &port.to_string(),
            use_tls,
            tls_settings,
            QwpWsConnectKind::Foreground,
            &qwp_ws,
            auth_header.as_deref(),
            Some(&gate),
        );

        assert!(result.is_err());
        server.join().unwrap();
    }

    #[test]
    fn connect_tcp_to_any_addr_falls_back_after_refused_ipv6() {
        use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, TcpListener};

        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let accepted = std::thread::spawn(move || listener.accept().unwrap());
        let bad_v6 = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, port, 0, 0));
        let good_v4 = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port));

        let tcp = connect_tcp_to_any_addr(
            "localhost",
            &port.to_string(),
            &[bad_v6, good_v4],
            Duration::from_secs(1),
            None,
            None,
        )
        .unwrap();

        drop(tcp);
        let _ = accepted.join().unwrap();
    }

    #[test]
    fn connect_tcp_to_any_addr_times_out_against_blackhole() {
        use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
        // 192.0.2.1 is RFC 5737 TEST-NET-1: globally unrouted, so the SYN is
        // dropped and the dial blocks until connect_timeout fires (instead of
        // the OS default, which is tens of seconds).
        let blackhole = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 1), 19009));
        let start = std::time::Instant::now();
        let err = match connect_tcp_to_any_addr(
            "192.0.2.1",
            "19009",
            &[blackhole],
            Duration::from_secs(1),
            Some(Duration::from_millis(300)),
            None,
        ) {
            Err(e) => e,
            Ok(_) => panic!("dialing a blackhole endpoint must not succeed"),
        };
        assert_eq!(
            err.code(),
            crate::ErrorCode::ConnectTimeout,
            "expected ConnectTimeout, got {:?}: {}",
            err.code(),
            err.msg()
        );
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "the dial must be bounded by connect_timeout (~300ms)"
        );
    }

    #[test]
    fn connect_tcp_to_any_addr_stops_between_addresses_after_gate_shutdown() {
        use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

        let gate = TrafficGate::default();
        gate.shutdown().unwrap();
        let blackhole = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 1), 19009));

        let start = std::time::Instant::now();
        let err = match connect_tcp_to_any_addr(
            "192.0.2.1",
            "19009",
            &[blackhole],
            Duration::from_secs(1),
            Some(Duration::from_millis(300)),
            Some(&gate),
        ) {
            Err(e) => e,
            Ok(_) => panic!("a shut gate must stop the dial walk"),
        };
        assert!(
            err.msg().contains("shutting down during connect"),
            "unexpected error: {}",
            err.msg()
        );
        assert!(
            start.elapsed() < Duration::from_millis(100),
            "a shut gate must skip the dial entirely"
        );
    }

    #[test]
    fn connect_tcp_sets_post_connect_io_timeout() {
        use std::net::{Ipv4Addr, TcpListener};

        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let accepted = std::thread::spawn(move || listener.accept().unwrap());
        let io_timeout = Duration::from_millis(250);

        let tcp =
            connect_qwp_ws_tcp("127.0.0.1", &port.to_string(), io_timeout, None, None).unwrap();

        assert_eq!(tcp.tcp().read_timeout().unwrap(), Some(io_timeout));
        assert_eq!(tcp.tcp().write_timeout().unwrap(), Some(io_timeout));
        drop(tcp);
        let _ = accepted.join().unwrap();
    }

    #[test]
    fn frame_short_payload_is_masked() {
        let mut out = Vec::new();
        let payload = b"hello";
        codec::write_frame_to_buf(&mut out, Opcode::Binary, payload, [0; 4]);
        assert_eq!(out[0], 0x82); // FIN | binary
        assert_eq!(out[1] & 0x80, 0x80); // masked
        assert_eq!(out[1] & 0x7F, 5); // length
    }

    #[test]
    fn write_ping_frame_masks_client_ping() {
        let mut stream = InMemoryWs::new(Vec::new());
        let mut scratch = Vec::new();

        write_ping_frame(&mut stream, &mut scratch, b"da").unwrap();

        assert_eq!(stream.written[0], 0x80 | OPCODE_PING);
        assert_eq!(stream.written[1] & 0x80, 0x80);
        assert_eq!(stream.written[1] & 0x7f, 2);
    }

    #[test]
    fn masked_server_frame_is_protocol_error() {
        let mut masked_frame = Vec::new();
        codec::write_frame_to_buf(&mut masked_frame, Opcode::Binary, b"hello", [0; 4]);
        let err = read_message(
            &mut std::io::Cursor::new(masked_frame),
            &mut Vec::new(),
            &mut Vec::new(),
        )
        .unwrap_err();

        assert_eq!(err.code(), crate::ErrorCode::SocketError);
        assert!(
            err.msg().contains("must not be masked"),
            "got: {}",
            err.msg()
        );
    }

    #[test]
    fn frame_reader_rejects_rsv_bits_without_extension() {
        let mut frame = Vec::new();
        append_server_frame(&mut frame, true, OPCODE_BINARY, b"hello");
        frame[0] |= 0x40;
        let mut reader = WsFrameReader::new();
        reader.append_input_for_test(&frame);
        let mut written = Vec::new();
        let mut scratch = Vec::new();

        let err = reader
            .try_read_buffered_for_test(&mut written, &mut scratch)
            .unwrap_err();

        assert_protocol_violation_contains(err, "RSV bits");
    }

    #[test]
    fn frame_reader_rejects_one_byte_close_payload() {
        let mut frame = Vec::new();
        append_server_frame(&mut frame, true, OPCODE_CLOSE, &[0x03]);
        let mut reader = WsFrameReader::new();
        reader.append_input_for_test(&frame);
        let mut written = Vec::new();
        let mut scratch = Vec::new();

        let err = reader
            .try_read_buffered_for_test(&mut written, &mut scratch)
            .unwrap_err();

        assert_protocol_violation_contains(err, "payload length must be 0 or at least 2 bytes");
    }

    #[test]
    fn frame_reader_rejects_non_minimal_16_bit_payload_length() {
        let frame = [0x80 | OPCODE_BINARY, 126, 0, 125];
        let mut reader = WsFrameReader::new();
        reader.append_input_for_test(&frame);
        let mut written = Vec::new();
        let mut scratch = Vec::new();

        let err = reader
            .try_read_buffered_for_test(&mut written, &mut scratch)
            .unwrap_err();

        assert_protocol_violation_contains(err, "non-minimal 16-bit encoding");
    }

    #[test]
    fn frame_reader_rejects_non_minimal_64_bit_payload_length() {
        let mut frame = vec![0x80 | OPCODE_BINARY, 127];
        frame.extend_from_slice(&0xffffu64.to_be_bytes());
        let mut reader = WsFrameReader::new();
        reader.append_input_for_test(&frame);
        let mut written = Vec::new();
        let mut scratch = Vec::new();

        let err = reader
            .try_read_buffered_for_test(&mut written, &mut scratch)
            .unwrap_err();

        assert_protocol_violation_contains(err, "non-minimal 64-bit encoding");
    }

    struct InMemoryWs {
        read: std::io::Cursor<Vec<u8>>,
        written: Vec<u8>,
    }

    impl InMemoryWs {
        fn new(read: Vec<u8>) -> Self {
            Self {
                read: std::io::Cursor::new(read),
                written: Vec::new(),
            }
        }
    }

    impl std::io::Read for InMemoryWs {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            std::io::Read::read(&mut self.read, buf)
        }
    }

    impl std::io::Write for InMemoryWs {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.written.extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    struct UpgradeResponseWithFrame {
        written: Vec<u8>,
        read: std::io::Cursor<Vec<u8>>,
        payload: Vec<u8>,
        response_built: bool,
    }

    impl UpgradeResponseWithFrame {
        fn new(payload: &[u8]) -> Self {
            Self {
                written: Vec::new(),
                read: std::io::Cursor::new(Vec::new()),
                payload: payload.to_vec(),
                response_built: false,
            }
        }

        fn build_response(&mut self) {
            let request = std::str::from_utf8(&self.written).unwrap();
            let key = request
                .split("\r\n")
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("sec-websocket-key")
                        .then(|| value.trim())
                })
                .unwrap();
            let accept = crate::ws::crypto::compute_accept(key);
            let mut response = format!(
                "HTTP/1.1 101 Switching Protocols\r\n\
                 Upgrade: websocket\r\n\
                 Connection: Upgrade\r\n\
                 Sec-WebSocket-Accept: {accept}\r\n\
                 X-QWP-Version: 1\r\n\
                 \r\n"
            )
            .into_bytes();
            append_server_frame(&mut response, true, OPCODE_BINARY, &self.payload);
            self.read = std::io::Cursor::new(response);
            self.response_built = true;
        }
    }

    impl std::io::Read for UpgradeResponseWithFrame {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            if !self.response_built {
                self.build_response();
            }
            std::io::Read::read(&mut self.read, buf)
        }
    }

    impl std::io::Write for UpgradeResponseWithFrame {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.written.extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn append_server_frame(out: &mut Vec<u8>, fin: bool, opcode: u8, payload: &[u8]) {
        let fin_bit = if fin { 0x80 } else { 0x00 };
        out.push(fin_bit | (opcode & 0x0F));
        let plen = payload.len();
        if plen <= 125 {
            out.push(plen as u8);
        } else if plen <= 0xFFFF {
            out.push(126);
            out.extend_from_slice(&(plen as u16).to_be_bytes());
        } else {
            out.push(127);
            out.extend_from_slice(&(plen as u64).to_be_bytes());
        }
        out.extend_from_slice(payload);
    }

    #[test]
    fn perform_upgrade_preserves_coalesced_websocket_frame() {
        // Server coalesces a WS data frame onto the tail of the upgrade
        // response. The shared `handshake::upgrade` MUST surface those
        // bytes via `Handshake.leftover` so the ingress frame reader can
        // consume them without losing the leading frame.
        let mut stream = UpgradeResponseWithFrame::new(b"\x02\x00");

        let extras = codec::qwp_extra_headers(None, 1, None, false);
        let handshake =
            crate::ws::handshake::upgrade(&mut stream, "localhost:9000", codec::WS_PATH, &extras)
                .unwrap();
        let result = codec::validate_qwp_handshake_headers(&handshake.headers, 1, false).unwrap();
        let leftover = handshake.leftover;

        assert_eq!(result.version, 1);
        let mut reader = WsFrameReader::with_initial_input(leftover);
        let mut written = Vec::new();
        let mut scratch = Vec::new();
        assert_eq!(
            reader
                .try_read_buffered_for_test(&mut written, &mut scratch)
                .unwrap(),
            WsFrameRead::Message {
                opcode: OPCODE_BINARY
            }
        );
        assert_eq!(reader.message(), b"\x02\x00");
    }

    fn assert_protocol_violation_contains(err: WsMessageError, needle: &str) {
        match err {
            WsMessageError::ProtocolViolation(reason) => {
                assert!(reason.contains(needle), "got: {reason}");
            }
            other => panic!("expected protocol violation, got {other:?}"),
        }
    }

    #[test]
    fn normal_close_is_reconnectable_role_movement_shape() {
        let mut frames = Vec::new();
        append_server_frame(&mut frames, true, OPCODE_CLOSE, &1000u16.to_be_bytes());
        let mut stream = InMemoryWs::new(frames);
        let mut scratch = Vec::new();
        let mut out = Vec::new();

        let err = read_message_with_close(&mut stream, &mut scratch, &mut out).unwrap_err();

        match err {
            WsMessageError::Close(close) => {
                assert_eq!(close.code, Some(1000));
                assert!(close.reason.is_empty());
            }
            other => panic!("expected normal close, got {other:?}"),
        }
    }

    #[test]
    fn read_message_preserves_fragment_across_ping() {
        let mut frames = Vec::new();
        append_server_frame(&mut frames, false, OPCODE_BINARY, b"hello ");
        append_server_frame(&mut frames, true, OPCODE_PING, b"p");
        append_server_frame(&mut frames, true, OPCODE_CONTINUATION, b"world");
        let mut stream = InMemoryWs::new(frames);
        let mut scratch = Vec::new();
        let mut out = Vec::new();

        let opcode = read_message_with_close(&mut stream, &mut scratch, &mut out).unwrap();

        assert_eq!(opcode, OPCODE_BINARY);
        assert_eq!(out, b"hello world");
        assert!(!stream.written.is_empty());
    }

    #[test]
    fn frame_reader_rejects_fragmented_message_over_aggregate_limit() {
        let mut frames = Vec::new();
        append_server_frame(&mut frames, false, OPCODE_BINARY, b"abc");
        append_server_frame(&mut frames, true, OPCODE_CONTINUATION, b"def");
        let mut reader = WsFrameReader::with_max_message_bytes_for_test(5);
        reader.append_input_for_test(&frames);
        let mut written = Vec::new();
        let mut scratch = Vec::new();

        assert_eq!(
            reader
                .try_read_buffered_for_test(&mut written, &mut scratch)
                .unwrap(),
            WsFrameRead::Progress
        );
        let err = reader
            .try_read_buffered_for_test(&mut written, &mut scratch)
            .unwrap_err();

        assert_protocol_violation_contains(err, "WebSocket message too large: 6 bytes");
        assert_eq!(reader.message(), b"abc");
    }

    #[test]
    fn frame_reader_consumes_pong_then_buffered_binary_message() {
        let mut frames = Vec::new();
        append_server_frame(&mut frames, true, OPCODE_PONG, b"");
        append_server_frame(&mut frames, true, OPCODE_BINARY, b"\x02\x00");
        let mut reader = WsFrameReader::new();
        reader.append_input_for_test(&frames);
        let mut written = Vec::new();
        let mut scratch = Vec::new();

        assert_eq!(
            reader
                .try_read_buffered_for_test(&mut written, &mut scratch)
                .unwrap(),
            WsFrameRead::Progress
        );
        assert!(written.is_empty());
        assert_eq!(
            reader
                .try_read_buffered_for_test(&mut written, &mut scratch)
                .unwrap(),
            WsFrameRead::Message {
                opcode: OPCODE_BINARY
            }
        );
        assert_eq!(reader.message(), b"\x02\x00");
    }

    #[test]
    fn frame_reader_answers_ping_and_returns_progress() {
        let mut frame = Vec::new();
        append_server_frame(&mut frame, true, OPCODE_PING, b"p");
        let mut reader = WsFrameReader::new();
        reader.append_input_for_test(&frame);
        let mut written = Vec::new();
        let mut scratch = Vec::new();

        assert_eq!(
            reader
                .try_read_buffered_for_test(&mut written, &mut scratch)
                .unwrap(),
            WsFrameRead::Progress
        );
        assert_eq!(written[0], 0x80 | OPCODE_PONG);
        assert_eq!(written[1] & 0x80, 0x80);
        assert_eq!(written[1] & 0x7f, 1);
    }

    #[test]
    fn frame_reader_preserves_incomplete_buffered_payload_until_complete() {
        let mut frame = Vec::new();
        append_server_frame(&mut frame, true, OPCODE_BINARY, b"ok");
        let mut reader = WsFrameReader::new();
        reader.append_input_for_test(&frame[..3]);
        let mut written = Vec::new();
        let mut scratch = Vec::new();

        assert_eq!(
            reader
                .try_read_buffered_for_test(&mut written, &mut scratch)
                .unwrap(),
            WsFrameRead::Idle
        );
        reader.append_input_for_test(&frame[3..]);
        assert_eq!(
            reader
                .try_read_buffered_for_test(&mut written, &mut scratch)
                .unwrap(),
            WsFrameRead::Message {
                opcode: OPCODE_BINARY
            }
        );
        assert_eq!(reader.message(), b"ok");
    }

    #[test]
    fn frame_reader_compacts_consumed_small_frames() {
        let mut frames = Vec::new();
        for _ in 0..2500 {
            append_server_frame(&mut frames, true, OPCODE_PONG, b"");
        }
        append_server_frame(&mut frames, true, OPCODE_BINARY, b"done");
        let original_len = frames.len();
        let mut reader = WsFrameReader::new();
        reader.append_input_for_test(&frames);
        let mut written = Vec::new();
        let mut scratch = Vec::new();

        for _ in 0..2500 {
            assert_eq!(
                reader
                    .try_read_buffered_for_test(&mut written, &mut scratch)
                    .unwrap(),
                WsFrameRead::Progress
            );
        }
        assert!(
            reader.input.len() < original_len,
            "reader did not compact consumed frames"
        );
        assert_eq!(
            reader
                .try_read_buffered_for_test(&mut written, &mut scratch)
                .unwrap(),
            WsFrameRead::Message {
                opcode: OPCODE_BINARY
            }
        );
        assert_eq!(reader.message(), b"done");
    }

    /// Run with:
    /// `cargo test --features sync-sender-qwp-ws --lib read_message_zero_alloc_after_warmup -- --ignored --test-threads=1`
    #[test]
    #[ignore]
    fn read_message_zero_alloc_after_warmup() {
        use crate::alloc_counter;

        let mut frame = Vec::new();
        append_server_frame(&mut frame, true, OPCODE_BINARY, b"\x00\x00");
        let mut scratch = Vec::with_capacity(64);
        let mut out = Vec::with_capacity(64);

        let mut warmup = InMemoryWs::new(frame.clone());
        assert_eq!(
            read_message_with_close(&mut warmup, &mut scratch, &mut out).unwrap(),
            OPCODE_BINARY
        );
        assert_eq!(out, b"\x00\x00");

        let mut counted = InMemoryWs::new(frame);
        alloc_counter::start_counting();
        assert_eq!(
            read_message_with_close(&mut counted, &mut scratch, &mut out).unwrap(),
            OPCODE_BINARY
        );
        let alloc_count = alloc_counter::stop_counting();

        assert_eq!(out, b"\x00\x00");
        assert_eq!(
            alloc_count, 0,
            "Expected zero allocations for warmed QWP/WebSocket inbound message read, got {alloc_count}"
        );
    }

    #[derive(Debug)]
    struct BlockingFirstSendTransport {
        send_started: mpsc::Sender<()>,
        release_send: mpsc::Receiver<()>,
        should_block_send: bool,
        sent_frames: Vec<SentFrame>,
    }

    impl QwpWsCoreTransport for BlockingFirstSendTransport {
        fn try_poll_response(&mut self) -> Result<TransportPoll, TransportFailure> {
            Ok(TransportPoll::Idle)
        }

        fn send_frame(
            &mut self,
            frame: OutboundFrameView<'_>,
        ) -> Result<TransportSendResult, TransportFailure> {
            let sent_frame = frame.sent_frame();
            if self.should_block_send {
                self.should_block_send = false;
                self.send_started.send(()).unwrap();
                self.release_send
                    .recv_timeout(Duration::from_secs(5))
                    .unwrap();
            }
            self.sent_frames.push(sent_frame);
            Ok(TransportSendResult::NoResponse)
        }
    }

    #[derive(Debug)]
    struct AckWhenReadyTransport {
        ack_ready: Arc<AtomicBool>,
        sent_frames: Vec<SentFrame>,
    }

    impl QwpWsCoreTransport for AckWhenReadyTransport {
        fn try_poll_response(&mut self) -> Result<TransportPoll, TransportFailure> {
            if self.ack_ready.swap(false, Ordering::AcqRel) {
                Ok(TransportPoll::Response(TransportResponse::Ack {
                    wire_seq: 0,
                }))
            } else {
                Ok(TransportPoll::Idle)
            }
        }

        fn send_frame(
            &mut self,
            frame: OutboundFrameView<'_>,
        ) -> Result<TransportSendResult, TransportFailure> {
            self.sent_frames.push(frame.sent_frame());
            Ok(TransportSendResult::NoResponse)
        }
    }

    #[derive(Debug)]
    struct DurableAckWhenReadyTransport {
        ack_ready: Arc<AtomicBool>,
        sent_frames: Vec<SentFrame>,
    }

    impl DurableAckWhenReadyTransport {
        fn table_seq_txns() -> Vec<TableSeqTxn> {
            vec![TableSeqTxn {
                table: "trades".to_string(),
                seq_txn: 10,
            }]
        }
    }

    impl QwpWsCoreTransport for DurableAckWhenReadyTransport {
        fn try_poll_response(&mut self) -> Result<TransportPoll, TransportFailure> {
            if self.ack_ready.swap(false, Ordering::AcqRel) {
                Ok(TransportPoll::Response(TransportResponse::DurableAck {
                    table_seq_txns: Self::table_seq_txns(),
                }))
            } else {
                Ok(TransportPoll::Idle)
            }
        }

        fn send_frame(
            &mut self,
            frame: OutboundFrameView<'_>,
        ) -> Result<TransportSendResult, TransportFailure> {
            self.sent_frames.push(frame.sent_frame());
            Ok(TransportSendResult::Response(
                TransportResponse::DurableOk {
                    wire_seq: 0,
                    table_seq_txns: Self::table_seq_txns(),
                },
            ))
        }
    }

    #[test]
    fn threaded_runner_accepts_publication_while_transport_send_is_blocked() {
        let (send_started_tx, send_started_rx) = mpsc::channel();
        let (release_send_tx, release_send_rx) = mpsc::channel();
        let queue = memory_queue(1024);
        let transport = BlockingFirstSendTransport {
            send_started: send_started_tx,
            release_send: release_send_rx,
            should_block_send: true,
            sent_frames: Vec::new(),
        };
        let driver = QwpWsCoreTestHarness::from_queue(queue, transport);
        let mut runner = SyncQwpWsRunner::start(driver);

        runner.publish_replay_payload(b"first").unwrap();
        send_started_rx
            .recv_timeout(Duration::from_secs(5))
            .unwrap();

        std::thread::scope(|scope| {
            let (published_tx, published_rx) = mpsc::channel();
            let runner = &mut runner;
            let publish_thread = scope.spawn(move || {
                let result = runner.publish_replay_payload(b"second");
                let _ = published_tx.send(result.map(|_| ()));
            });

            let publish_result = match published_rx.recv_timeout(Duration::from_secs(2)) {
                Ok(result) => result,
                Err(err) => {
                    let _ = release_send_tx.send(());
                    publish_thread.join().unwrap();
                    panic!("publication waited for blocked transport send: {err:?}");
                }
            };
            publish_result.unwrap();
            publish_thread.join().unwrap();
        });

        release_send_tx.send(()).unwrap();
        drop(runner);
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn runner_shutdown_timeout_keeps_slot_locked_until_worker_exit() {
        let dir = TempDir::new().unwrap();
        let slot_options = SfaSlotOptions {
            sf_dir: dir.path().to_path_buf(),
            sender_id: "blocked-runner".to_string(),
            segment_size_bytes: 4096,
            max_bytes: 8192,
            periodic_sync_interval: None,
        };
        let queue = SfaSlotQueue::open(slot_options.clone()).unwrap();
        let (send_started_tx, send_started_rx) = mpsc::channel();
        let (release_send_tx, release_send_rx) = mpsc::channel();
        let transport = BlockingFirstSendTransport {
            send_started: send_started_tx,
            release_send: release_send_rx,
            should_block_send: true,
            sent_frames: Vec::new(),
        };
        let driver = QwpWsCoreTestHarness::from_queue(queue, transport);
        let mut runner = SyncQwpWsRunner::start(driver);
        runner.shutdown_timeout = Duration::from_millis(50);

        runner.publish_replay_payload(b"blocked").unwrap();
        send_started_rx
            .recv_timeout(Duration::from_secs(5))
            .unwrap();

        let started = Instant::now();
        drop(runner);
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "runner drop exceeded its shutdown backstop"
        );

        match SfaSlotQueue::open(slot_options.clone()) {
            Err(SfaQueueError::SlotInUse { .. }) => {}
            Err(err) => panic!("expected the detached worker to retain the slot lock: {err:?}"),
            Ok(_) => panic!("detached worker released its slot before exiting"),
        }

        release_send_tx.send(()).unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            match SfaSlotQueue::open(slot_options.clone()) {
                Ok(queue) => {
                    // The unacked frame must survive the detached worker's
                    // exit and replay to the next adopter of the slot.
                    let mut driver =
                        QwpWsCoreTestHarness::from_queue(queue, FakeOrderedServer::ack_each_send());
                    assert_eq!(
                        driver.drive_once().unwrap(),
                        DriveOutcome::Acked { wire_seq: 0 }
                    );
                    assert_eq!(
                        driver.poll_event(),
                        Some(DriverEvent::Sent {
                            fsn: 0,
                            wire_seq: 0
                        })
                    );
                    break;
                }
                Err(SfaQueueError::SlotInUse { .. }) if Instant::now() < deadline => {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(err) => panic!("slot did not become reusable after worker exit: {err:?}"),
            }
        }
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn runner_drives_periodic_sync_from_config() {
        let dir = TempDir::new().unwrap();
        let qwp_ws = periodic_qwp_ws_config(dir.path(), "periodic-driver");
        let queue = open_configured_qwp_ws_queue(&qwp_ws).unwrap();
        let driver = QwpWsCoreTestHarness::from_queue(queue, FakeOrderedServer::no_response());
        let (mut store, send_core) = driver.into_parts();
        store.try_submit(b"periodic").unwrap();
        let progress = store.progress_view();
        let lifecycle = store.lifecycle();
        let shared = Arc::new(Mutex::new(store));
        let mut core = SyncQwpWsRunnerCore {
            send_core,
            progress,
            cold_effects: VecDeque::new(),
            backpressure: Arc::new(BackpressureNotifier::new()),
            ok_completed_upper: Arc::new(AtomicU64::new(0)),
            lifecycle,
            recycle: Arc::new(RecycleLink::new(true)),
        };

        assert_eq!(
            core.drive_step(&shared, &AtomicBool::new(false)),
            RunnerStep::Continue
        );

        let mut store = shared.lock().unwrap();
        assert!(!store.storage_maintenance_in_flight().unwrap());
        assert!(
            store.take_storage_maintenance_step().unwrap().is_none(),
            "the runner must finish the initial periodic sync and arm its configured cadence"
        );
        store.close_queue().unwrap();
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn threaded_runner_waits_for_in_flight_periodic_sync_before_close() {
        let dir = TempDir::new().unwrap();
        let sender_id = "periodic-runner";
        let qwp_ws = periodic_qwp_ws_config(dir.path(), sender_id);
        let slot_options = SfaSlotOptions {
            sf_dir: dir.path().to_path_buf(),
            sender_id: sender_id.to_owned(),
            segment_size_bytes: 256,
            max_bytes: 1024,
            periodic_sync_interval: Some(Duration::from_secs(3600)),
        };
        let mut queue = open_configured_qwp_ws_queue(&qwp_ws).unwrap();
        let receipt = PublicationLog::try_publish(&mut queue, b"periodic").unwrap();
        PublicationLog::progress_view(&queue)
            .complete_through_fsn(receipt.fsn)
            .unwrap();
        PublicationLog::persist_completed_fsn(&mut queue, receipt.fsn);

        // Hold the real sync step instead of racing a filesystem call: taking
        // it sets the production in-flight flag until finish is reported.
        let sync_step = PublicationLog::take_storage_maintenance_step(&mut queue, false)
            .unwrap()
            .expect("periodic queue must offer its initial sync step");
        assert!(matches!(sync_step, SfaStorageStep::SyncPublished(_)));
        assert!(PublicationLog::storage_maintenance_in_flight(&queue).unwrap());

        let driver = QwpWsCoreTestHarness::from_queue(queue, FakeOrderedServer::no_response());
        let mut runner = SyncQwpWsRunner::start(driver);
        runner.begin_close();

        // An already-expired deadline probes the gate without sleeping.
        let err = runner
            .drain_to_deadline(Some(Instant::now()))
            .expect_err("close must wait for the held periodic sync step");
        assert!(err.msg().contains("close drain timed out"));
        assert!(matches!(
            SfaSlotQueue::open(slot_options.clone()),
            Err(SfaQueueError::SlotInUse { .. })
        ));

        let sync_result = sync_step.perform().unwrap();
        runner
            .shared
            .lock()
            .unwrap()
            .finish_storage_maintenance(sync_result)
            .unwrap();
        runner
            .shared
            .lock()
            .unwrap()
            .complete_storage_maintenance()
            .unwrap();
        runner.drain_to_deadline(None).unwrap();

        SfaSlotQueue::open(slot_options).unwrap();
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn threaded_runner_waits_for_in_flight_hot_spare_creation_before_close() {
        let dir = TempDir::new().unwrap();
        let slot_options = SfaSlotOptions {
            sf_dir: dir.path().to_path_buf(),
            sender_id: "hot-spare-runner".to_string(),
            segment_size_bytes: 38,
            max_bytes: 114,
            periodic_sync_interval: None,
        };
        let mut queue = SfaSlotQueue::open(slot_options.clone()).unwrap();
        PublicationLog::try_publish(&mut queue, b"first").unwrap();
        let last = PublicationLog::try_publish(&mut queue, b"second").unwrap();
        PublicationLog::progress_view(&queue)
            .complete_through_fsn(last.fsn)
            .unwrap();
        PublicationLog::persist_completed_fsn(&mut queue, last.fsn);

        // Retire the sealed segment first so the next maintenance task is the
        // hot-spare creation involved in the close race.
        let trim_step = PublicationLog::take_storage_maintenance_step(&mut queue, false)
            .unwrap()
            .expect("completed sealed segment must schedule trim");
        assert!(matches!(trim_step, SfaStorageStep::Trim(_)));
        let trim_result = trim_step.perform().unwrap();
        PublicationLog::finish_storage_maintenance(&mut queue, trim_result, false).unwrap();
        PublicationLog::complete_storage_maintenance(&mut queue).unwrap();

        // Hold the real task after taking it. This is the precise window where
        // its off-lock file creation used to race a fully drained close.
        let create_step = PublicationLog::take_storage_maintenance_step(&mut queue, true)
            .unwrap()
            .expect("queue without a spare must schedule creation");
        assert!(matches!(create_step, SfaStorageStep::CreateHotSpare { .. }));
        assert!(PublicationLog::storage_maintenance_in_flight(&queue).unwrap());

        let driver = QwpWsCoreTestHarness::from_queue(queue, FakeOrderedServer::no_response());
        let mut runner = SyncQwpWsRunner::start(driver);
        runner.begin_close();

        let err = runner
            .drain_to_deadline(Some(Instant::now()))
            .expect_err("close must wait for the held hot-spare creation");
        assert!(err.msg().contains("close drain timed out"));
        assert!(matches!(
            SfaSlotQueue::open(slot_options.clone()),
            Err(SfaQueueError::SlotInUse { .. })
        ));

        let create_result = create_step.perform().unwrap();
        let cleanup = runner
            .shared
            .lock()
            .unwrap()
            .finish_storage_maintenance(create_result)
            .unwrap()
            .into_cleanup()
            .expect("closing queue must abandon the created spare");
        assert!(cleanup.perform().is_none());
        runner
            .shared
            .lock()
            .unwrap()
            .complete_storage_maintenance()
            .unwrap();
        runner.drain_to_deadline(None).unwrap();

        SfaSlotQueue::open(slot_options).unwrap();
    }

    #[test]
    fn threaded_sfa_publication_does_not_take_shared_store_mutex() {
        let dir = TempDir::new().unwrap();
        let queue = SfaFrameQueue::open(SfaQueueOptions {
            slot_dir: dir.path().to_path_buf(),
            segment_size_bytes: 4096,
            max_bytes: 8192,
            periodic_sync_interval: None,
        })
        .unwrap();
        let driver = QwpWsCoreTestHarness::from_queue(queue, FakeOrderedServer::no_response());
        let mut runner =
            SyncQwpWsRunner::start_driver_with_append_deadline(driver, Duration::from_secs(5));
        let shared = Arc::clone(&runner.shared);
        let guard = shared.lock().unwrap();

        std::thread::scope(|scope| {
            let (published_tx, published_rx) = mpsc::channel();
            let runner = &mut runner;
            let publish_thread = scope.spawn(move || {
                let result = runner.publish_replay_payload(b"sfa-first");
                let _ = published_tx.send(result);
            });

            assert_eq!(
                published_rx
                    .recv_timeout(Duration::from_secs(2))
                    .unwrap()
                    .unwrap(),
                0
            );
            publish_thread.join().unwrap();
        });

        drop(guard);
        drop(runner);
    }

    #[test]
    fn threaded_sfa_send_progress_does_not_take_shared_store_mutex() {
        let dir = TempDir::new().unwrap();
        let queue = SfaFrameQueue::open(SfaQueueOptions {
            slot_dir: dir.path().to_path_buf(),
            segment_size_bytes: 4096,
            max_bytes: 8192,
            periodic_sync_interval: None,
        })
        .unwrap();
        let (send_started_tx, send_started_rx) = mpsc::channel();
        let (release_send_tx, release_send_rx) = mpsc::channel();
        let transport = BlockingFirstSendTransport {
            send_started: send_started_tx,
            release_send: release_send_rx,
            should_block_send: true,
            sent_frames: Vec::new(),
        };
        let mut driver = QwpWsCoreTestHarness::from_queue(queue, transport);
        let receipt = driver.try_submit(b"sfa-first").unwrap();
        assert_eq!(receipt.fsn, 0);
        let (store, send_core) = driver.into_parts();
        let progress = store.progress_view();
        let lifecycle = store.lifecycle();
        let shared = Arc::new(Mutex::new(store));
        let mut guard = Some(shared.lock().unwrap());
        let backpressure = Arc::new(BackpressureNotifier::new());
        let mut core = SyncQwpWsRunnerCore {
            send_core,
            progress,
            cold_effects: VecDeque::new(),
            backpressure,
            ok_completed_upper: Arc::new(AtomicU64::new(0)),
            lifecycle,
            recycle: Arc::new(RecycleLink::new(true)),
        };
        let stop = AtomicBool::new(false);
        let shared_for_step = Arc::clone(&shared);

        std::thread::scope(|scope| {
            let step_thread = scope.spawn(|| core.drive_step(&shared_for_step, &stop));
            match send_started_rx.recv_timeout(Duration::from_secs(2)) {
                Ok(()) => {}
                Err(err) => {
                    drop(guard.take());
                    let _ = send_started_rx.recv_timeout(Duration::from_secs(2));
                    let _ = release_send_tx.send(());
                    step_thread.join().unwrap();
                    panic!("send progress waited for shared-store mutex: {err:?}");
                }
            }
            release_send_tx.send(()).unwrap();
            drop(guard.take());
            assert_eq!(step_thread.join().unwrap(), RunnerStep::Continue);
        });
    }

    #[test]
    fn threaded_sfa_ack_progress_does_not_take_shared_store_mutex() {
        let dir = TempDir::new().unwrap();
        let queue = SfaFrameQueue::open(SfaQueueOptions {
            slot_dir: dir.path().to_path_buf(),
            segment_size_bytes: 4096,
            max_bytes: 8192,
            periodic_sync_interval: None,
        })
        .unwrap();
        let ack_ready = Arc::new(AtomicBool::new(false));
        let transport = AckWhenReadyTransport {
            ack_ready: Arc::clone(&ack_ready),
            sent_frames: Vec::new(),
        };
        let mut driver = QwpWsCoreTestHarness::from_queue(queue, transport);
        let receipt = driver.try_submit(b"sfa-first").unwrap();
        assert_eq!(receipt.fsn, 0);
        let (store, send_core) = driver.into_parts();
        let progress = store.progress_view();
        let lifecycle = store.lifecycle();
        let shared = Arc::new(Mutex::new(store));
        let backpressure = Arc::new(BackpressureNotifier::new());
        let mut core = SyncQwpWsRunnerCore {
            send_core,
            progress: progress.clone(),
            cold_effects: VecDeque::new(),
            backpressure,
            ok_completed_upper: Arc::new(AtomicU64::new(0)),
            lifecycle,
            recycle: Arc::new(RecycleLink::new(true)),
        };
        let stop = AtomicBool::new(false);

        assert_eq!(core.drive_step(&shared, &stop), RunnerStep::Continue);
        assert_eq!(progress.completed_fsn(), None);

        let mut guard = Some(shared.lock().unwrap());
        ack_ready.store(true, Ordering::Release);
        let shared_for_step = Arc::clone(&shared);
        std::thread::scope(|scope| {
            let step_thread = scope.spawn(|| core.drive_step(&shared_for_step, &stop));
            let deadline = Instant::now() + Duration::from_secs(2);
            while Instant::now() < deadline {
                if progress.completed_fsn() == Some(0) {
                    drop(guard.take());
                    assert_eq!(step_thread.join().unwrap(), RunnerStep::Continue);
                    return;
                }
                thread::sleep(Duration::from_millis(10));
            }
            drop(guard.take());
            let _ = step_thread.join();
            panic!("ACK progress waited for shared-store mutex");
        });
    }

    #[test]
    fn threaded_sfa_durable_ack_progress_does_not_take_shared_store_mutex() {
        let dir = TempDir::new().unwrap();
        let queue = SfaFrameQueue::open(SfaQueueOptions {
            slot_dir: dir.path().to_path_buf(),
            segment_size_bytes: 4096,
            max_bytes: 8192,
            periodic_sync_interval: None,
        })
        .unwrap();
        let ack_ready = Arc::new(AtomicBool::new(false));
        let transport = DurableAckWhenReadyTransport {
            ack_ready: Arc::clone(&ack_ready),
            sent_frames: Vec::new(),
        };
        let mut driver = QwpWsCoreTestHarness::from_queue_with_reconnect_policy(
            queue,
            transport,
            ReconnectPolicy::bounded(Duration::MAX, Duration::ZERO, Duration::ZERO),
            true,
        );
        let receipt = driver.try_submit(b"sfa-first").unwrap();
        assert_eq!(receipt.fsn, 0);
        let (store, send_core) = driver.into_parts();
        let progress = store.progress_view();
        let lifecycle = store.lifecycle();
        let shared = Arc::new(Mutex::new(store));
        let backpressure = Arc::new(BackpressureNotifier::new());
        let ok_completed_upper = Arc::new(AtomicU64::new(0));
        let mut core = SyncQwpWsRunnerCore {
            send_core,
            progress: progress.clone(),
            cold_effects: VecDeque::new(),
            backpressure,
            ok_completed_upper: Arc::clone(&ok_completed_upper),
            lifecycle,
            recycle: Arc::new(RecycleLink::new(true)),
        };
        let stop = AtomicBool::new(false);

        assert_eq!(core.drive_step(&shared, &stop), RunnerStep::Continue);
        assert_eq!(ok_completed_upper.load(Ordering::Acquire), 1);
        assert_eq!(progress.completed_fsn(), None);

        let mut guard = Some(shared.lock().unwrap());
        ack_ready.store(true, Ordering::Release);
        let shared_for_step = Arc::clone(&shared);
        std::thread::scope(|scope| {
            let step_thread = scope.spawn(|| core.drive_step(&shared_for_step, &stop));
            let deadline = Instant::now() + Duration::from_secs(2);
            while Instant::now() < deadline {
                if progress.completed_fsn() == Some(0) {
                    drop(guard.take());
                    assert_eq!(step_thread.join().unwrap(), RunnerStep::Continue);
                    return;
                }
                thread::sleep(Duration::from_millis(10));
            }
            drop(guard.take());
            let _ = step_thread.join();
            panic!("durable ACK progress waited for shared-store mutex");
        });
    }

    #[test]
    fn threaded_sfa_ok_fsn_uses_completed_fsn_lower_bound() {
        let dir = TempDir::new().unwrap();
        let queue = SfaFrameQueue::open(SfaQueueOptions {
            slot_dir: dir.path().to_path_buf(),
            segment_size_bytes: 4096,
            max_bytes: 8192,
            periodic_sync_interval: None,
        })
        .unwrap();
        let mut driver = QwpWsCoreTestHarness::from_queue(queue, FakeOrderedServer::no_response());
        let receipt = driver.try_submit(b"sfa-completed").unwrap();
        let (store, send_core) = driver.into_parts();
        let progress = store.progress_view();
        progress.complete_through_fsn(receipt.fsn).unwrap();
        let runner = SyncQwpWsRunner::start_with_append_deadline(
            store,
            send_core,
            Duration::from_secs(5),
            Arc::new(TrafficGate::default()),
        );

        assert_eq!(runner.ok_fsn().unwrap(), Some(receipt.fsn));
    }

    #[test]
    fn threaded_sfa_watermark_reads_do_not_take_shared_store_mutex() {
        let dir = TempDir::new().unwrap();
        let queue = SfaFrameQueue::open(SfaQueueOptions {
            slot_dir: dir.path().to_path_buf(),
            segment_size_bytes: 4096,
            max_bytes: 8192,
            periodic_sync_interval: None,
        })
        .unwrap();
        let driver = QwpWsCoreTestHarness::from_queue(queue, FakeOrderedServer::no_response());
        let mut runner =
            SyncQwpWsRunner::start_driver_with_append_deadline(driver, Duration::from_secs(5));
        let fsn = runner.publish_replay_payload(b"sfa-first").unwrap();

        let shared = Arc::clone(&runner.shared);
        let mut guard = Some(shared.lock().unwrap());
        std::thread::scope(|scope| {
            let (watermarks_tx, watermarks_rx) = mpsc::channel();
            let runner = &runner;
            scope.spawn(move || {
                let result = (runner.published_fsn(), runner.ok_fsn(), runner.acked_fsn());
                let _ = watermarks_tx.send(result);
            });

            let (published, ok, acked) = match watermarks_rx.recv_timeout(Duration::from_secs(2)) {
                Ok(result) => result,
                Err(err) => {
                    drop(guard.take());
                    let _ = watermarks_rx.recv_timeout(Duration::from_secs(2));
                    panic!("watermark read waited for shared-store mutex: {err:?}");
                }
            };
            assert_eq!(published.unwrap(), Some(fsn));
            assert_eq!(ok.unwrap(), None);
            assert_eq!(acked.unwrap(), None);
        });

        drop(guard);
        drop(runner);
    }

    #[derive(Debug)]
    struct BlockingReconnectTransport {
        send_started: mpsc::Sender<()>,
        reconnect_started: mpsc::Sender<()>,
        release_reconnect: mpsc::Receiver<()>,
        should_fail_send: bool,
        sent_frames: Vec<SentFrame>,
    }

    impl QwpWsCoreTransport for BlockingReconnectTransport {
        fn try_poll_response(&mut self) -> Result<TransportPoll, TransportFailure> {
            Ok(TransportPoll::Idle)
        }

        fn send_frame(
            &mut self,
            frame: OutboundFrameView<'_>,
        ) -> Result<TransportSendResult, TransportFailure> {
            if self.should_fail_send {
                self.should_fail_send = false;
                self.send_started.send(()).unwrap();
                return Err(TransportFailure::Disconnect(crate::Error::new(
                    crate::ErrorCode::SocketError,
                    "fake disconnect before reconnect",
                )));
            }
            self.sent_frames.push(frame.sent_frame());
            Ok(TransportSendResult::NoResponse)
        }

        fn restart_connection(&mut self, _reason: ReconnectReason) -> Result<(), DriverError> {
            self.reconnect_started.send(()).unwrap();
            self.release_reconnect
                .recv_timeout(Duration::from_secs(5))
                .unwrap();
            Ok(())
        }
    }

    #[test]
    fn recycle_session_defers_during_reconnect() {
        let (send_tx, _) = mpsc::channel();
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let transport = RecycleBarrierTransport {
            entered: entered_tx,
            release: release_rx,
            reconnect: true,
            terminal: false,
            first: true,
            sent: send_tx,
        };
        let mut runner = SyncQwpWsRunner::start(QwpWsCoreTestHarness::from_queue(
            memory_queue(1024),
            transport,
        ));
        entered_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        let started = Instant::now();
        assert!(runner.request_recycle(None).unwrap().is_none());
        assert!(started.elapsed() < Duration::from_secs(1));
        runner.publish_replay_payload(b"after defer").unwrap();
        release_tx.send(()).unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while runner.acked_fsn().unwrap() != Some(0) && Instant::now() < deadline {
            thread::yield_now();
        }
        assert_eq!(runner.acked_fsn().unwrap(), Some(0));
        assert!(
            !runner.stop.load(Ordering::Acquire),
            "a deferred request cannot park later"
        );
    }

    #[test]
    fn recycle_session_pending_timeout_is_only_waited_once() {
        let (mut runner, entered, release) = recycle_barrier_runner(false);
        entered.recv_timeout(Duration::from_secs(5)).unwrap();
        runner.shutdown_timeout = Duration::from_millis(25);
        assert!(runner.request_recycle(None).is_err());
        // A second full wait would make this test take ten seconds.
        runner.shutdown_timeout = Duration::from_secs(10);
        let started = Instant::now();
        assert!(runner.request_recycle(None).is_err());
        assert!(started.elapsed() < Duration::from_secs(1));
        assert!(runner.thread.is_some());
        assert!(runner.parked.lock().unwrap().is_none());
        release.send(()).unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while !runner.thread.as_ref().unwrap().is_finished() && Instant::now() < deadline {
            thread::yield_now();
        }
        let permit = runner.request_recycle(None).unwrap().unwrap();
        assert!(runner.thread.is_none());
        assert!(runner.parked.lock().unwrap().is_some());
        runner
            .with_recycle_storage(&permit, |queue, producer| {
                queue
                    .reset_drained(producer)
                    .map_err(DriverError::from)
                    .map_err(driver_error_to_error_without_state)
            })
            .unwrap();
        assert!(
            runner
                .publish_replay_payload(b"sealed after storage reset")
                .is_err()
        );
        runner.finish_recycle(permit, false).unwrap();
        assert!(runner.thread.is_some());
        runner.publish_replay_payload(b"new").unwrap();
    }

    #[test]
    fn recycle_session_boundary_breach_terminalizes_before_storage() {
        let mut runner = SyncQwpWsRunner::start(QwpWsCoreTestHarness::from_queue(
            memory_queue(1024),
            FakeOrderedServer::ack_each_send(),
        ));
        let permit = runner.request_recycle(None).unwrap().unwrap();
        // Simulate an internal owner violating the publication seal.
        runner
            .producer
            .as_mut()
            .unwrap()
            .try_submit(b"unexpected")
            .unwrap();
        let result = runner.with_recycle_storage(&permit, |_, _| Ok(()));
        assert!(
            result.is_err(),
            "a stale drained proof cannot authorize storage work"
        );
        assert!(runner.lifecycle_is_terminal());
        assert!(runner.pending_recycle.is_some());
    }

    #[test]
    fn recycle_session_spawn_failure_keeps_installed_capsule_for_resume() {
        let mut runner = SyncQwpWsRunner::start(QwpWsCoreTestHarness::from_queue(
            memory_queue(1024),
            FakeOrderedServer::ack_each_send(),
        ));
        let permit = runner.request_recycle(None).unwrap().unwrap();
        FAIL_NEXT_RECYCLE_SPAWN.with(|fail| fail.set(true));
        assert!(
            runner
                .finish_recycle(permit, true)
                .unwrap_err()
                .msg()
                .contains("spawn failure")
        );
        assert!(runner.pending_recycle.as_ref().unwrap().installed);
        assert!(runner.thread.is_none());
        assert!(runner.parked.lock().unwrap().is_some());
        assert!(runner.publish_replay_payload(b"sealed").is_err());
        let installed_gate = Arc::clone(&runner.traffic_gate);
        let permit = runner.request_recycle(None).unwrap().unwrap();
        runner.finish_recycle(permit, true).unwrap();
        assert!(
            Arc::ptr_eq(&installed_gate, &runner.traffic_gate),
            "resume must not reinstall the session"
        );
        assert!(runner.pending_recycle.is_none());
    }

    #[test]
    fn recycle_session_worker_failure_retains_ownership_and_terminal_event_once() {
        let (mut runner, entered, release) = recycle_barrier_runner(false);
        entered.recv_timeout(Duration::from_secs(5)).unwrap();
        runner.shutdown_timeout = Duration::from_millis(10);
        assert!(runner.request_recycle(None).is_err());
        // Disconnecting the barrier deliberately panics the test transport.
        drop(release);
        let deadline = Instant::now() + Duration::from_secs(5);
        while !runner.thread.as_ref().unwrap().is_finished() && Instant::now() < deadline {
            thread::yield_now();
        }
        let err = runner.request_recycle(None).unwrap_err();
        assert!(err.msg().contains("worker panicked"));
        assert!(runner.thread.is_none());
        assert!(runner.pending_recycle.is_some());
        assert!(
            runner
                .request_recycle(None)
                .unwrap_err()
                .msg()
                .contains("worker panicked")
        );
        let mut store = runner.lock_shared().unwrap();
        assert_eq!(store.poll_event(), Some(DriverEvent::Terminal));
        assert_eq!(store.poll_event(), None);
    }

    #[test]
    fn recycle_session_worker_failure_on_close_retains_terminal_event_once() {
        let (mut runner, entered, release) = recycle_barrier_runner(false);
        entered.recv_timeout(Duration::from_secs(5)).unwrap();
        runner.shutdown_timeout = Duration::from_millis(10);
        assert!(runner.request_recycle(None).is_err());
        // Disconnecting the barrier panics outside the publication-store mutex.
        drop(release);
        let deadline = Instant::now() + Duration::from_secs(5);
        while !runner.thread.as_ref().unwrap().is_finished() && Instant::now() < deadline {
            thread::yield_now();
        }
        assert!(runner.thread.as_ref().unwrap().is_finished());
        runner.begin_close();
        let err = runner.drain_to_deadline(Some(deadline)).unwrap_err();
        assert!(err.msg().contains("worker panicked"));
        assert!(runner.thread.is_none());
        assert!(runner.pending_recycle.is_some());
        assert!(runner.lifecycle_is_terminal());
        assert!(
            runner
                .drain_to_deadline(Some(deadline))
                .unwrap_err()
                .msg()
                .contains("worker panicked")
        );
        let mut store = runner.lock_shared().unwrap();
        assert_eq!(store.poll_event(), Some(DriverEvent::Terminal));
        assert_eq!(store.poll_event(), None);
    }

    #[test]
    fn recycle_session_ok_does_not_discard_pending_durable_ack() {
        let ready = Arc::new(AtomicBool::new(false));
        let transport = DurableAckWhenReadyTransport {
            ack_ready: Arc::clone(&ready),
            sent_frames: Vec::new(),
        };
        let driver = QwpWsCoreTestHarness::from_queue_with_reconnect_policy(
            memory_queue(1024),
            transport,
            ReconnectPolicy::bounded(Duration::MAX, Duration::ZERO, Duration::ZERO),
            true,
        );
        let mut runner = SyncQwpWsRunner::start(driver);
        runner.publish_replay_payload(b"old").unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while runner.ok_fsn().unwrap() != Some(0) && Instant::now() < deadline {
            thread::yield_now();
        }
        assert_eq!(runner.ok_fsn().unwrap(), Some(0));
        assert_eq!(runner.acked_fsn().unwrap(), None);
        assert!(runner.request_recycle(Some(0)).unwrap().is_none());
        assert!(runner.pending_recycle.is_none());
        ready.store(true, Ordering::Release);
        let deadline = Instant::now() + Duration::from_secs(5);
        while runner.acked_fsn().unwrap() != Some(0) && Instant::now() < deadline {
            thread::yield_now();
        }
        assert!(runner.request_recycle(Some(0)).unwrap().is_some());
    }

    #[test]
    fn recycle_session_close_cannot_release_slot_before_parked_worker_exits() {
        let dir = TempDir::new().unwrap();
        let options = recycle_slot_options(&dir, "recycle-close-stall");
        let (entered, entered_rx) = mpsc::channel();
        let (release_tx, release) = mpsc::channel();
        let (sent, _) = mpsc::channel();
        let transport = RecycleBarrierTransport {
            entered,
            release,
            reconnect: false,
            terminal: false,
            first: true,
            sent,
        };
        let queue = SfaSlotQueue::open(options.clone()).unwrap();
        let mut runner = SyncQwpWsRunner::start(QwpWsCoreTestHarness::from_queue(queue, transport));
        entered_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        runner.shutdown_timeout = Duration::from_millis(10);
        assert!(runner.request_recycle(None).is_err());
        runner.begin_close();
        let error = runner.drain_to_deadline(Some(Instant::now())).unwrap_err();
        assert!(error.msg().contains("waiting for recycled worker"));
        assert_eq!(runner.lifecycle.load(), PublicationState::Closing);
        assert!(runner.pending_recycle.is_some());
        assert!(!runner.thread.as_ref().unwrap().is_finished());
        // Close has started, but the channel still holds the accepted worker.
        // Probe before releasing it so exclusion does not depend on scheduling.
        assert_recycle_slot_locked(&options.sf_dir, &options.sender_id, "blocked close");
        assert!(matches!(
            SfaSlotQueue::open(options.clone()),
            Err(SfaQueueError::SlotInUse { .. })
        ));
        assert!(!runner.thread.as_ref().unwrap().is_finished());
        release_tx.send(()).unwrap();
        runner
            .drain_to_deadline(Some(Instant::now() + Duration::from_secs(5)))
            .unwrap();
        assert!(runner.thread.is_none());
        let mut reopened = SfaSlotQueue::open(options.clone()).unwrap();
        reopened.close().unwrap();
        SfaSlotQueue::open_replay_only_existing(SfaQueueOptions {
            slot_dir: options.sf_dir.join(&options.sender_id),
            segment_size_bytes: options.segment_size_bytes,
            max_bytes: options.max_bytes,
            periodic_sync_interval: options.periodic_sync_interval,
        })
        .unwrap();
    }

    pub(super) fn assert_recycle_slot_locked(root: &std::path::Path, sender_id: &str, phase: &str) {
        let result = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "ingress::sender::qwp_ws_sfa_slot::tests::qwp_ws_sfa_slot_child_process_lock_helper",
                "--ignored",
            ])
            .env("QDB_SFA_SLOT_CHILD_MODE", "probe-locked")
            .env("QDB_SFA_SLOT_CHILD_SF_DIR", root)
            .env("QDB_SFA_SLOT_CHILD_SENDER_ID", sender_id)
            .output()
            .unwrap();
        let orphan = SfaSlotQueue::open_replay_only_existing(SfaQueueOptions {
            slot_dir: root.join(sender_id),
            segment_size_bytes: 4096,
            max_bytes: 32768,
            periodic_sync_interval: None,
        });
        assert!(
            result.status.success() && matches!(orphan, Err(SfaQueueError::SlotInUse { .. })),
            "slot exclusion during {phase}: external contender status={}, stdout={}, stderr={}, orphan={orphan:?}",
            result.status,
            String::from_utf8_lossy(&result.stdout),
            String::from_utf8_lossy(&result.stderr),
        );
    }

    #[test]
    fn recycle_session_full_budget_runs_drained_maintenance_before_reset() {
        let dir = TempDir::new().unwrap();
        let mut options = recycle_slot_options(&dir, "recycle-full-budget");
        options.segment_size_bytes = 38;
        options.max_bytes = 76;
        let mut queue = SfaSlotQueue::open(options).unwrap();
        drop(queue.take_persisted_symbol_dict());
        let mut producer = queue.take_producer().unwrap();
        producer.try_submit(b"one").unwrap();
        producer.try_submit(b"two").unwrap();
        queue.progress_view().complete_through_fsn(1).unwrap();
        queue.persist_completed_fsn(1);
        assert!(queue.reset_drained(&mut producer).is_err());
        reset_recycle_storage(&mut queue, &mut producer).unwrap();
        assert_eq!(producer.try_submit(b"new").unwrap().fsn, 2);
    }

    fn recycle_slot_options(dir: &TempDir, sender_id: &str) -> SfaSlotOptions {
        SfaSlotOptions {
            sf_dir: dir.path().to_path_buf(),
            sender_id: sender_id.to_string(),
            segment_size_bytes: 4096,
            max_bytes: 8192,
            periodic_sync_interval: None,
        }
    }

    #[test]
    fn recycle_session_exclusive_store_failure_retains_slot() {
        let dir = TempDir::new().unwrap();
        let options = recycle_slot_options(&dir, "recycle-exclusive");
        let mut queue = SfaSlotQueue::open(options.clone()).unwrap();
        drop(queue.take_persisted_symbol_dict());
        let mut runner = SyncQwpWsRunner::start(QwpWsCoreTestHarness::from_queue(
            queue,
            FakeOrderedServer::ack_each_send(),
        ));
        let observer = Arc::clone(&runner.shared);
        let permit = runner.request_recycle(None).unwrap().unwrap();
        let err = runner
            .with_recycle_storage(&permit, reset_recycle_storage)
            .unwrap_err();
        assert!(err.msg().contains("still has observers"));
        assert!(matches!(
            SfaSlotQueue::open(options.clone()),
            Err(SfaQueueError::SlotInUse { .. })
        ));
        assert!(runner.publish_replay_payload(b"sealed").is_err());
        assert!(observer.try_lock().is_ok());
        drop(observer);
        runner
            .with_recycle_storage(&permit, reset_recycle_storage)
            .unwrap();
        assert!(matches!(
            SfaSlotQueue::open(options),
            Err(SfaQueueError::SlotInUse { .. })
        ));
        runner.finish_recycle(permit, true).unwrap();
    }

    #[test]
    fn recycle_session_fresh_wire_sequence_preserves_fsn_and_totals() {
        let (entered, _) = mpsc::channel();
        let (_, release) = mpsc::channel();
        let (sent, received) = mpsc::channel();
        let transport = RecycleBarrierTransport {
            entered,
            release,
            reconnect: false,
            terminal: false,
            first: false,
            sent,
        };
        let mut runner = SyncQwpWsRunner::start(QwpWsCoreTestHarness::from_queue(
            memory_queue(1024),
            transport,
        ));
        for fsn in 0..2 {
            assert_eq!(runner.publish_replay_payload(b"old").unwrap(), fsn);
            let frame = received.recv_timeout(Duration::from_secs(5)).unwrap();
            assert_eq!((frame.fsn, frame.wire_seq), (fsn, fsn));
        }
        let deadline = Instant::now() + Duration::from_secs(5);
        while runner.acked_fsn().unwrap() != Some(1) && Instant::now() < deadline {
            thread::yield_now();
        }
        let original_acks = runner.counters().unwrap().total_acks;
        let original_store = Arc::as_ptr(&runner.shared);
        let original_ok = Arc::as_ptr(&runner.ok_completed_upper);
        let old_gate = Arc::clone(&runner.traffic_gate);
        let permit = runner.request_recycle(Some(1)).unwrap().unwrap();
        runner
            .with_recycle_storage(&permit, |queue, producer| {
                queue
                    .reset_drained(producer)
                    .map_err(DriverError::from)
                    .map_err(driver_error_to_error_without_state)
            })
            .unwrap();
        runner.finish_recycle(permit, false).unwrap();
        assert!(old_gate.is_shutdown());
        assert!(!runner.traffic_gate.is_shutdown());
        assert_eq!(Arc::as_ptr(&runner.shared), original_store);
        assert_eq!(Arc::as_ptr(&runner.ok_completed_upper), original_ok);
        assert_eq!(runner.publish_replay_payload(b"new").unwrap(), 2);
        let frame = received.recv_timeout(Duration::from_secs(5)).unwrap();
        assert_eq!((frame.fsn, frame.wire_seq), (2, 0));
        let deadline = Instant::now() + Duration::from_secs(5);
        while runner.acked_fsn().unwrap() != Some(2) && Instant::now() < deadline {
            thread::yield_now();
        }
        let _permit = runner.request_recycle(Some(2)).unwrap().unwrap();
        let totals = runner.counters().unwrap();
        assert_eq!(totals.total_frames_sent, 3);
        assert_eq!(totals.total_acks, original_acks);
    }

    #[test]
    fn recycle_session_manual_installs_without_dial_or_worker() {
        let queue = SfaSlotQueue::open_memory(SfaMemoryQueueOptions {
            segment_size_bytes: 128,
            max_bytes: 512,
        })
        .unwrap();
        let (mut store, mut core) =
            QwpWsCoreTestHarness::from_queue(queue, FakeOrderedServer::ack_each_send())
                .into_parts();
        let mut recycle = ManualRecycle::new(Arc::new(TrafficGate::default()));
        assert_eq!(store.try_submit(b"old").unwrap().fsn, 0);
        core.drive_once(&mut store).unwrap();
        let permit = recycle
            .request(&mut store, &mut core, Some(0))
            .unwrap()
            .unwrap();
        reset_recycle_storage(
            store.recycle_queue_mut(),
            recycle.producer.as_mut().unwrap(),
        )
        .unwrap();
        recycle
            .finish(&mut store, &mut core, permit, false)
            .unwrap();
        assert!(core.has_pending_reconnect());
        assert_eq!(
            store.counters().total_reconnects_succeeded,
            0,
            "installation cannot dial on the manual caller"
        );
        assert_eq!(store.try_submit(b"new").unwrap().fsn, 1);
        core.drive_once(&mut store).unwrap();
        core.drive_once(&mut store).unwrap();
        assert_eq!(store.completed_fsn(), Some(1));
        assert_eq!(store.counters().total_reconnects_succeeded, 1);
    }

    #[test]
    fn recycle_session_storage_stall_retains_slot_and_can_resume() {
        let dir = TempDir::new().unwrap();
        let mut options = recycle_slot_options(&dir, "recycle-storage-stall");
        options.periodic_sync_interval = Some(Duration::from_secs(3600));
        let mut queue = SfaSlotQueue::open(options.clone()).unwrap();
        drop(queue.take_persisted_symbol_dict());
        let fsn = queue.try_publish(b"old").unwrap().fsn;
        queue.progress_view().complete_through_fsn(fsn).unwrap();
        queue.persist_completed_fsn(fsn);
        let task = queue.take_storage_maintenance_step(false).unwrap().unwrap();
        let mut runner = SyncQwpWsRunner::start(QwpWsCoreTestHarness::from_queue(
            queue,
            FakeOrderedServer::no_response(),
        ));
        assert!(runner.request_recycle(Some(fsn)).is_err());
        assert!(runner.thread.is_none());
        assert!(runner.publish_replay_payload(b"sealed").is_err());
        assert!(matches!(
            SfaSlotQueue::open(options.clone()),
            Err(SfaQueueError::SlotInUse { .. })
        ));
        let result = task.perform().unwrap();
        {
            let mut store = runner.lock_shared().unwrap();
            store.finish_storage_maintenance(result).unwrap();
            store.complete_storage_maintenance().unwrap();
        }
        let permit = runner.request_recycle(Some(fsn)).unwrap().unwrap();
        runner
            .with_recycle_storage(&permit, reset_recycle_storage)
            .unwrap();
        runner.finish_recycle(permit, false).unwrap();
        assert!(matches!(
            SfaSlotQueue::open(options),
            Err(SfaQueueError::SlotInUse { .. })
        ));
    }

    #[test]
    fn recycle_session_rejects_stale_permits_and_close_before_install() {
        let mut runner = SyncQwpWsRunner::start(QwpWsCoreTestHarness::from_queue(
            memory_queue(1024),
            FakeOrderedServer::ack_each_send(),
        ));
        let old = runner.request_recycle(None).unwrap().unwrap();
        let current = runner.request_recycle(None).unwrap().unwrap();
        assert!(runner.finish_recycle(old, false).is_err());
        runner.begin_close();
        assert!(runner.finish_recycle(current, false).is_err());
        assert!(runner.thread.is_none());
        assert!(runner.parked.lock().unwrap().is_some());
        assert!(runner.publish_replay_payload(b"closed").is_err());
    }

    struct RecycleBarrierTransport {
        entered: mpsc::Sender<()>,
        release: mpsc::Receiver<()>,
        reconnect: bool,
        terminal: bool,
        first: bool,
        sent: mpsc::Sender<SentFrame>,
    }

    impl QwpWsCoreTransport for RecycleBarrierTransport {
        fn try_poll_response(&mut self) -> Result<TransportPoll, TransportFailure> {
            if self.first {
                self.first = false;
                if self.reconnect {
                    return Err(TransportFailure::Retryable(error::fmt!(
                        SocketError,
                        "reconnect barrier"
                    )));
                }
                self.entered.send(()).unwrap();
                self.release.recv_timeout(Duration::from_secs(5)).unwrap();
                if self.terminal {
                    return Err(TransportFailure::Terminal(error::fmt!(
                        SocketError,
                        "terminal during park"
                    )));
                }
            }
            Ok(TransportPoll::Idle)
        }
        fn restart_connection(&mut self, _: ReconnectReason) -> Result<(), DriverError> {
            if self.reconnect {
                self.entered.send(()).unwrap();
                self.release.recv_timeout(Duration::from_secs(5)).unwrap();
                self.reconnect = false;
            }
            Ok(())
        }
        fn send_frame(
            &mut self,
            frame: OutboundFrameView<'_>,
        ) -> Result<TransportSendResult, TransportFailure> {
            let _ = self.sent.send(frame.sent_frame());
            Ok(TransportSendResult::Response(TransportResponse::Ack {
                wire_seq: frame.wire_seq,
            }))
        }
    }

    fn recycle_barrier_runner(
        terminal: bool,
    ) -> (
        SyncQwpWsRunner<SfaFrameQueue>,
        mpsc::Receiver<()>,
        mpsc::Sender<()>,
    ) {
        let (entered, entered_rx) = mpsc::channel();
        let (release_tx, release) = mpsc::channel();
        let (sent, _) = mpsc::channel();
        let transport = RecycleBarrierTransport {
            entered,
            release,
            reconnect: false,
            terminal,
            first: true,
            sent,
        };
        (
            SyncQwpWsRunner::start(QwpWsCoreTestHarness::from_queue(
                memory_queue(1024),
                transport,
            )),
            entered_rx,
            release_tx,
        )
    }

    #[test]
    fn recycle_session_terminal_during_park() {
        let (mut runner, entered, release) = recycle_barrier_runner(true);
        entered.recv_timeout(Duration::from_secs(5)).unwrap();
        runner.shutdown_timeout = Duration::from_millis(10);
        assert!(
            runner.request_recycle(None).is_err(),
            "accepted park must stay pending when its worker stalls"
        );
        assert!(runner.publish_replay_payload(b"sealed").is_err());
        release.send(()).unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while !runner.thread.as_ref().unwrap().is_finished() && Instant::now() < deadline {
            thread::yield_now();
        }
        let err = runner
            .request_recycle(None)
            .expect_err("terminal must beat the satisfied empty boundary");
        assert!(err.to_string().contains("terminal during park"), "{err}");
        assert!(runner.lifecycle_is_terminal());
    }

    #[test]
    fn recycle_session_close_wins() {
        let (mut runner, entered, release) = recycle_barrier_runner(false);
        entered.recv_timeout(Duration::from_secs(5)).unwrap();
        runner.shutdown_timeout = Duration::from_millis(10);
        assert!(runner.request_recycle(None).is_err());
        runner.begin_close();
        release.send(()).unwrap();
        assert!(runner.request_recycle(None).is_err());
        assert!(runner.publish_replay_payload(b"closed").is_err());
        assert_eq!(runner.lifecycle.load(), PublicationState::Closing);
    }

    #[test]
    fn threaded_runner_accepts_publication_while_reconnect_is_blocked() {
        let (send_started_tx, send_started_rx) = mpsc::channel();
        let (reconnect_started_tx, reconnect_started_rx) = mpsc::channel();
        let (release_reconnect_tx, release_reconnect_rx) = mpsc::channel();
        let queue = memory_queue(1024);
        let transport = BlockingReconnectTransport {
            send_started: send_started_tx,
            reconnect_started: reconnect_started_tx,
            release_reconnect: release_reconnect_rx,
            should_fail_send: true,
            sent_frames: Vec::new(),
        };
        let driver = QwpWsCoreTestHarness::from_queue(queue, transport);
        let mut runner = SyncQwpWsRunner::start(driver);

        runner.publish_replay_payload(b"first").unwrap();
        send_started_rx
            .recv_timeout(Duration::from_secs(5))
            .unwrap();
        reconnect_started_rx
            .recv_timeout(Duration::from_secs(5))
            .unwrap();

        std::thread::scope(|scope| {
            let (published_tx, published_rx) = mpsc::channel();
            let runner = &mut runner;
            let publish_thread = scope.spawn(move || {
                let result = runner.publish_replay_payload(b"second");
                let _ = published_tx.send(result.map(|_| ()));
            });

            let publish_result = match published_rx.recv_timeout(Duration::from_secs(2)) {
                Ok(result) => result,
                Err(err) => {
                    let _ = release_reconnect_tx.send(());
                    publish_thread.join().unwrap();
                    panic!("publication waited for blocked reconnect: {err:?}");
                }
            };
            publish_result.unwrap();
            publish_thread.join().unwrap();
        });

        release_reconnect_tx.send(()).unwrap();
        drop(runner);
    }

    #[derive(Debug)]
    struct SignalResponseTransport {
        sent_frame: mpsc::Sender<SentFrame>,
        ack: mpsc::Receiver<()>,
        terminal: mpsc::Receiver<()>,
        sent_frames: Vec<SentFrame>,
    }

    impl QwpWsCoreTransport for SignalResponseTransport {
        fn try_poll_response(&mut self) -> Result<TransportPoll, TransportFailure> {
            if self.terminal.try_recv().is_ok() {
                return Err(TransportFailure::Terminal(crate::Error::new(
                    crate::ErrorCode::SocketError,
                    "synthetic terminal failure",
                )));
            }
            if self.ack.try_recv().is_ok() {
                return Ok(TransportPoll::Response(TransportResponse::Ack {
                    wire_seq: 0,
                }));
            }
            Ok(TransportPoll::Idle)
        }

        fn send_frame(
            &mut self,
            frame: OutboundFrameView<'_>,
        ) -> Result<TransportSendResult, TransportFailure> {
            let sent_frame = frame.sent_frame();
            self.sent_frames.push(sent_frame);
            self.sent_frame.send(sent_frame).unwrap();
            Ok(TransportSendResult::NoResponse)
        }
    }

    // Two 10-byte frames fill the two-segment byte budget; a third publish then
    // backpressures until acks trim an earlier frame's segment.
    fn byte_backpressured_queue() -> SfaFrameQueue {
        SfaFrameQueue::open_memory(SfaMemoryQueueOptions {
            segment_size_bytes: 48,
            max_bytes: 96,
        })
        .unwrap()
    }

    #[test]
    fn threaded_runner_waits_for_ack_when_sfa_publication_is_backpressured() {
        let (sent_tx, sent_rx) = mpsc::channel();
        let (ack_tx, ack_rx) = mpsc::channel();
        let (_terminal_tx, terminal_rx) = mpsc::channel();
        let transport = SignalResponseTransport {
            sent_frame: sent_tx,
            ack: ack_rx,
            terminal: terminal_rx,
            sent_frames: Vec::new(),
        };
        let driver = QwpWsCoreTestHarness::from_queue(byte_backpressured_queue(), transport);
        let mut runner =
            SyncQwpWsRunner::start_driver_with_append_deadline(driver, Duration::from_secs(5));

        runner.publish_replay_payload(b"aaaaaaaaaa").unwrap();
        assert_eq!(sent_rx.recv_timeout(Duration::from_secs(5)).unwrap().fsn, 0);
        runner.publish_replay_payload(b"bbbbbbbbbb").unwrap();
        assert_eq!(sent_rx.recv_timeout(Duration::from_secs(5)).unwrap().fsn, 1);

        std::thread::scope(|scope| {
            let (published_tx, published_rx) = mpsc::channel();
            let runner = &mut runner;
            let publish_thread = scope.spawn(move || {
                let result = runner.publish_replay_payload(b"cccccccccc");
                let _ = published_tx.send(result.map(|_| ()));
            });

            assert!(
                published_rx
                    .recv_timeout(Duration::from_millis(50))
                    .is_err()
            );
            ack_tx.send(()).unwrap();
            published_rx
                .recv_timeout(Duration::from_secs(5))
                .unwrap()
                .unwrap();
            publish_thread.join().unwrap();
        });
    }

    #[test]
    fn threaded_runner_times_out_when_sfa_publication_stays_backpressured() {
        let (sent_tx, sent_rx) = mpsc::channel();
        let (_ack_tx, ack_rx) = mpsc::channel();
        let (_terminal_tx, terminal_rx) = mpsc::channel();
        let transport = SignalResponseTransport {
            sent_frame: sent_tx,
            ack: ack_rx,
            terminal: terminal_rx,
            sent_frames: Vec::new(),
        };
        let driver = QwpWsCoreTestHarness::from_queue(byte_backpressured_queue(), transport);
        let mut runner =
            SyncQwpWsRunner::start_driver_with_append_deadline(driver, Duration::from_millis(20));

        runner.publish_replay_payload(b"aaaaaaaaaa").unwrap();
        assert_eq!(sent_rx.recv_timeout(Duration::from_secs(5)).unwrap().fsn, 0);
        runner.publish_replay_payload(b"bbbbbbbbbb").unwrap();
        assert_eq!(sent_rx.recv_timeout(Duration::from_secs(5)).unwrap().fsn, 1);

        let err = runner.publish_replay_payload(b"cccccccccc").unwrap_err();
        assert_eq!(err.code(), crate::ErrorCode::SocketError);
        assert!(
            err.msg()
                .contains("timed out waiting for ACK-driven segment trim"),
            "got: {}",
            err.msg()
        );
    }

    #[test]
    fn threaded_runner_wakes_backpressured_publication_on_terminal_error() {
        let (sent_tx, sent_rx) = mpsc::channel();
        let (_ack_tx, ack_rx) = mpsc::channel();
        let (terminal_tx, terminal_rx) = mpsc::channel();
        let transport = SignalResponseTransport {
            sent_frame: sent_tx,
            ack: ack_rx,
            terminal: terminal_rx,
            sent_frames: Vec::new(),
        };
        let driver = QwpWsCoreTestHarness::from_queue(byte_backpressured_queue(), transport);
        let mut runner =
            SyncQwpWsRunner::start_driver_with_append_deadline(driver, Duration::from_secs(5));

        runner.publish_replay_payload(b"aaaaaaaaaa").unwrap();
        assert_eq!(sent_rx.recv_timeout(Duration::from_secs(5)).unwrap().fsn, 0);
        runner.publish_replay_payload(b"bbbbbbbbbb").unwrap();
        assert_eq!(sent_rx.recv_timeout(Duration::from_secs(5)).unwrap().fsn, 1);

        std::thread::scope(|scope| {
            let (published_tx, published_rx) = mpsc::channel();
            let runner = &mut runner;
            let publish_thread = scope.spawn(move || {
                let result = runner.publish_replay_payload(b"cccccccccc");
                let _ = published_tx.send(result.map(|_| ()));
            });

            assert!(
                published_rx
                    .recv_timeout(Duration::from_millis(50))
                    .is_err()
            );
            terminal_tx.send(()).unwrap();
            let err = published_rx
                .recv_timeout(Duration::from_secs(5))
                .unwrap()
                .unwrap_err();
            assert_eq!(err.code(), crate::ErrorCode::SocketError);
            assert!(
                err.msg().contains("synthetic terminal failure"),
                "got: {}",
                err.msg()
            );
            publish_thread.join().unwrap();
        });
    }

    #[derive(Debug)]
    struct ImmediateFailureReconnectTransport {
        reconnect_started: mpsc::Sender<()>,
        release_reconnect: mpsc::Receiver<()>,
        should_fail_send: bool,
        sent_frames: Vec<SentFrame>,
    }

    impl QwpWsCoreTransport for ImmediateFailureReconnectTransport {
        fn try_poll_response(&mut self) -> Result<TransportPoll, TransportFailure> {
            Ok(TransportPoll::Idle)
        }

        fn send_frame(
            &mut self,
            frame: OutboundFrameView<'_>,
        ) -> Result<TransportSendResult, TransportFailure> {
            let sent_frame = frame.sent_frame();
            self.sent_frames.push(sent_frame);
            if self.should_fail_send {
                self.should_fail_send = false;
                return Ok(TransportSendResult::Failure(TransportFailure::Disconnect(
                    crate::Error::new(crate::ErrorCode::SocketError, "fake disconnect after send"),
                )));
            }
            Ok(TransportSendResult::NoResponse)
        }

        fn restart_connection(&mut self, _reason: ReconnectReason) -> Result<(), DriverError> {
            self.reconnect_started.send(()).unwrap();
            self.release_reconnect
                .recv_timeout(Duration::from_secs(5))
                .unwrap();
            Ok(())
        }
    }

    #[test]
    fn threaded_runner_records_immediate_transport_failure_as_sent() {
        let (reconnect_started_tx, reconnect_started_rx) = mpsc::channel();
        let (release_reconnect_tx, release_reconnect_rx) = mpsc::channel();
        let queue = memory_queue(1024);
        let transport = ImmediateFailureReconnectTransport {
            reconnect_started: reconnect_started_tx,
            release_reconnect: release_reconnect_rx,
            should_fail_send: true,
            sent_frames: Vec::new(),
        };
        let driver = QwpWsCoreTestHarness::from_queue(queue, transport);
        let mut runner = SyncQwpWsRunner::start(driver);

        runner.publish_replay_payload(b"first").unwrap();
        reconnect_started_rx
            .recv_timeout(Duration::from_secs(5))
            .unwrap();

        // The sent event is flushed before reconnect I/O starts. Pin the
        // background-runner counter path while reconnect is deliberately
        // blocked so no replay can race this assertion.
        {
            let store = runner.lock_shared().unwrap();
            let counters = store.counters();
            assert_eq!(counters.total_frames_sent, 1);
            assert_eq!(counters.total_frames_replayed, 0);
        }

        release_reconnect_tx.send(()).unwrap();

        let events = {
            let mut store = runner.lock_shared().unwrap();
            let mut events = Vec::new();
            while let Some(event) = store.poll_event() {
                events.push(event);
            }
            events
        };
        assert_eq!(
            events.first(),
            Some(&DriverEvent::Sent {
                fsn: 0,
                wire_seq: 0,
            })
        );
        if let Some(reconnect_idx) = events
            .iter()
            .position(|event| matches!(event, DriverEvent::Reconnected { .. }))
        {
            assert!(
                reconnect_idx > 0,
                "immediate transport failure was not recorded as sent before reconnect: {events:?}"
            );
        }
        drop(runner);
    }
}

#[cfg(test)]
mod publication_recycle_tests {
    use super::*;
    use crate::ingress::{AckLevel, SenderBuilder};
    use crate::tests::qwp_ws_recycle::Server;

    fn state(sender: &mut crate::ingress::Sender) -> &mut SyncQwpWsHandlerState {
        match &mut sender.handler {
            super::super::SyncProtocolHandler::SyncQwpWs(state) => state,
            _ => panic!("background sender expected"),
        }
    }

    #[test]
    fn recycle_crash_after_fresh_session_install_and_publication() {
        use crate::ingress::QwpWsProgress;
        use std::io::{BufRead, Write};
        if let Ok(conf) = std::env::var("QDB_RECYCLE_SESSION_CONF") {
            let publish = std::env::var("QDB_RECYCLE_SESSION_PUBLISH").unwrap() == "true";
            let mut sender = SenderBuilder::from_conf(conf)
                .unwrap()
                .qwp_ws_progress(QwpWsProgress::Manual)
                .unwrap()
                .build()
                .unwrap();
            let mut buffer = sender.new_buffer();
            buffer
                .table("trades")
                .unwrap()
                .symbol("sym", "old")
                .unwrap()
                .at(crate::ingress::TimestampNanos::new(7))
                .unwrap();
            sender.flush(&mut buffer).unwrap();
            sender.wait(AckLevel::Ok, Duration::from_secs(5)).unwrap();
            sender.reset_symbol_dictionary().unwrap();
            let super::super::SyncProtocolHandler::ManualQwpWs(handler) = &mut sender.handler
            else {
                panic!("manual expected")
            };
            let mut encoder = handler.encoder.take().unwrap();
            handler
                .before_publication(&mut encoder, true, false)
                .unwrap();
            assert_eq!(encoder.symbol_count(), 0);
            assert!(handler.send_core.has_pending_reconnect());
            handler.encoder = Some(encoder);
            if publish {
                buffer
                    .table("trades")
                    .unwrap()
                    .symbol("sym", "new")
                    .unwrap()
                    .at(crate::ingress::TimestampNanos::new(7))
                    .unwrap();
                assert_eq!(sender.flush_and_get_fsn(&mut buffer).unwrap(), Some(1));
                assert_eq!(sender.acked_fsn().unwrap(), Some(0));
            }
            println!("SESSION_KILL_READY");
            std::io::stdout().flush().unwrap();
            loop {
                thread::park();
            }
        }
        for durability in ["memory", "periodic"] {
            for publish in [false, true] {
                let server = Server::new();
                let dir = tempfile::TempDir::new().unwrap();
                let conf = format!(
                    "ws::addr=127.0.0.1:{};sf_dir={};sender_id=crash;sf_durability={durability};sf_max_segment_bytes=4096;symbol_dict_reset_max_wait_millis=0;",
                    server.port,
                    dir.path().display()
                );
                let mut child = std::process::Command::new(std::env::current_exe().unwrap())
                    .args(["--exact", "ingress::sender::qwp_ws::publication_recycle_tests::recycle_crash_after_fresh_session_install_and_publication", "--nocapture"])
                    .env("QDB_RECYCLE_SESSION_CONF", &conf).env("QDB_RECYCLE_SESSION_PUBLISH", publish.to_string())
                    .stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::inherit()).spawn().unwrap();
                let output = child.stdout.take().unwrap();
                let (ready, wait) = std::sync::mpsc::channel();
                let reader = thread::spawn(move || {
                    for line in std::io::BufReader::new(output).lines() {
                        if line.unwrap() == "SESSION_KILL_READY" {
                            ready.send(()).unwrap();
                        }
                    }
                });
                if let Err(error) = wait.recv_timeout(Duration::from_secs(10)) {
                    let _ = child.kill();
                    let _ = child.wait();
                    panic!("fresh-session checkpoint missing: {error}");
                }
                child.kill().unwrap();
                assert!(!child.wait().unwrap().success());
                reader.join().unwrap();
                let (_, mut expected) = server.frame();
                assert_eq!(&expected[15..18], b"old");
                expected[15..18].copy_from_slice(b"new");
                let mut recovered = SfaSlotQueue::open(SfaSlotOptions {
                    sf_dir: dir.path().to_path_buf(),
                    sender_id: "crash".into(),
                    segment_size_bytes: 4096,
                    max_bytes: 32768,
                    periodic_sync_interval: (durability == "periodic")
                        .then_some(Duration::from_secs(1)),
                })
                .unwrap();
                assert_eq!(recovered.completed_fsn(), Some(0));
                assert_eq!(recovered.published_fsn(), Some(u64::from(publish)));
                assert_eq!(recovered.oldest_unresolved_fsn(), publish.then_some(1));
                if publish {
                    let frame =
                        recovered
                            .progress_view()
                            .next_outbound_frame(
                                &mut super::super::qwp_ws_driver::SendCursor::default(),
                            )
                            .unwrap()
                            .unwrap();
                    assert_eq!(frame.fsn, 1);
                    frame
                        .payload
                        .with_bytes(|bytes| assert_eq!(bytes, expected));
                    assert_eq!(
                        PersistedSymbolDict::open(&dir.path().join("crash"))
                            .unwrap()
                            .read_loaded_symbols(),
                        [b"new"]
                    );
                }
                assert_eq!(
                    recovered.try_publish(&expected).unwrap().fsn,
                    if publish { 2 } else { 1 }
                );
            }
        }
    }

    #[test]
    fn recycle_slot_contender_during_every_phase() {
        use super::super::qwp_ws_sfa_queue::{RECYCLE_OBSERVER, SfaQueueError};
        let server = Server::new();
        let dir = tempfile::TempDir::new().unwrap();
        let mut sender = SenderBuilder::from_conf(format!("ws::addr=127.0.0.1:{};sf_dir={};sender_id=contender;symbol_dict_reset_threshold=1;symbol_dict_reset_max_wait_millis=0;", server.port, dir.path().display())).unwrap().build().unwrap();
        let mut buffer = sender.new_buffer();
        buffer
            .table("trades")
            .unwrap()
            .symbol("sym", "old")
            .unwrap()
            .at_now()
            .unwrap();
        sender.flush(&mut buffer).unwrap();
        sender.wait(AckLevel::Ok, Duration::from_secs(5)).unwrap();
        server.frame();
        let root = dir.path().to_path_buf();
        let probes = Arc::new(Mutex::new(Vec::new()));
        let recorded = Arc::clone(&probes);
        RECYCLE_OBSERVER.with(|observer| {
            *observer.borrow_mut() = Some(Box::new(move |phase| {
                super::tests::assert_recycle_slot_locked(&root, "contender", phase);
                recorded.lock().unwrap().push(phase);
            }))
        });
        FAIL_NEXT_RECYCLE_SPAWN.with(|fault| fault.set(true));
        buffer
            .table("trades")
            .unwrap()
            .symbol("sym", "new")
            .unwrap()
            .at_now()
            .unwrap();
        assert!(
            sender
                .flush(&mut buffer)
                .unwrap_err()
                .msg()
                .contains("spawn failure")
        );
        super::super::qwp_ws_sfa_queue::observe_recycle_phase("failed resume");
        super::super::qwp_ws_sfa_queue::observe_recycle_phase("pre-close");
        RECYCLE_OBSERVER.with(|observer| observer.borrow_mut().take());
        let probes = probes.lock().unwrap();
        assert!(probes.contains(&"accepted park"));
        assert!(probes.contains(&"reset phase"));
        assert!(
            probes.contains(&"dictionary directory synced"),
            "observed {probes:?}"
        );
        assert!(probes.contains(&"failed resume"));
        assert!(probes.contains(&"pre-close"));
        sender.close_drain().unwrap();
        drop(sender);
        let options = SfaSlotOptions {
            sf_dir: dir.path().to_path_buf(),
            sender_id: "contender".into(),
            segment_size_bytes: 4096,
            max_bytes: 32768,
            periodic_sync_interval: None,
        };
        let mut acquired = SfaSlotQueue::open(options.clone()).unwrap();
        assert!(matches!(
            SfaSlotQueue::open(options.clone()),
            Err(SfaQueueError::SlotInUse { .. })
        ));
        acquired.close().unwrap();
        drop(SfaSlotQueue::open(options).unwrap());
    }

    #[test]
    fn recycle_observation_three_epochs_retained_observers() {
        let server = Server::new();
        let mut sender = SenderBuilder::from_conf(format!("ws::addr=127.0.0.1:{};symbol_dict_reset_threshold=100000;symbol_dict_reset_max_wait_millis=0;", server.port)).unwrap().connection_listener(Arc::new(|_| {}), 0).unwrap().build().unwrap();
        let source = Arc::clone(sender.conn_events.as_ref().unwrap());
        let lifecycle = state(&mut sender).runner.lifecycle.clone();
        let shared_identity = Arc::as_ptr(&state(&mut sender).runner.shared);
        let ok_upper = Arc::clone(&state(&mut sender).runner.ok_completed_upper);
        let progress = state(&mut sender)
            .runner
            .shared
            .lock()
            .unwrap()
            .progress_view();
        let mut buffer = sender.new_buffer();
        for epoch in 0..3 {
            if epoch > 0 {
                assert!(Arc::ptr_eq(&source, sender.conn_events.as_ref().unwrap()));
                assert_eq!(lifecycle.load(), PublicationState::Open);
                let before = sender.qwp_ws_totals().unwrap();
                sender.reset_symbol_dictionary().unwrap();
                let handler = state(&mut sender);
                let mut encoder = handler.encoder.take().unwrap();
                handler
                    .before_publication(&mut encoder, true, false)
                    .unwrap();
                assert_eq!(encoder.symbol_count(), 0);
                handler.encoder = Some(encoder);
                assert_eq!(shared_identity, Arc::as_ptr(&handler.runner.shared));
                assert!(Arc::ptr_eq(&ok_upper, &handler.runner.ok_completed_upper));
                let boundary = Some(epoch * 2 - 1);
                assert_eq!(sender.published_fsn().unwrap(), boundary);
                assert_eq!(sender.acked_fsn().unwrap(), boundary);
                assert_eq!(sender.completed_fsn(AckLevel::Ok).unwrap(), boundary);
                assert_eq!(progress.completed_fsn(), boundary);
                sender.wait(AckLevel::Ok, Duration::from_millis(1)).unwrap();
                let after = sender.qwp_ws_totals().unwrap();
                assert_eq!(
                    (
                        after.frames_sent,
                        after.frames_replayed,
                        after.acks,
                        after.server_errors
                    ),
                    (
                        before.frames_sent,
                        before.frames_replayed,
                        before.acks,
                        before.server_errors
                    )
                );
            }
            for row in 0..2 {
                buffer
                    .table("trades")
                    .unwrap()
                    .symbol("sym", if row == 0 { "alpha" } else { "beta" })
                    .unwrap()
                    .at_now()
                    .unwrap();
                let boundary = epoch * 2 + row;
                assert_eq!(
                    sender.flush_and_get_fsn(&mut buffer).unwrap(),
                    Some(boundary)
                );
                sender.wait(AckLevel::Ok, Duration::from_secs(5)).unwrap();
                assert_eq!(server.frame().0, epoch as usize);
                assert_eq!(
                    progress.completed_fsn(),
                    Some(boundary),
                    "observer retained before all resets must see later targets advance"
                );
                // Queue completion can satisfy wait before the worker publishes
                // its separate OK counter. Both retained observers must advance.
                let deadline = Instant::now() + Duration::from_secs(5);
                while ok_upper.load(Ordering::Acquire) != boundary + 1 && Instant::now() < deadline
                {
                    thread::yield_now();
                }
                assert_eq!(ok_upper.load(Ordering::Acquire), boundary + 1);
                assert_eq!(
                    state(&mut sender)
                        .runner
                        .shared
                        .lock()
                        .unwrap()
                        .published_fsn(),
                    Some(boundary)
                );
            }
        }
        state(&mut sender)
            .runner
            .shared
            .lock()
            .unwrap()
            .mark_terminal(Some(crate::Error::new(
                crate::ErrorCode::SocketError,
                "terminal after completed boundary",
            )));
        assert_eq!(lifecycle.load(), PublicationState::Terminal);
        assert_eq!(
            sender
                .wait(AckLevel::Ok, Duration::from_millis(1))
                .unwrap_err()
                .msg(),
            "terminal after completed boundary"
        );
        assert_eq!(
            sender.reset_symbol_dictionary().unwrap_err().msg(),
            "terminal after completed boundary"
        );
    }

    #[test]
    fn recycle_boundary_retains_storage_and_install_phases() {
        let server = Server::new();
        let dir = tempfile::TempDir::new().unwrap();
        let mut sender = SenderBuilder::from_conf(format!("ws::addr=127.0.0.1:{};sf_dir={};sender_id=phase;symbol_dict_reset_threshold=1;symbol_dict_reset_max_wait_millis=0;", server.port, dir.path().display())).unwrap().build().unwrap();
        let mut buffer = sender.new_buffer();
        buffer
            .table("trades")
            .unwrap()
            .symbol("sym", "alpha")
            .unwrap()
            .at_now()
            .unwrap();
        sender.flush(&mut buffer).unwrap();
        sender.wait(AckLevel::Ok, Duration::from_secs(5)).unwrap();
        server.frame();
        buffer
            .table("trades")
            .unwrap()
            .symbol("sym", "beta")
            .unwrap()
            .at_now()
            .unwrap();
        super::super::qwp_ws_sfa_queue::RECYCLE_FAIL_AFTER.with(|fail| fail.set(Some(0)));
        assert!(
            sender
                .flush(&mut buffer)
                .unwrap_err()
                .msg()
                .contains("injected recycle failure")
        );
        assert!(!buffer.is_empty());
        assert!(matches!(
            state(&mut sender)
                .publication_recycle
                .as_ref()
                .unwrap()
                .phase,
            ForegroundRecyclePhase::Storage { old_count: 1 }
        ));
        assert_eq!(
            state(&mut sender).encoder.as_ref().unwrap().symbol_count(),
            1
        );
        assert!(state(&mut sender).pending_recycle_boundary().is_some());
        FAIL_NEXT_RECYCLE_SPAWN.with(|fail| fail.set(true));
        assert!(
            sender
                .flush(&mut buffer)
                .unwrap_err()
                .msg()
                .contains("spawn failure")
        );
        assert!(!buffer.is_empty());
        assert!(matches!(
            state(&mut sender)
                .publication_recycle
                .as_ref()
                .unwrap()
                .phase,
            ForegroundRecyclePhase::Installing {
                old_count: 1,
                delta_enabled: true
            }
        ));
        assert_eq!(
            state(&mut sender).encoder.as_ref().unwrap().symbol_count(),
            0
        );
        // A replacement permit must retry finish only, not repeat storage or dictionary reset.
        super::super::qwp_ws_sfa_queue::RECYCLE_FAIL_AFTER.with(|fail| fail.set(Some(0)));
        assert_eq!(sender.flush_and_get_fsn(&mut buffer).unwrap(), Some(1));
        super::super::qwp_ws_sfa_queue::RECYCLE_FAIL_AFTER
            .with(|fail| assert_eq!(fail.replace(None), Some(0)));
        sender.wait(AckLevel::Ok, Duration::from_secs(5)).unwrap();
        let (connection, beta) = server.frame();
        assert_eq!(beta[12], 0);
        buffer
            .table("trades")
            .unwrap()
            .symbol("sym", "gamma")
            .unwrap()
            .at_now()
            .unwrap();
        assert_eq!(sender.flush_and_get_fsn(&mut buffer).unwrap(), Some(2));
        sender.wait(AckLevel::Ok, Duration::from_secs(5)).unwrap();
        let (same, gamma) = server.frame();
        assert_eq!(
            same, connection,
            "the floor must use the retained pre-reset count"
        );
        assert_eq!(gamma[12], 1);
    }

    #[test]
    fn recycle_boundary_invalid_and_empty_buffer_do_not_start_maintenance() {
        let server = Server::new();
        let mut sender = SenderBuilder::from_conf(format!("ws::addr=127.0.0.1:{};symbol_dict_reset_threshold=1;symbol_dict_reset_max_wait_millis=0;", server.port)).unwrap().build().unwrap();
        let mut buffer = sender.new_buffer();
        buffer
            .table("trades")
            .unwrap()
            .symbol("sym", "alpha")
            .unwrap()
            .at_now()
            .unwrap();
        sender.flush(&mut buffer).unwrap();
        sender.wait(AckLevel::Ok, Duration::from_secs(5)).unwrap();
        server.frame();
        assert_eq!(sender.flush_and_get_fsn(&mut buffer).unwrap(), None);
        buffer
            .table("trades")
            .unwrap()
            .symbol("sym", "beta")
            .unwrap();
        assert_eq!(
            sender.flush(&mut buffer).unwrap_err().code(),
            crate::ErrorCode::InvalidApiCall
        );
        assert_eq!(
            state(&mut sender).encoder.as_ref().unwrap().symbol_count(),
            1
        );
        assert!(state(&mut sender).pending_recycle_boundary().is_none());
        assert!(
            state(&mut sender)
                .publication_recycle
                .as_ref()
                .unwrap()
                .policy
                .is_armed()
        );
    }

    #[test]
    fn recycle_boundary_dense_fallback_heals() {
        let server = Server::new();
        let dir = tempfile::TempDir::new().unwrap();
        let mut sender = SenderBuilder::from_conf(format!("ws::addr=127.0.0.1:{};sf_dir={};sender_id=heal;symbol_dict_reset_threshold=2;symbol_dict_reset_max_wait_millis=0;", server.port, dir.path().display())).unwrap().build().unwrap();
        let encoder = state(&mut sender).encoder.as_mut().unwrap();
        let mut persisted = encoder.take_persisted_dict().unwrap();
        persisted.arm_fail_next_append_cleanup();
        encoder.set_persisted_symbol_dict(Some(persisted));
        let mut buffer = sender.new_buffer();
        buffer
            .table("trades")
            .unwrap()
            .symbol("sym", "alpha")
            .unwrap()
            .at_now()
            .unwrap();
        assert!(sender.flush(&mut buffer).is_err());
        sender.flush(&mut buffer).unwrap();
        sender.wait(AckLevel::Ok, Duration::from_secs(5)).unwrap();
        let (_, dense) = server.frame();
        assert_eq!(dense[12], 0);
        assert!(
            state(&mut sender)
                .encoder
                .as_mut()
                .unwrap()
                .take_persisted_dict()
                .is_none()
        );
        buffer
            .table("trades")
            .unwrap()
            .symbol("sym", "beta")
            .unwrap()
            .at_now()
            .unwrap();
        sender.flush(&mut buffer).unwrap();
        sender.wait(AckLevel::Ok, Duration::from_secs(5)).unwrap();
        let (_, dense_second) = server.frame();
        assert_eq!(
            &dense_second[12..14],
            &[0, 2],
            "dense fallback repeats the whole dictionary"
        );
        buffer
            .table("trades")
            .unwrap()
            .symbol("sym", "gamma")
            .unwrap()
            .at_now()
            .unwrap();
        sender.flush(&mut buffer).unwrap();
        sender.wait(AckLevel::Ok, Duration::from_secs(5)).unwrap();
        let (_, healed) = server.frame();
        assert_eq!(healed[5] & 8, 8);
        assert_eq!(healed[12], 0);
        assert!(
            state(&mut sender)
                .encoder
                .as_mut()
                .unwrap()
                .take_persisted_dict()
                .is_some()
        );
    }
    #[test]
    fn recycle_boundary_io_deadline_bounds_stalled_data_and_pong() {
        use std::io::Write;
        use std::net::TcpListener;
        for pong in [false, true] {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            socket2::SockRef::from(&listener)
                .set_recv_buffer_size(1024)
                .unwrap();
            let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
            let (_peer, _) = listener.accept().unwrap();
            // Fill the real kernel send buffer while the peer never reads.
            socket2::SockRef::from(&client)
                .set_send_buffer_size(4096)
                .unwrap();
            client.set_nonblocking(true).unwrap();
            let mut stream = WsStream::Plain(NoSigpipeTcp::new(client).unwrap());
            let bytes = vec![0; 1024 * 1024];
            for _ in 0..5 {
                while stream.write(&bytes).is_ok() {}
                std::thread::sleep(Duration::from_millis(10));
            }
            while stream.write(&bytes).is_ok() {}
            while stream.write(&[0]).is_ok() {}
            stream.tcp_stream().set_nonblocking(false).unwrap();
            stream
                .set_timeouts(Some(Duration::from_secs(3)), Some(Duration::from_secs(3)))
                .unwrap();
            let started = Instant::now();
            let saved = stream
                .begin_io_deadline(started + Duration::from_millis(20))
                .unwrap();
            let mut scratch = Vec::new();
            if pong {
                let mut reader = WsFrameReader::new();
                loop {
                    reader.append_input_for_test(&[0x89, 0]);
                    if reader.try_read_one(&mut stream, &mut scratch).is_err() {
                        break;
                    }
                }
            } else {
                assert!(write_binary_frame(&mut stream, &mut scratch, &bytes).is_err());
            }
            stream.end_io_deadline(saved).unwrap();
            assert!(
                started.elapsed() < Duration::from_millis(500),
                "one recycle budget must bound control and data writes"
            );
            assert_eq!(
                stream.tcp_stream().write_timeout().unwrap(),
                Some(Duration::from_secs(3))
            );
            assert_eq!(
                stream.tcp_stream().read_timeout().unwrap(),
                Some(Duration::from_secs(3))
            );
        }
    }

    #[test]
    fn recycle_boundary_dictionary_reset_failure_resumes_after_storage() {
        let server = Server::new();
        let dir = tempfile::TempDir::new().unwrap();
        let mut sender = SenderBuilder::from_conf(format!("ws::addr=127.0.0.1:{};sf_dir={};sender_id=dictfail;symbol_dict_reset_threshold=1;symbol_dict_reset_max_wait_millis=0;", server.port, dir.path().display())).unwrap().build().unwrap();
        let mut buffer = sender.new_buffer();
        buffer
            .table("trades")
            .unwrap()
            .symbol("sym", "alpha")
            .unwrap()
            .at_now()
            .unwrap();
        sender.flush(&mut buffer).unwrap();
        sender.wait(AckLevel::Ok, Duration::from_secs(5)).unwrap();
        server.frame();
        let state = state(&mut sender);
        let slot = state
            .runner
            .lock_shared()
            .unwrap()
            .recycle_queue_mut()
            .slot_dir()
            .unwrap()
            .to_path_buf();
        drop(state.encoder.as_mut().unwrap().take_persisted_dict());
        let dictionary = slot.join(".symbol-dict");
        let retained = slot.join("old-symbols");
        std::fs::rename(&dictionary, &retained).unwrap();
        std::fs::create_dir(&dictionary).unwrap();
        buffer
            .table("trades")
            .unwrap()
            .symbol("sym", "beta")
            .unwrap()
            .at_now()
            .unwrap();
        assert!(
            sender
                .flush(&mut buffer)
                .unwrap_err()
                .msg()
                .contains("reset recycled symbol dictionary")
        );
        assert!(matches!(
            self::state(&mut sender)
                .publication_recycle
                .as_ref()
                .unwrap()
                .phase,
            ForegroundRecyclePhase::Dictionary { old_count: 1, .. }
        ));
        assert_eq!(
            self::state(&mut sender)
                .encoder
                .as_ref()
                .unwrap()
                .symbol_count(),
            1
        );
        std::fs::remove_dir(&dictionary).unwrap();
        std::fs::rename(&retained, &dictionary).unwrap();
        sender.flush(&mut buffer).unwrap();
        sender.wait(AckLevel::Ok, Duration::from_secs(5)).unwrap();
        let (_, frame) = server.frame();
        assert_eq!(&frame[12..14], &[0, 1]);
        assert_eq!(sender.published_fsn().unwrap(), Some(1));
    }

    #[test]
    fn recycle_boundary_close_preempts_drain_readiness() {
        let server = Server::new();
        let mut sender = SenderBuilder::from_conf(format!("ws::addr=127.0.0.1:{};", server.port))
            .unwrap()
            .build()
            .unwrap();
        let state = state(&mut sender);
        state.runner.begin_close();
        assert!(
            state.recycle_snapshot().is_err(),
            "a closing sender must not enter the recycle wait"
        );
    }
}
