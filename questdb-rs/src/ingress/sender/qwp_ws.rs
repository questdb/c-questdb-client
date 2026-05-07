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

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use rand::RngCore;

use crate::error;
use crate::ingress::SyncProtocolHandler;
use crate::ingress::buffer::QwpBuffer;
use crate::ingress::conf::{QwpWsConfig, SfDurability};
use crate::ingress::tls::{TlsSettings, configure_tls};

use super::qwp_ws_codec::{
    self as codec, MAX_INBOUND_FRAME_BYTES, WS_OPCODE_BINARY, WS_OPCODE_CLOSE,
    WS_OPCODE_CONTINUATION, WS_OPCODE_PING, WS_OPCODE_PONG, WS_OPCODE_TEXT,
};
use super::qwp_ws_driver::{
    BlockingQwpWsTransport, CloseOutcome, DriveOutcome, DriverError, ManualDriverPrototype,
    ManualDriverTransport, PublicationLifecycle, PublicationLog, PublicationState,
    QwpWsPublicationStore, QwpWsReconnectProgress, QwpWsSendCore, QwpWsSendProgress,
    QwpWsTransportFailureAction, ReconnectPolicy, ReconnectReason, SendCursor, TransportFailure,
    TransportPoll, reconnect_error_is_terminal,
};
use super::qwp_ws_orphan::{
    ManualOrphanDrainers, OrphanDrainerConfig, OrphanDrainerPool, scan_orphan_slots,
};
use super::qwp_ws_ownership::QwpWsSenderError;
use super::qwp_ws_publisher::{QwpWsPublicationDriver, QwpWsPublicationError, QwpWsReplayEncoder};
use super::qwp_ws_queue::{
    LockFreeVolatileProducer, LockFreeVolatilePublicationLog, OutboundFrame, PendingPayload,
    QwpReceipt, QwpReceiptStatus, VolatileQueueOptions,
};
use super::qwp_ws_sfa_queue::{
    SfaCleanupFailure, SfaProducer, SfaStorageFinish, SfaStorageResult, SfaStorageStep,
};
use super::qwp_ws_sfa_slot::{SfaSlotOptions, SfaSlotQueue};

// ---------- transport ----------

type TlsStream = rustls::StreamOwned<rustls::ClientConnection, TcpStream>;

pub(crate) enum WsStream {
    Plain(TcpStream),
    Tls(Box<TlsStream>),
}

impl WsStream {
    fn set_timeouts(&self, read: Option<Duration>, write: Option<Duration>) -> std::io::Result<()> {
        let sock = match self {
            WsStream::Plain(s) => s,
            WsStream::Tls(s) => s.get_ref(),
        };
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

    fn tcp_stream(&self) -> &TcpStream {
        match self {
            WsStream::Plain(sock) => sock,
            WsStream::Tls(stream) => stream.get_ref(),
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

pub(crate) type SyncQwpWsPublisher =
    QwpWsPublicationDriver<ConfiguredQwpWsQueue, BlockingQwpWsTransport>;

pub(crate) struct SyncQwpWsHandlerState {
    encoder: QwpWsReplayEncoder,
    runner: SyncQwpWsRunner,
    orphan_pool: Option<OrphanDrainerPool>,
}

pub(crate) struct ManualQwpWsHandlerState {
    publisher: SyncQwpWsPublisher,
    orphan_drainers: Option<ManualOrphanDrainers>,
    append_deadline: Duration,
}

pub(crate) struct SyncQwpWsRunner<Q = ConfiguredQwpWsQueue> {
    shared: Arc<Mutex<QwpWsPublicationStore<Q>>>,
    producer: Option<LockFreeVolatileProducer>,
    sfa_producer: Option<SfaProducer>,
    lifecycle: PublicationLifecycle,
    backpressure: Arc<BackpressureNotifier>,
    append_deadline: Duration,
    stop: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
}

// Only the publication store is shared with producers. Transport ownership,
// cursor state, reconnect, and backoff stay in the background loop so blocking
// I/O cannot hold the publication mutex.
struct SyncQwpWsRunnerCore<T = BlockingQwpWsTransport> {
    send_core: QwpWsSendCore<T>,
    backpressure: Arc<BackpressureNotifier>,
    lifecycle: PublicationLifecycle,
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
pub(crate) const DEFAULT_CLOSE_DRAIN_TIMEOUT: Duration = Duration::from_secs(5);

impl<Q> SyncQwpWsRunner<Q>
where
    Q: PublicationLog + Send + 'static,
{
    #[cfg(test)]
    fn start<T>(publisher: QwpWsPublicationDriver<Q, T>) -> Self
    where
        T: ManualDriverTransport + Send + 'static,
    {
        Self::start_with_append_deadline(publisher, DEFAULT_APPEND_DEADLINE)
    }

    fn start_with_append_deadline<T>(
        publisher: QwpWsPublicationDriver<Q, T>,
        append_deadline: Duration,
    ) -> Self
    where
        T: ManualDriverTransport + Send + 'static,
    {
        let (mut store, send_core) = publisher.into_runner_parts();
        let lifecycle = store.lifecycle();
        let producer = store.take_lock_free_producer();
        let sfa_producer = store.take_sfa_producer();
        let shared = Arc::new(Mutex::new(store));
        let backpressure = Arc::new(BackpressureNotifier::new());
        let stop = Arc::new(AtomicBool::new(false));
        let thread_shared = Arc::clone(&shared);
        let thread_backpressure = Arc::clone(&backpressure);
        let thread_stop = Arc::clone(&stop);
        let thread_lifecycle = lifecycle.clone();
        let thread = thread::spawn(move || {
            let mut core = SyncQwpWsRunnerCore {
                send_core,
                backpressure: thread_backpressure,
                lifecycle: thread_lifecycle,
            };
            while !thread_stop.load(Ordering::Acquire) {
                match core.drive_step(&thread_shared, &thread_stop) {
                    RunnerStep::Idle => thread::sleep(Duration::from_micros(50)),
                    RunnerStep::Continue => {}
                    RunnerStep::Stop => break,
                };
            }
        });

        Self {
            shared,
            producer,
            sfa_producer,
            lifecycle,
            backpressure,
            append_deadline,
            stop,
            thread: Some(thread),
        }
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
                        let err = DriverError::Queue(err);
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
            if let Some(producer) = self.sfa_producer.as_mut() {
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
            PublicationState::Open => Ok(()),
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
        let store = self.lock_shared()?;
        check_store_error(&store)?;
        Ok(store.published_fsn())
    }

    fn acked_fsn(&self) -> crate::Result<Option<u64>> {
        let store = self.lock_shared()?;
        check_store_error(&store)?;
        Ok(store.completed_fsn())
    }

    fn poll_sender_error(&self) -> crate::Result<Option<QwpWsSenderError>> {
        let mut store = self.lock_shared()?;
        Ok(store.poll_sender_error())
    }

    fn terminal_sender_error(&self) -> crate::Result<Option<QwpWsSenderError>> {
        let store = self.lock_shared()?;
        Ok(store.terminal_sender_error().cloned())
    }

    fn sender_errors_dropped_total(&self) -> crate::Result<u64> {
        let store = self.lock_shared()?;
        Ok(store.sender_errors_dropped_total())
    }

    fn close_drain(&self, timeout: Duration) -> crate::Result<()> {
        let deadline = Instant::now().checked_add(timeout);
        self.lifecycle.begin_close();
        self.backpressure.notify_all();
        {
            let mut store = self.lock_shared()?;
            check_store_error(&store)?;
            if store.all_published_receipts_resolved() {
                store
                    .close_queue()
                    .map_err(driver_error_to_error_without_state)?;
                return Ok(());
            }
        }

        loop {
            let backpressure_generation = self.backpressure.generation();
            {
                let mut store = self.lock_shared()?;
                check_store_error(&store)?;
                if store.all_published_receipts_resolved() {
                    store
                        .close_queue()
                        .map_err(driver_error_to_error_without_state)?;
                    return Ok(());
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

impl<T> SyncQwpWsRunnerCore<T>
where
    T: ManualDriverTransport,
{
    fn drive_step<Q>(
        &mut self,
        shared: &Arc<Mutex<QwpWsPublicationStore<Q>>>,
        stop: &AtomicBool,
    ) -> RunnerStep
    where
        Q: PublicationLog,
    {
        let outbound = {
            let mut store = match shared.lock() {
                Ok(store) => store,
                Err(_) => return self.handle_poisoned_lock(),
            };
            if store.is_terminal() {
                return RunnerStep::Stop;
            }
            match self.send_core.next_outbound_frame(&mut store) {
                Ok(outbound) => outbound,
                Err(err) => return self.store_driver_error(&mut store, err),
            }
        };

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
            Ok(send_result) => {
                let mut store = match shared.lock() {
                    Ok(store) => store,
                    Err(_) => return self.handle_poisoned_lock(),
                };
                match self
                    .send_core
                    .finish_send_result(&mut store, frame, send_result)
                {
                    Ok(QwpWsSendProgress::Outcome(outcome)) => {
                        let step = step_from_drive_outcome(outcome);
                        self.backpressure.notify_all();
                        step
                    }
                    Ok(QwpWsSendProgress::TransportFailure(failure)) => {
                        drop(store);
                        self.apply_transport_failure(shared, stop, failure)
                    }
                    Err(err) => self.store_driver_error(&mut store, err),
                }
            }
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
            Ok(TransportPoll::Response(response)) => {
                let mut store = match shared.lock() {
                    Ok(store) => store,
                    Err(_) => return self.handle_poisoned_lock(),
                };
                match self.send_core.finish_response(&mut store, response) {
                    Ok(outcome) => {
                        let step = if outcome == DriveOutcome::Idle {
                            RunnerStep::Continue
                        } else {
                            step_from_drive_outcome(outcome)
                        };
                        self.backpressure.notify_all();
                        step
                    }
                    Err(err) => self.store_driver_error(&mut store, err),
                }
            }
            Ok(TransportPoll::Progress) => RunnerStep::Continue,
            Ok(TransportPoll::Idle) => RunnerStep::Idle,
            Err(failure) => self.apply_transport_failure(shared, stop, failure),
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
        let durable_ack_pending = {
            let store = match shared.lock() {
                Ok(store) => store,
                Err(_) => return self.handle_poisoned_lock(),
            };
            if store.is_terminal() {
                return RunnerStep::Stop;
            }
            store.has_pending_durable_ack()
        };
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
                return self.store_driver_error(&mut store, err.into());
            }
        };

        let (finish, terminal) = {
            let mut store = match shared.lock() {
                Ok(store) => store,
                Err(_) => return self.handle_poisoned_lock(),
            };
            match store.finish_storage_maintenance(result) {
                Ok(finish) => {
                    let terminal = store.is_terminal();
                    (finish, terminal)
                }
                Err(err) => return self.store_driver_error(&mut store, err),
            }
        };

        let changed = changed_before_io || finish.did_change();
        if changed {
            self.backpressure.notify_all();
        }
        if let Some(cleanup) = finish.into_cleanup()
            && let Some(failure) = cleanup.perform()
        {
            let mut store = match shared.lock() {
                Ok(store) => store,
                Err(_) => return self.handle_poisoned_lock(),
            };
            if let Err(err) = store.record_storage_cleanup_failure(failure) {
                return self.store_driver_error(&mut store, err);
            }
        }

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
            self.send_core.transport_failure_action(&mut store, failure)
        };
        match action {
            QwpWsTransportFailureAction::Reconnect {
                reason,
                initial_error,
            } => self.reconnect_with_policy(shared, stop, reason, initial_error),
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
    ) -> RunnerStep
    where
        Q: PublicationLog,
    {
        let reconnect_result = self.send_core.reconnect_transport_with_policy(
            reason,
            initial_error,
            || stop.load(Ordering::Acquire),
            |deadline, backoff| sleep_before_runner_reconnect(deadline, backoff, stop),
        );
        match reconnect_result {
            Ok(QwpWsReconnectProgress::Reconnected { reason }) => {
                let mut store = match shared.lock() {
                    Ok(store) => store,
                    Err(_) => return self.handle_poisoned_lock(),
                };
                let outcome = self.send_core.finish_reconnect_success(&mut store, reason);
                step_from_drive_outcome(outcome)
            }
            Ok(QwpWsReconnectProgress::Terminal(error)) => self.mark_store_terminal(shared, error),
            Ok(QwpWsReconnectProgress::Stopped) => RunnerStep::Stop,
            Err(err) => {
                let mut store = match shared.lock() {
                    Ok(store) => store,
                    Err(_) => return self.handle_poisoned_lock(),
                };
                self.store_driver_error(&mut store, err)
            }
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
    /// Reaches the same observable end-state as `mark_store_terminal` without
    /// re-entering the poisoned mutex: flips the lifecycle to `Terminal` via
    /// its own atomic, and wakes condvar waiters so any `publish_replay_payload`
    /// blocked on append-deadline backpressure observes the terminal state on
    /// its next loop iteration instead of timing out per submit. The store's
    /// `terminal_error` is left unset; publishers see a generic terminal error
    /// rather than a runner-specific one, but they fail fast.
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
        | DriveOutcome::Progress => RunnerStep::Continue,
    }
}

fn check_store_error<Q: PublicationLog>(store: &QwpWsPublicationStore<Q>) -> crate::Result<()> {
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
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

pub(crate) enum ConfiguredQwpWsQueue {
    Memory(LockFreeVolatilePublicationLog),
    StoreAndForward(Box<SfaSlotQueue>),
}

impl ConfiguredQwpWsQueue {
    fn open(qwp_ws: &QwpWsConfig) -> crate::Result<Self> {
        if *qwp_ws.sf_durability != SfDurability::Memory {
            let durability = qwp_ws.sf_durability.as_conf_value();
            return Err(error::fmt!(
                ConfigError,
                "sf_durability={durability} is not yet supported (deferred follow-up; use sf_durability=memory)"
            ));
        }

        let max_bytes = usize_from_config("sf_max_total_bytes", qwp_ws.sf_max_total_bytes())?;
        let max_in_flight = *qwp_ws.max_in_flight;

        if let Some(sf_dir) = qwp_ws.sf_dir.as_ref() {
            return Ok(Self::StoreAndForward(Box::new(
                SfaSlotQueue::open(SfaSlotOptions {
                    sf_dir: sf_dir.clone(),
                    sender_id: qwp_ws.sender_id.to_string(),
                    segment_size_bytes: *qwp_ws.sf_max_bytes,
                    max_bytes,
                    max_in_flight,
                })
                .map_err(|err| {
                    error::fmt!(
                        SocketError,
                        "Could not open QWP/WebSocket Store-and-Forward queue: {:?}",
                        err
                    )
                })?,
            )));
        }

        let max_frames = configured_max_frames(qwp_ws)?;
        Ok(Self::Memory(
            LockFreeVolatilePublicationLog::new(VolatileQueueOptions {
                max_frames,
                max_bytes,
                max_in_flight,
            })
            .map_err(|err| {
                error::fmt!(
                    ConfigError,
                    "Invalid QWP/WebSocket memory queue configuration: {:?}",
                    err
                )
            })?,
        ))
    }
}

fn configured_max_frames(qwp_ws: &QwpWsConfig) -> crate::Result<usize> {
    let max_total_bytes = qwp_ws.sf_max_total_bytes();
    let segment_bytes = (*qwp_ws.sf_max_bytes).max(1);
    let frames_by_bytes = max_total_bytes.div_ceil(segment_bytes).max(1);
    let frames = frames_by_bytes.max(*qwp_ws.max_in_flight as u64);
    usize_from_config("computed QWP/WebSocket max_frames", frames)
}

fn usize_from_config(name: &str, value: u64) -> crate::Result<usize> {
    usize::try_from(value).map_err(|_| {
        error::fmt!(
            ConfigError,
            "{name} value is too large for this platform [value={value}]"
        )
    })
}

impl PublicationLog for ConfiguredQwpWsQueue {
    fn try_publish(&mut self, payload: &[u8]) -> Result<QwpReceipt, DriverError> {
        match self {
            Self::Memory(queue) => PublicationLog::try_publish(queue, payload),
            Self::StoreAndForward(queue) => PublicationLog::try_publish(queue.as_mut(), payload),
        }
    }

    fn take_lock_free_producer(&mut self) -> Option<LockFreeVolatileProducer> {
        match self {
            Self::Memory(queue) => PublicationLog::take_lock_free_producer(queue),
            Self::StoreAndForward(queue) => PublicationLog::take_lock_free_producer(queue.as_mut()),
        }
    }

    fn take_sfa_producer(&mut self) -> Option<SfaProducer> {
        match self {
            Self::Memory(queue) => PublicationLog::take_sfa_producer(queue),
            Self::StoreAndForward(queue) => PublicationLog::take_sfa_producer(queue.as_mut()),
        }
    }

    fn next_outbound_frame(
        &mut self,
        send_cursor: &mut SendCursor,
    ) -> Result<Option<OutboundFrame>, DriverError> {
        match self {
            Self::Memory(queue) => PublicationLog::next_outbound_frame(queue, send_cursor),
            Self::StoreAndForward(queue) => {
                PublicationLog::next_outbound_frame(queue.as_mut(), send_cursor)
            }
        }
    }

    fn pending_payload_for_fsn(&self, fsn: u64) -> Result<Option<PendingPayload>, DriverError> {
        match self {
            Self::Memory(queue) => PublicationLog::pending_payload_for_fsn(queue, fsn),
            Self::StoreAndForward(queue) => {
                PublicationLog::pending_payload_for_fsn(queue.as_ref(), fsn)
            }
        }
    }

    fn restart_send_cursor(&mut self) {
        match self {
            Self::Memory(queue) => PublicationLog::restart_send_cursor(queue),
            Self::StoreAndForward(queue) => PublicationLog::restart_send_cursor(queue.as_mut()),
        }
    }

    fn take_storage_maintenance_step(
        &mut self,
        allow_create: bool,
    ) -> Result<Option<SfaStorageStep>, DriverError> {
        match self {
            Self::Memory(queue) => {
                PublicationLog::take_storage_maintenance_step(queue, allow_create)
            }
            Self::StoreAndForward(queue) => {
                PublicationLog::take_storage_maintenance_step(queue.as_mut(), allow_create)
            }
        }
    }

    fn finish_storage_maintenance(
        &mut self,
        result: SfaStorageResult,
        allow_install: bool,
    ) -> Result<SfaStorageFinish, DriverError> {
        match self {
            Self::Memory(queue) => {
                PublicationLog::finish_storage_maintenance(queue, result, allow_install)
            }
            Self::StoreAndForward(queue) => {
                PublicationLog::finish_storage_maintenance(queue.as_mut(), result, allow_install)
            }
        }
    }

    fn record_storage_cleanup_failure(
        &mut self,
        failure: SfaCleanupFailure,
    ) -> Result<(), DriverError> {
        match self {
            Self::Memory(queue) => PublicationLog::record_storage_cleanup_failure(queue, failure),
            Self::StoreAndForward(queue) => {
                PublicationLog::record_storage_cleanup_failure(queue.as_mut(), failure)
            }
        }
    }

    fn oldest_unresolved_fsn(&self) -> Option<u64> {
        match self {
            Self::Memory(queue) => PublicationLog::oldest_unresolved_fsn(queue),
            Self::StoreAndForward(queue) => PublicationLog::oldest_unresolved_fsn(queue.as_ref()),
        }
    }

    fn complete_through(&mut self, fsn: u64) -> Result<(), DriverError> {
        match self {
            Self::Memory(queue) => PublicationLog::complete_through(queue, fsn),
            Self::StoreAndForward(queue) => PublicationLog::complete_through(queue.as_mut(), fsn),
        }
    }

    fn reject_fsn(&mut self, fsn: u64) -> Result<QwpReceipt, DriverError> {
        match self {
            Self::Memory(queue) => PublicationLog::reject_fsn(queue, fsn),
            Self::StoreAndForward(queue) => PublicationLog::reject_fsn(queue.as_mut(), fsn),
        }
    }

    fn close(&mut self) -> Result<(), DriverError> {
        match self {
            Self::Memory(queue) => PublicationLog::close(queue),
            Self::StoreAndForward(queue) => Ok(queue.close()?),
        }
    }

    fn receipt_status(&self, receipt: QwpReceipt) -> QwpReceiptStatus {
        match self {
            Self::Memory(queue) => PublicationLog::receipt_status(queue, receipt),
            Self::StoreAndForward(queue) => PublicationLog::receipt_status(queue.as_ref(), receipt),
        }
    }

    fn published_fsn(&self) -> Option<u64> {
        match self {
            Self::Memory(queue) => PublicationLog::published_fsn(queue),
            Self::StoreAndForward(queue) => PublicationLog::published_fsn(queue.as_ref()),
        }
    }

    fn completed_fsn(&self) -> Option<u64> {
        match self {
            Self::Memory(queue) => PublicationLog::completed_fsn(queue),
            Self::StoreAndForward(queue) => PublicationLog::completed_fsn(queue.as_ref()),
        }
    }

    fn max_in_flight(&self) -> usize {
        match self {
            Self::Memory(queue) => PublicationLog::max_in_flight(queue),
            Self::StoreAndForward(queue) => PublicationLog::max_in_flight(queue.as_ref()),
        }
    }
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
    codec::write_frame_to_buf(out, true, WS_OPCODE_BINARY, payload, random_mask());
    stream.write_all(out)
}

pub(crate) fn write_ping_frame<W: Write>(
    stream: &mut W,
    out: &mut Vec<u8>,
    payload: &[u8],
) -> std::io::Result<()> {
    codec::write_frame_to_buf(out, true, WS_OPCODE_PING, payload, random_mask());
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
            WS_OPCODE_PING => {
                let payload = read_control_frame_payload(stream, header, &mut control_payload)?;
                codec::write_frame_to_buf(scratch, true, WS_OPCODE_PONG, payload, random_mask());
                stream.write_all(scratch).map_err(|io| {
                    WsMessageError::Error(error::fmt!(
                        SocketError,
                        "Could not send WebSocket PONG: {}",
                        io
                    ))
                })?;
                continue;
            }
            WS_OPCODE_PONG => {
                read_control_frame_payload(stream, header, &mut control_payload)?;
                continue;
            }
            WS_OPCODE_CLOSE => {
                let payload = read_control_frame_payload(stream, header, &mut control_payload)?;
                let (code, reason) = codec::ws_close_details(payload);
                return Err(WsMessageError::Close(WsCloseFrame { code, reason }));
            }
            WS_OPCODE_TEXT | WS_OPCODE_BINARY => {
                if first_opcode.is_some() {
                    return Err(WsMessageError::ProtocolViolation(
                        "Unexpected new data frame mid-message".to_string(),
                    ));
                }
                first_opcode = Some(header.opcode);
                read_payload_into(stream, out, header.payload_len)?;
            }
            WS_OPCODE_CONTINUATION => {
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
            WS_OPCODE_PING => {
                let payload = self.payload_slice(header);
                codec::write_frame_to_buf(scratch, true, WS_OPCODE_PONG, payload, random_mask());
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
            WS_OPCODE_PONG => {
                self.consume_frame(header.frame_end);
                Ok(WsFrameRead::Progress)
            }
            WS_OPCODE_CLOSE => {
                let (code, reason) = codec::ws_close_details(self.payload_slice(header));
                self.consume_frame(header.frame_end);
                Err(WsMessageError::Close(WsCloseFrame { code, reason }))
            }
            WS_OPCODE_TEXT | WS_OPCODE_BINARY => {
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
            WS_OPCODE_CONTINUATION => {
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

pub(crate) fn is_terminal_ws_close_code(code: u16) -> bool {
    matches!(code, 1002 | 1003 | 1007 | 1008 | 1009 | 1010)
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
    if !matches!(opcode, WS_OPCODE_PING | WS_OPCODE_PONG | WS_OPCODE_CLOSE) {
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
    if opcode == WS_OPCODE_CLOSE && payload_len == 1 {
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

#[allow(clippy::too_many_arguments)]
pub(crate) fn perform_upgrade<S: Read + Write>(
    stream: &mut S,
    host_header: &str,
    auth_header: Option<&str>,
    max_version: u32,
    client_id: Option<&str>,
    request_durable_ack: bool,
) -> crate::Result<(u8, Vec<u8>)> {
    // RFC 6455 only requires a 16-byte random nonce that the client base64-
    // encodes. It is not a security boundary.
    let mut key_bytes = [0u8; 16];
    rand::rng().fill_bytes(&mut key_bytes);
    let key_b64 = codec::b64_encode(&key_bytes);

    let req = codec::build_upgrade_request(
        host_header,
        &key_b64,
        auth_header,
        max_version,
        client_id,
        request_durable_ack,
    );

    stream.write_all(req.as_bytes()).map_err(|io| {
        error::fmt!(
            SocketError,
            "Could not send WebSocket upgrade request: {}",
            io
        )
    })?;

    let (header_block, leftover) = read_http_header_block(stream)?;
    let parsed = codec::parse_http_header_block(&header_block)?;
    let expected_accept = codec::compute_accept(&key_b64);
    let negotiated_version =
        codec::validate_upgrade_response(&parsed, &expected_accept, request_durable_ack)?;
    Ok((negotiated_version, leftover))
}

fn read_http_header_block<R: Read>(stream: &mut R) -> crate::Result<(Vec<u8>, Vec<u8>)> {
    let mut buf = Vec::with_capacity(1024);
    let mut tmp = [0u8; 512];
    loop {
        let n = stream
            .read(&mut tmp)
            .map_err(|io| error::fmt!(SocketError, "Could not read upgrade response: {}", io))?;
        if n == 0 {
            return Err(error::fmt!(
                SocketError,
                "Connection closed before WebSocket upgrade completed"
            ));
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(pos) = codec::find_subsequence(&buf, b"\r\n\r\n") {
            let leftover = buf.split_off(pos + 4);
            buf.truncate(pos);
            return Ok((buf, leftover));
        }
        if buf.len() > 8192 {
            return Err(error::fmt!(
                SocketError,
                "WebSocket upgrade response exceeds 8 KiB header limit"
            ));
        }
    }
}

// ---------- connect ----------

/// Establish a fresh QWP/WebSocket connection: TCP → optional TLS → HTTP
/// upgrade. Returns the connected stream, the version the server picked, and any
/// WebSocket bytes read after the HTTP upgrade response.
pub(crate) fn establish_connection(
    host: &str,
    port: &str,
    use_tls: bool,
    tls_settings: Option<TlsSettings>,
    qwp_ws: &QwpWsConfig,
    auth_header: Option<&str>,
) -> crate::Result<(WsStream, u8, Vec<u8>)> {
    use std::net::ToSocketAddrs;

    let connect_timeout = *qwp_ws.connect_timeout;
    let request_timeout = *qwp_ws.request_timeout;

    let addr = (
        host,
        port.parse::<u16>()
            .map_err(|_| error::fmt!(ConfigError, "Invalid port: {:?}", port))?,
    )
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
        .next()
        .ok_or_else(|| {
            error::fmt!(
                CouldNotResolveAddr,
                "No address found for {}:{}",
                host,
                port
            )
        })?;

    let tcp = TcpStream::connect_timeout(&addr, connect_timeout)
        .map_err(|io| error::fmt!(SocketError, "Could not connect to {}: {}", addr, io))?;
    tcp.set_nodelay(true).ok();
    tcp.set_read_timeout(Some(request_timeout)).ok();
    tcp.set_write_timeout(Some(request_timeout)).ok();

    let mut stream = if use_tls {
        let tls = tls_settings.ok_or_else(|| {
            error::fmt!(ConfigError, "TLS settings missing for QWP/WebSocket Secure")
        })?;
        let cfg: Arc<rustls::ClientConfig> = configure_tls(tls)?;
        let server_name = host
            .to_string()
            .try_into()
            .map_err(|e| error::fmt!(TlsError, "Invalid TLS server name {:?}: {}", host, e))?;
        let conn = rustls::ClientConnection::new(cfg, server_name)
            .map_err(|e| error::fmt!(TlsError, "TLS handshake setup failed: {}", e))?;
        WsStream::Tls(Box::new(rustls::StreamOwned::new(conn, tcp)))
    } else {
        WsStream::Plain(tcp)
    };

    let host_header = if (use_tls && port == "443") || (!use_tls && port == "80") {
        host.to_string()
    } else {
        format!("{host}:{port}")
    };

    let max_version = *qwp_ws.max_protocol_version;
    let client_id = qwp_ws.client_id.as_deref();
    let request_durable_ack = *qwp_ws.request_durable_ack;

    let (negotiated_version, leftover) = perform_upgrade(
        &mut stream,
        &host_header,
        auth_header,
        max_version,
        client_id,
        request_durable_ack,
    )?;

    stream
        .set_timeouts(Some(request_timeout), Some(request_timeout))
        .ok();

    Ok((stream, negotiated_version, leftover))
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
    let orphan_config = OrphanDrainerConfig::new(
        host,
        port,
        use_tls,
        tls_settings.clone(),
        qwp_ws,
        auth_header.clone(),
    );
    let publisher = open_qwp_ws_publisher(host, port, use_tls, tls_settings, qwp_ws, auth_header)?;
    let negotiated_version = publisher.version();
    let runner = SyncQwpWsRunner::start_with_append_deadline(publisher, *qwp_ws.sf_append_deadline);
    let orphan_candidates = orphan_candidates(qwp_ws);
    let orphan_pool = OrphanDrainerPool::start(
        orphan_candidates,
        *qwp_ws.max_background_drainers,
        orphan_config,
    );

    Ok(SyncProtocolHandler::SyncQwpWs(Box::new(
        SyncQwpWsHandlerState {
            encoder: QwpWsReplayEncoder::new(negotiated_version),
            runner,
            orphan_pool,
        },
    )))
}

fn orphan_candidates(qwp_ws: &QwpWsConfig) -> Vec<std::path::PathBuf> {
    if !*qwp_ws.drain_orphans {
        return Vec::new();
    }
    let Some(sf_dir) = qwp_ws.sf_dir.as_ref() else {
        return Vec::new();
    };
    scan_orphan_slots(sf_dir, qwp_ws.sender_id.as_str())
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
    let publisher = open_qwp_ws_publisher(host, port, use_tls, tls_settings, qwp_ws, auth_header)?;
    let orphan_drainers = ManualOrphanDrainers::new(
        orphan_candidates(qwp_ws),
        *qwp_ws.max_background_drainers,
        orphan_config,
    );
    Ok(ManualQwpWsHandlerState {
        publisher,
        orphan_drainers,
        append_deadline: *qwp_ws.sf_append_deadline,
    })
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn open_qwp_ws_publisher(
    host: &str,
    port: &str,
    use_tls: bool,
    tls_settings: Option<TlsSettings>,
    qwp_ws: &QwpWsConfig,
    auth_header: Option<String>,
) -> crate::Result<SyncQwpWsPublisher> {
    let queue = ConfiguredQwpWsQueue::open(qwp_ws)?;
    let transport =
        connect_blocking_transport(host, port, use_tls, tls_settings, qwp_ws, auth_header)?;
    let negotiated_version = transport.negotiated_version();
    let driver = ManualDriverPrototype::from_queue_with_reconnect_policy(
        queue,
        transport,
        ReconnectPolicy::bounded(
            *qwp_ws.reconnect_max_duration,
            *qwp_ws.reconnect_initial_backoff,
            *qwp_ws.reconnect_max_backoff,
        ),
        *qwp_ws.request_durable_ack,
    );

    Ok(QwpWsPublicationDriver::new(driver, negotiated_version))
}

fn connect_blocking_transport(
    host: &str,
    port: &str,
    use_tls: bool,
    tls_settings: Option<TlsSettings>,
    qwp_ws: &QwpWsConfig,
    auth_header: Option<String>,
) -> crate::Result<BlockingQwpWsTransport> {
    if *qwp_ws.initial_connect_retry {
        connect_blocking_transport_with_retry(
            host,
            port,
            use_tls,
            tls_settings,
            qwp_ws,
            auth_header,
        )
    } else {
        BlockingQwpWsTransport::connect(
            host,
            port,
            use_tls,
            tls_settings,
            qwp_ws.clone(),
            auth_header,
        )
    }
}

fn connect_blocking_transport_with_retry(
    host: &str,
    port: &str,
    use_tls: bool,
    tls_settings: Option<TlsSettings>,
    qwp_ws: &QwpWsConfig,
    auth_header: Option<String>,
) -> crate::Result<BlockingQwpWsTransport> {
    let deadline = Instant::now().checked_add(*qwp_ws.reconnect_max_duration);
    let mut attempts = 0usize;
    let mut backoff = *qwp_ws.reconnect_initial_backoff;
    let mut last_error = None;

    while deadline.is_none_or(|deadline| Instant::now() < deadline) {
        attempts += 1;
        match BlockingQwpWsTransport::connect(
            host,
            port,
            use_tls,
            tls_settings.clone(),
            qwp_ws.clone(),
            auth_header.clone(),
        ) {
            Ok(transport) => return Ok(transport),
            Err(err) if reconnect_error_is_terminal(&err) => return Err(err),
            Err(err) => last_error = Some(err),
        }

        let Some(deadline) = deadline else {
            thread::sleep(backoff);
            backoff = double_duration(backoff).min(*qwp_ws.reconnect_max_backoff);
            continue;
        };
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        thread::sleep(backoff.min(remaining));
        backoff = double_duration(backoff).min(*qwp_ws.reconnect_max_backoff);
    }

    Err(last_error.unwrap_or_else(|| {
        error::fmt!(
            SocketError,
            "QWP/WebSocket initial connect retry budget exhausted after {attempts} attempts"
        )
    }))
}

// ---------- send / receive ----------

/// Public flush entry point: publish through the replay queue and return once
/// the frame is locally accepted. A sender-owned runner advances WebSocket I/O.
pub(crate) fn flush_qwp_ws(
    state: &mut SyncQwpWsHandlerState,
    buffer: &QwpBuffer,
) -> crate::Result<Option<u64>> {
    let payload = state.encoder.encode(buffer)?;
    state.runner.publish_replay_payload(payload).map(Some)
}

pub(crate) fn flush_qwp_ws_manual(
    state: &mut ManualQwpWsHandlerState,
    buffer: &QwpBuffer,
) -> crate::Result<Option<u64>> {
    let receipt = state
        .publisher
        .submit_qwp_with_append_deadline(buffer, state.append_deadline)
        .map_err(|err| match err {
            QwpWsPublicationError::Encode(err) => err,
            QwpWsPublicationError::Driver(err) => driver_error_to_error(&state.publisher, err),
        })?;
    Ok(Some(receipt.fsn))
}

pub(crate) fn qwp_ws_drive_once(state: &mut ManualQwpWsHandlerState) -> crate::Result<bool> {
    let foreground_progress = match state.publisher.drive_ready_once() {
        Ok(DriveOutcome::Idle) => Ok(false),
        Ok(DriveOutcome::Terminal) => qwp_ws_manual_terminal_error(state),
        Ok(
            DriveOutcome::Sent(_)
            | DriveOutcome::Acked { .. }
            | DriveOutcome::Rejected { .. }
            | DriveOutcome::Reconnected { .. }
            | DriveOutcome::Progress,
        ) => Ok(true),
        Err(err) => Err(driver_error_to_error(&state.publisher, err)),
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

pub(crate) fn qwp_ws_published_fsn_manual(
    state: &ManualQwpWsHandlerState,
) -> crate::Result<Option<u64>> {
    check_manual_publisher_error(state)?;
    Ok(state.publisher.published_fsn())
}

pub(crate) fn qwp_ws_acked_fsn_manual(
    state: &ManualQwpWsHandlerState,
) -> crate::Result<Option<u64>> {
    check_manual_publisher_error(state)?;
    Ok(state.publisher.acked_fsn())
}

pub(crate) fn qwp_ws_check_error_background(state: &SyncQwpWsHandlerState) -> crate::Result<()> {
    state.runner.check_error()
}

pub(crate) fn qwp_ws_check_error_manual(state: &ManualQwpWsHandlerState) -> crate::Result<()> {
    check_manual_publisher_error(state)
}

pub(crate) fn qwp_ws_poll_sender_error_background(
    state: &SyncQwpWsHandlerState,
) -> crate::Result<Option<QwpWsSenderError>> {
    state.runner.poll_sender_error()
}

pub(crate) fn qwp_ws_poll_sender_error_manual(
    state: &mut ManualQwpWsHandlerState,
) -> crate::Result<Option<QwpWsSenderError>> {
    Ok(state.publisher.poll_sender_error())
}

pub(crate) fn qwp_ws_terminal_sender_error_background(
    state: &SyncQwpWsHandlerState,
) -> crate::Result<Option<QwpWsSenderError>> {
    state.runner.terminal_sender_error()
}

pub(crate) fn qwp_ws_terminal_sender_error_manual(
    state: &ManualQwpWsHandlerState,
) -> crate::Result<Option<QwpWsSenderError>> {
    Ok(state.publisher.terminal_sender_error().cloned())
}

pub(crate) fn qwp_ws_sender_errors_dropped_background(
    state: &SyncQwpWsHandlerState,
) -> crate::Result<u64> {
    state.runner.sender_errors_dropped_total()
}

pub(crate) fn qwp_ws_sender_errors_dropped_manual(
    state: &ManualQwpWsHandlerState,
) -> crate::Result<u64> {
    Ok(state.publisher.sender_errors_dropped_total())
}

pub(crate) fn qwp_ws_close_drain_background(
    state: &mut SyncQwpWsHandlerState,
) -> crate::Result<()> {
    let result = state.runner.close_drain(DEFAULT_CLOSE_DRAIN_TIMEOUT);
    if let Some(mut orphan_pool) = state.orphan_pool.take() {
        orphan_pool.close();
    }
    result
}

pub(crate) fn qwp_ws_close_drain_manual(state: &mut ManualQwpWsHandlerState) -> crate::Result<()> {
    let deadline = Instant::now().checked_add(DEFAULT_CLOSE_DRAIN_TIMEOUT);
    loop {
        match state.publisher.close_drain_ready_once() {
            Ok(CloseOutcome::Drained) => return Ok(()),
            Ok(CloseOutcome::Terminal) => return qwp_ws_manual_terminal_error(state),
            Ok(CloseOutcome::Timeout) => {
                if backpressure_deadline_expired(deadline) {
                    return Err(error::fmt!(
                        SocketError,
                        "QWP/WebSocket close drain timed out before all published frames were acknowledged"
                    ));
                }
                thread::sleep(BACKPRESSURE_PARK);
            }
            Err(err) => return Err(driver_error_to_error(&state.publisher, err)),
        }
    }
}

fn check_manual_publisher_error(state: &ManualQwpWsHandlerState) -> crate::Result<()> {
    if let Some(err) = state.publisher.terminal_error() {
        return Err(err.clone());
    }
    if state.publisher.is_terminal() {
        return Err(error::fmt!(SocketError, "QWP/WebSocket sender is terminal"));
    }
    Ok(())
}

fn qwp_ws_manual_terminal_error<T>(state: &ManualQwpWsHandlerState) -> crate::Result<T> {
    Err(state
        .publisher
        .terminal_error()
        .cloned()
        .unwrap_or_else(|| error::fmt!(SocketError, "QWP/WebSocket sender is terminal")))
}

fn double_duration(duration: Duration) -> Duration {
    duration.checked_mul(2).unwrap_or(Duration::MAX)
}

pub(crate) fn driver_error_to_error<Q, T>(
    publisher: &QwpWsPublicationDriver<Q, T>,
    err: DriverError,
) -> crate::Error
where
    Q: PublicationLog,
    T: ManualDriverTransport,
{
    match err {
        DriverError::Terminal => publisher
            .terminal_error()
            .cloned()
            .unwrap_or_else(|| error::fmt!(SocketError, "QWP/WebSocket sender is terminal")),
        err => driver_error_to_error_without_state(err),
    }
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
        DriverError, DriverEvent, FakeOrderedServer, ReconnectReason, TransportFailure,
        TransportResponse, TransportSendResult,
    };
    use super::super::qwp_ws_queue::{OutboundFrameView, SentFrame, VolatileFrameQueue};
    use super::super::qwp_ws_sfa_queue::{SfaFrameQueue, SfaQueueOptions};
    use super::*;
    use std::sync::{Arc, mpsc};
    use tempfile::TempDir;

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
    fn frame_short_payload_is_masked() {
        let mut out = Vec::new();
        let payload = b"hello";
        codec::write_frame_to_buf(&mut out, true, WS_OPCODE_BINARY, payload, [0; 4]);
        assert_eq!(out[0], 0x82); // FIN | binary
        assert_eq!(out[1] & 0x80, 0x80); // masked
        assert_eq!(out[1] & 0x7F, 5); // length
    }

    #[test]
    fn write_ping_frame_masks_client_ping() {
        let mut stream = InMemoryWs::new(Vec::new());
        let mut scratch = Vec::new();

        write_ping_frame(&mut stream, &mut scratch, b"da").unwrap();

        assert_eq!(stream.written[0], 0x80 | WS_OPCODE_PING);
        assert_eq!(stream.written[1] & 0x80, 0x80);
        assert_eq!(stream.written[1] & 0x7f, 2);
    }

    #[test]
    fn masked_server_frame_is_protocol_error() {
        let mut masked_frame = Vec::new();
        codec::write_frame_to_buf(&mut masked_frame, true, WS_OPCODE_BINARY, b"hello", [0; 4]);
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
        append_server_frame(&mut frame, true, WS_OPCODE_BINARY, b"hello");
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
        append_server_frame(&mut frame, true, WS_OPCODE_CLOSE, &[0x03]);
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
        let frame = [0x80 | WS_OPCODE_BINARY, 126, 0, 125];
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
        let mut frame = vec![0x80 | WS_OPCODE_BINARY, 127];
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
            let accept = codec::compute_accept(key);
            let mut response = format!(
                "HTTP/1.1 101 Switching Protocols\r\n\
                 Upgrade: websocket\r\n\
                 Connection: Upgrade\r\n\
                 Sec-WebSocket-Accept: {accept}\r\n\
                 X-QWP-Version: 1\r\n\
                 \r\n"
            )
            .into_bytes();
            append_server_frame(&mut response, true, WS_OPCODE_BINARY, &self.payload);
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
        let mut stream = UpgradeResponseWithFrame::new(b"\x02\x00");

        let (version, leftover) =
            perform_upgrade(&mut stream, "localhost:9000", None, 1, None, false).unwrap();

        assert_eq!(version, 1);
        let mut reader = WsFrameReader::with_initial_input(leftover);
        let mut written = Vec::new();
        let mut scratch = Vec::new();
        assert_eq!(
            reader
                .try_read_buffered_for_test(&mut written, &mut scratch)
                .unwrap(),
            WsFrameRead::Message {
                opcode: WS_OPCODE_BINARY
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
    fn read_message_preserves_fragment_across_ping() {
        let mut frames = Vec::new();
        append_server_frame(&mut frames, false, WS_OPCODE_BINARY, b"hello ");
        append_server_frame(&mut frames, true, WS_OPCODE_PING, b"p");
        append_server_frame(&mut frames, true, WS_OPCODE_CONTINUATION, b"world");
        let mut stream = InMemoryWs::new(frames);
        let mut scratch = Vec::new();
        let mut out = Vec::new();

        let opcode = read_message_with_close(&mut stream, &mut scratch, &mut out).unwrap();

        assert_eq!(opcode, WS_OPCODE_BINARY);
        assert_eq!(out, b"hello world");
        assert!(!stream.written.is_empty());
    }

    #[test]
    fn frame_reader_rejects_fragmented_message_over_aggregate_limit() {
        let mut frames = Vec::new();
        append_server_frame(&mut frames, false, WS_OPCODE_BINARY, b"abc");
        append_server_frame(&mut frames, true, WS_OPCODE_CONTINUATION, b"def");
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
        append_server_frame(&mut frames, true, WS_OPCODE_PONG, b"");
        append_server_frame(&mut frames, true, WS_OPCODE_BINARY, b"\x02\x00");
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
                opcode: WS_OPCODE_BINARY
            }
        );
        assert_eq!(reader.message(), b"\x02\x00");
    }

    #[test]
    fn frame_reader_answers_ping_and_returns_progress() {
        let mut frame = Vec::new();
        append_server_frame(&mut frame, true, WS_OPCODE_PING, b"p");
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
        assert_eq!(written[0], 0x80 | WS_OPCODE_PONG);
        assert_eq!(written[1] & 0x80, 0x80);
        assert_eq!(written[1] & 0x7f, 1);
    }

    #[test]
    fn frame_reader_preserves_incomplete_buffered_payload_until_complete() {
        let mut frame = Vec::new();
        append_server_frame(&mut frame, true, WS_OPCODE_BINARY, b"ok");
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
                opcode: WS_OPCODE_BINARY
            }
        );
        assert_eq!(reader.message(), b"ok");
    }

    #[test]
    fn frame_reader_compacts_consumed_small_frames() {
        let mut frames = Vec::new();
        for _ in 0..2500 {
            append_server_frame(&mut frames, true, WS_OPCODE_PONG, b"");
        }
        append_server_frame(&mut frames, true, WS_OPCODE_BINARY, b"done");
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
                opcode: WS_OPCODE_BINARY
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
        append_server_frame(&mut frame, true, WS_OPCODE_BINARY, b"\x00\x00");
        let mut scratch = Vec::with_capacity(64);
        let mut out = Vec::with_capacity(64);

        let mut warmup = InMemoryWs::new(frame.clone());
        assert_eq!(
            read_message_with_close(&mut warmup, &mut scratch, &mut out).unwrap(),
            WS_OPCODE_BINARY
        );
        assert_eq!(out, b"\x00\x00");

        let mut counted = InMemoryWs::new(frame);
        alloc_counter::start_counting();
        assert_eq!(
            read_message_with_close(&mut counted, &mut scratch, &mut out).unwrap(),
            WS_OPCODE_BINARY
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

    impl ManualDriverTransport for BlockingFirstSendTransport {
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

        fn sent_frames(&self) -> &[SentFrame] {
            &self.sent_frames
        }
    }

    #[test]
    fn threaded_runner_accepts_publication_while_transport_send_is_blocked() {
        let (send_started_tx, send_started_rx) = mpsc::channel();
        let (release_send_tx, release_send_rx) = mpsc::channel();
        let queue = VolatileFrameQueue::new(VolatileQueueOptions {
            max_frames: 2,
            max_bytes: 1024,
            max_in_flight: 1,
        })
        .unwrap();
        let transport = BlockingFirstSendTransport {
            send_started: send_started_tx,
            release_send: release_send_rx,
            should_block_send: true,
            sent_frames: Vec::new(),
        };
        let driver = ManualDriverPrototype::from_queue(queue, transport);
        let publisher = QwpWsPublicationDriver::new(driver, 1);
        let mut runner = SyncQwpWsRunner::start(publisher);

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

    #[test]
    fn threaded_sfa_publication_does_not_take_shared_store_mutex() {
        let dir = TempDir::new().unwrap();
        let queue = SfaFrameQueue::open(SfaQueueOptions {
            slot_dir: dir.path().to_path_buf(),
            segment_size_bytes: 4096,
            max_bytes: 8192,
            max_in_flight: 1,
        })
        .unwrap();
        let driver = ManualDriverPrototype::from_queue(queue, FakeOrderedServer::no_response());
        let publisher = QwpWsPublicationDriver::new(driver, 1);
        let mut runner =
            SyncQwpWsRunner::start_with_append_deadline(publisher, Duration::from_secs(5));
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

    #[derive(Debug)]
    struct BlockingReconnectTransport {
        send_started: mpsc::Sender<()>,
        reconnect_started: mpsc::Sender<()>,
        release_reconnect: mpsc::Receiver<()>,
        should_fail_send: bool,
        sent_frames: Vec<SentFrame>,
    }

    impl ManualDriverTransport for BlockingReconnectTransport {
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

        fn sent_frames(&self) -> &[SentFrame] {
            &self.sent_frames
        }
    }

    #[test]
    fn threaded_runner_accepts_publication_while_reconnect_is_blocked() {
        let (send_started_tx, send_started_rx) = mpsc::channel();
        let (reconnect_started_tx, reconnect_started_rx) = mpsc::channel();
        let (release_reconnect_tx, release_reconnect_rx) = mpsc::channel();
        let queue = VolatileFrameQueue::new(VolatileQueueOptions {
            max_frames: 2,
            max_bytes: 1024,
            max_in_flight: 1,
        })
        .unwrap();
        let transport = BlockingReconnectTransport {
            send_started: send_started_tx,
            reconnect_started: reconnect_started_tx,
            release_reconnect: release_reconnect_rx,
            should_fail_send: true,
            sent_frames: Vec::new(),
        };
        let driver = ManualDriverPrototype::from_queue(queue, transport);
        let publisher = QwpWsPublicationDriver::new(driver, 1);
        let mut runner = SyncQwpWsRunner::start(publisher);

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

    impl ManualDriverTransport for SignalResponseTransport {
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

        fn sent_frames(&self) -> &[SentFrame] {
            &self.sent_frames
        }
    }

    #[test]
    fn threaded_runner_waits_for_ack_when_lock_free_publication_is_backpressured() {
        let (sent_tx, sent_rx) = mpsc::channel();
        let (ack_tx, ack_rx) = mpsc::channel();
        let (_terminal_tx, terminal_rx) = mpsc::channel();
        let queue = LockFreeVolatilePublicationLog::new(VolatileQueueOptions {
            max_frames: 1,
            max_bytes: 1024,
            max_in_flight: 1,
        })
        .unwrap();
        let transport = SignalResponseTransport {
            sent_frame: sent_tx,
            ack: ack_rx,
            terminal: terminal_rx,
            sent_frames: Vec::new(),
        };
        let driver = ManualDriverPrototype::from_queue(queue, transport);
        let publisher = QwpWsPublicationDriver::new(driver, 1);
        let mut runner =
            SyncQwpWsRunner::start_with_append_deadline(publisher, Duration::from_secs(5));

        runner.publish_replay_payload(b"first").unwrap();
        assert_eq!(sent_rx.recv_timeout(Duration::from_secs(5)).unwrap().fsn, 0);

        std::thread::scope(|scope| {
            let (published_tx, published_rx) = mpsc::channel();
            let runner = &mut runner;
            let publish_thread = scope.spawn(move || {
                let result = runner.publish_replay_payload(b"second");
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
    fn threaded_runner_times_out_when_lock_free_publication_stays_backpressured() {
        let (sent_tx, sent_rx) = mpsc::channel();
        let (_ack_tx, ack_rx) = mpsc::channel();
        let (_terminal_tx, terminal_rx) = mpsc::channel();
        let queue = LockFreeVolatilePublicationLog::new(VolatileQueueOptions {
            max_frames: 1,
            max_bytes: 1024,
            max_in_flight: 1,
        })
        .unwrap();
        let transport = SignalResponseTransport {
            sent_frame: sent_tx,
            ack: ack_rx,
            terminal: terminal_rx,
            sent_frames: Vec::new(),
        };
        let driver = ManualDriverPrototype::from_queue(queue, transport);
        let publisher = QwpWsPublicationDriver::new(driver, 1);
        let mut runner =
            SyncQwpWsRunner::start_with_append_deadline(publisher, Duration::from_millis(20));

        runner.publish_replay_payload(b"first").unwrap();
        assert_eq!(sent_rx.recv_timeout(Duration::from_secs(5)).unwrap().fsn, 0);

        let err = runner.publish_replay_payload(b"second").unwrap_err();
        assert_eq!(err.code(), crate::ErrorCode::SocketError);
        assert!(
            err.msg()
                .contains("timed out waiting for local queue capacity"),
            "got: {}",
            err.msg()
        );
    }

    #[test]
    fn threaded_runner_wakes_backpressured_publication_on_terminal_error() {
        let (sent_tx, sent_rx) = mpsc::channel();
        let (_ack_tx, ack_rx) = mpsc::channel();
        let (terminal_tx, terminal_rx) = mpsc::channel();
        let queue = LockFreeVolatilePublicationLog::new(VolatileQueueOptions {
            max_frames: 1,
            max_bytes: 1024,
            max_in_flight: 1,
        })
        .unwrap();
        let transport = SignalResponseTransport {
            sent_frame: sent_tx,
            ack: ack_rx,
            terminal: terminal_rx,
            sent_frames: Vec::new(),
        };
        let driver = ManualDriverPrototype::from_queue(queue, transport);
        let publisher = QwpWsPublicationDriver::new(driver, 1);
        let mut runner =
            SyncQwpWsRunner::start_with_append_deadline(publisher, Duration::from_secs(5));

        runner.publish_replay_payload(b"first").unwrap();
        assert_eq!(sent_rx.recv_timeout(Duration::from_secs(5)).unwrap().fsn, 0);

        std::thread::scope(|scope| {
            let (published_tx, published_rx) = mpsc::channel();
            let runner = &mut runner;
            let publish_thread = scope.spawn(move || {
                let result = runner.publish_replay_payload(b"second");
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

    impl ManualDriverTransport for ImmediateFailureReconnectTransport {
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

        fn sent_frames(&self) -> &[SentFrame] {
            &self.sent_frames
        }
    }

    #[test]
    fn threaded_runner_records_immediate_transport_failure_as_sent_before_reconnect() {
        let (reconnect_started_tx, reconnect_started_rx) = mpsc::channel();
        let (release_reconnect_tx, release_reconnect_rx) = mpsc::channel();
        let queue = VolatileFrameQueue::new(VolatileQueueOptions {
            max_frames: 2,
            max_bytes: 1024,
            max_in_flight: 1,
        })
        .unwrap();
        let transport = ImmediateFailureReconnectTransport {
            reconnect_started: reconnect_started_tx,
            release_reconnect: release_reconnect_rx,
            should_fail_send: true,
            sent_frames: Vec::new(),
        };
        let driver = ManualDriverPrototype::from_queue(queue, transport);
        let publisher = QwpWsPublicationDriver::new(driver, 1);
        let mut runner = SyncQwpWsRunner::start(publisher);

        runner.publish_replay_payload(b"first").unwrap();
        reconnect_started_rx
            .recv_timeout(Duration::from_secs(5))
            .unwrap();

        let events = {
            let mut store = runner.lock_shared().unwrap();
            let mut events = Vec::new();
            while let Some(event) = store.poll_event() {
                events.push(event);
            }
            events
        };
        assert_eq!(
            events,
            vec![
                DriverEvent::Published { fsn: 0 },
                DriverEvent::Sent {
                    fsn: 0,
                    wire_seq: 0,
                },
            ]
        );

        release_reconnect_tx.send(()).unwrap();
        drop(runner);
    }
}
