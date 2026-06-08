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

//! `TcpStream` newtype whose `write` calls cannot raise SIGPIPE.
//!
//! Background. `Cursor::Drop` on the egress reader emits a 9-byte
//! `CANCEL` frame and then a 4-byte `Close` frame on the same socket
//! (see [`crate::egress::reader::Cursor`] → [`super::super::transport::WsTransport::try_write_cancel`]
//! → [`super::super::transport::WsTransport::close_in_place`]). If the
//! peer has gone away between the two writes, Linux consumes `sk_err`
//! on the first `write(2)` (which returns `ECONNRESET`) and raises
//! `SIGPIPE` on the second — the clean-`sk_err`/`sk_shutdown` path in
//! `tcp_sendmsg`. macOS surfaces the closed state on the very first
//! send, so even a single teardown write would `SIGPIPE`. The same
//! shape recurs on the failover replay path (re-issued `QUERY_REQUEST`
//! followed by `CREDIT` frames on a freshly-opened-but-then-dead
//! socket).
//!
//! Pure-Rust binaries are shielded by `std`'s startup `SIG_IGN`, but
//! the FFI (`questdb-rs-ffi`, exposed as `line_reader_*`) is a `cdylib`
//! — that `SIG_IGN` is not installed when the library is loaded into a
//! C/Python/etc. host. Python keeps `SIGPIPE` at `SIG_DFL`; a plain C
//! program typically also leaves it default. Either would be killed.
//!
//! The C++ mock server has the same shape and the same fix already
//! lives there — see commit `7239e5d` (`QWP_MSG_NOSIGNAL` + the
//! `set_no_sigpipe` helper in `cpp_test/qwp_mock_server.cpp`). This
//! module mirrors that pattern for the Rust client:
//!
//! - **Linux / Android**: route every `write` through `send(2)` with
//!   `MSG_NOSIGNAL`. Linux has no per-socket SIGPIPE switch, so the
//!   flag must travel on every send.
//! - **macOS / iOS / *BSD**: set `SO_NOSIGPIPE` once at construction;
//!   subsequent `write`s go through `TcpStream::write` unchanged. The
//!   option lives on the kernel socket, so `try_clone`-derived fds
//!   inherit it without a second `setsockopt`.
//! - **Windows / other**: pass-through. `WSASend` cannot raise
//!   `SIGPIPE`; the signal does not exist.

use std::io;
#[cfg(feature = "_egress")]
use std::io::{Read, Write};
use std::net::TcpStream;

#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "tvos",
    target_os = "watchos",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly",
    all(feature = "_egress", any(target_os = "linux", target_os = "android")),
))]
use std::os::fd::AsRawFd;

/// [`TcpStream`] wrapper that suppresses `SIGPIPE` on writes to a
/// closed peer. See the module-level docs for the platform breakdown.
/// Apply `setsockopt(SO_NOSIGPIPE)` on platforms that have a per-socket
/// switch (macOS / iOS / *BSD). No-op elsewhere. The kernel-socket option
/// carries across `TcpStream::try_clone`, so it is applied exactly once
/// per native socket.
pub(crate) fn apply_so_nosigpipe(_tcp: &TcpStream) -> io::Result<()> {
    #[cfg(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "tvos",
        target_os = "watchos",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly",
    ))]
    {
        let enable: libc::c_int = 1;
        let ret = unsafe {
            libc::setsockopt(
                _tcp.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_NOSIGPIPE,
                &enable as *const libc::c_int as *const libc::c_void,
                std::mem::size_of_val(&enable) as libc::socklen_t,
            )
        };
        if ret != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

#[cfg(feature = "_egress")]
pub(crate) struct NoSigpipeTcp(TcpStream);

#[cfg(feature = "_egress")]
impl NoSigpipeTcp {
    /// Wrap `tcp` and apply the per-platform SIGPIPE suppression. See
    /// [`apply_so_nosigpipe`] for the option semantics.
    pub(crate) fn new(tcp: TcpStream) -> io::Result<Self> {
        apply_so_nosigpipe(&tcp)?;
        Ok(Self(tcp))
    }

    pub(crate) fn tcp(&self) -> &TcpStream {
        &self.0
    }

    pub(crate) fn tcp_mut(&mut self) -> &mut TcpStream {
        &mut self.0
    }

    pub(crate) fn try_clone(&self) -> io::Result<Self> {
        Ok(Self(self.0.try_clone()?))
    }
}

#[cfg(feature = "_egress")]
impl Read for NoSigpipeTcp {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.read(buf)
    }
}

#[cfg(feature = "_egress")]
impl Write for NoSigpipeTcp {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        // SAFETY: fd is live for the duration of the call; `buf` is a
        // valid pointer for `buf.len()` bytes of read access.
        let ret = unsafe {
            libc::send(
                self.0.as_raw_fd(),
                buf.as_ptr() as *const libc::c_void,
                buf.len(),
                libc::MSG_NOSIGNAL,
            )
        };
        if ret < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(ret as usize)
        }
    }

    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}
