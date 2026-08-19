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

//! Loopback port reservations shared by the unit-test suites.

use socket2::{Domain, Protocol, Socket, Type};
use std::net::{Ipv4Addr, SocketAddrV4, TcpListener};

/// A loopback TCP port held for the lifetime of the guard.
///
/// The socket is bound but never listened on, so connecting to
/// [`ReservedPort::port`] is refused exactly as it would be against a port
/// nothing owns — while the bind stops any other test in the process from
/// claiming it.
///
/// Binding a `TcpListener`, reading its port and dropping it looks
/// equivalent but is not: the kernel hands the port straight back to the
/// ephemeral range, so the next mock server that binds `127.0.0.1:0` on
/// another test thread can be given exactly that port. The test that
/// believed the port dead then dials the other test's mock server, which
/// inflates that server's accept count and makes the "dead" endpoint
/// unexpectedly alive. Under `cargo test`'s thread pool both tests are
/// running at once, so both observe the damage.
pub(crate) struct ReservedPort {
    socket: Socket,
    port: u16,
}

impl ReservedPort {
    /// Reserve an ephemeral loopback port that refuses connections.
    pub(crate) fn reserve() -> Self {
        let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))
            .expect("create reserved port socket");
        socket
            .bind(&SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0).into())
            .expect("bind reserved port socket");
        let port = socket
            .local_addr()
            .expect("reserved port local addr")
            .as_socket_ipv4()
            .expect("reserved port IPv4 addr")
            .port();
        Self { socket, port }
    }

    pub(crate) fn port(&self) -> u16 {
        self.port
    }

    /// Start accepting on the reserved port, without ever releasing it.
    ///
    /// Lets a test hold a port dead for a while and then bring a server up
    /// on that exact port, with no window where another test could take it.
    pub(crate) fn listen(self) -> TcpListener {
        self.socket.listen(128).expect("listen on reserved port");
        TcpListener::from(self.socket)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::ErrorKind;
    use std::net::{SocketAddr, TcpStream};
    use std::time::Duration;

    /// The property every "dead endpoint" test depends on: while the guard
    /// lives, nothing else in the process can put a server on that port.
    #[test]
    fn reserved_port_cannot_be_bound_by_anyone_else() {
        let reserved = ReservedPort::reserve();
        let err = TcpListener::bind(("127.0.0.1", reserved.port()))
            .expect_err("a reserved port must not be bindable while the guard lives");
        assert_eq!(err.kind(), ErrorKind::AddrInUse, "{err}");
    }

    /// The other half: a reserved port must refuse connections as promptly
    /// as an unowned one, so fail-fast tests keep measuring the client's
    /// retry policy rather than a connect timeout.
    #[test]
    fn reserved_port_refuses_connections() {
        let reserved = ReservedPort::reserve();
        let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, reserved.port()));
        let err = TcpStream::connect_timeout(&addr, Duration::from_secs(5))
            .expect_err("a reserved port must refuse connections");
        assert_eq!(err.kind(), ErrorKind::ConnectionRefused, "{err}");
    }

    /// Handing the reservation to a server keeps the port throughout: the
    /// same port that was refusing connections starts accepting them.
    #[test]
    fn reserved_port_can_be_promoted_to_a_listener() {
        let reserved = ReservedPort::reserve();
        let port = reserved.port();
        let listener = reserved.listen();
        assert_eq!(listener.local_addr().unwrap().port(), port);
        let client = TcpStream::connect(("127.0.0.1", port)).expect("connect to promoted port");
        let (accepted, _) = listener.accept().expect("accept on promoted port");
        drop(accepted);
        drop(client);
    }
}
