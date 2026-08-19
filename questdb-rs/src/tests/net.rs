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

//! Loopback port bookkeeping shared by the unit-test suites.
//!
//! Two things need to agree: a test that wants a *dead* endpoint, and every
//! test that opens a server socket. Without that agreement a "dead" port is
//! only dead until some other test's mock server is handed the same
//! ephemeral port and starts serving it.

use std::collections::HashSet;
use std::net::TcpListener;
use std::sync::{LazyLock, Mutex};

/// Ports currently claimed as dead endpoints. Consulted by
/// [`bind_test_listener`], populated by [`ReservedPort`].
static CLAIMED: LazyLock<Mutex<HashSet<u16>>> = LazyLock::new(|| Mutex::new(HashSet::new()));

/// How many draws to make before giving up. Each attempt holds on to its
/// listener, so the kernel cannot keep returning the same claimed port.
const MAX_DRAWS: usize = 64;

/// A loopback port claimed as a dead endpoint for the guard's lifetime.
///
/// The port is left genuinely unbound: connecting to it must be *refused*,
/// promptly, the way it is against any port nothing owns. Holding the socket
/// instead — bound but never listening — looks equivalent and is not. macOS
/// silently drops SYNs addressed to such a socket, turning a prompt refusal
/// into a connect timeout, which is a very different thing for a test that
/// measures how fast the client gives up.
///
/// So the reservation is process-wide bookkeeping rather than a kernel
/// binding: [`bind_test_listener`] will not hand out a claimed port, so no
/// mock server can end up serving an endpoint another test believes is dead.
/// Simply reading a port off a `TcpListener` and dropping it — the obvious
/// thing, and what this replaces — offers no such protection: the kernel
/// returns the port to the ephemeral range immediately, and under `cargo
/// test`'s thread pool the next server to bind `127.0.0.1:0` can be given
/// exactly that port while the first test is still dialing it.
pub(crate) struct ReservedPort {
    port: u16,
}

impl ReservedPort {
    /// Claim a loopback port that nothing is listening on.
    pub(crate) fn reserve() -> Self {
        let mut rejected = Vec::new();
        for _ in 0..MAX_DRAWS {
            let listener = TcpListener::bind("127.0.0.1:0").expect("bind to draw a dead port");
            let port = listener.local_addr().expect("dead port local addr").port();
            if CLAIMED.lock().unwrap().insert(port) {
                // Claim first, release second: from here on no test server
                // can take the port, and the endpoint is dead.
                drop(listener);
                return Self { port };
            }
            rejected.push(listener);
        }
        panic!("no unclaimed loopback port in {MAX_DRAWS} draws");
    }

    pub(crate) fn port(&self) -> u16 {
        self.port
    }
}

impl Drop for ReservedPort {
    fn drop(&mut self) {
        CLAIMED.lock().unwrap().remove(&self.port);
    }
}

/// Bind a loopback listener on a port no test has claimed as dead.
///
/// Every test server in this crate goes through here; that is what makes a
/// [`ReservedPort`] claim mean anything.
pub(crate) fn bind_test_listener() -> TcpListener {
    let mut rejected = Vec::new();
    for _ in 0..MAX_DRAWS {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test listener");
        let port = listener
            .local_addr()
            .expect("test listener local addr")
            .port();
        if !CLAIMED.lock().unwrap().contains(&port) {
            return listener;
        }
        rejected.push(listener);
    }
    panic!("no unclaimed loopback port in {MAX_DRAWS} draws");
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::ErrorKind;
    use std::net::{Ipv4Addr, SocketAddr, TcpStream};
    use std::time::{Duration, Instant};

    /// The property every dead-endpoint test measures against: connecting is
    /// refused, and refused *promptly*. A reservation that held the socket
    /// would black-hole the SYN on macOS and this would time out instead.
    #[test]
    fn reserved_port_refuses_connections_promptly() {
        let reserved = ReservedPort::reserve();
        let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, reserved.port()));
        let start = Instant::now();
        let err = TcpStream::connect_timeout(&addr, Duration::from_secs(5))
            .expect_err("a reserved port must refuse connections");
        assert_eq!(err.kind(), ErrorKind::ConnectionRefused, "{err}");
        assert!(
            start.elapsed() < Duration::from_secs(1),
            "refusal took {:?}",
            start.elapsed()
        );
    }

    /// The other half: while the claim stands, no test server can be handed
    /// that port, so nothing can start serving the dead endpoint.
    #[test]
    fn claimed_ports_are_never_handed_to_a_test_listener() {
        let reserved = ReservedPort::reserve();
        assert!(CLAIMED.lock().unwrap().contains(&reserved.port()));
        for _ in 0..64 {
            let listener = bind_test_listener();
            assert_ne!(listener.local_addr().unwrap().port(), reserved.port());
        }
    }

    /// And the claim is not a leak: the port returns to general use.
    #[test]
    fn dropping_the_guard_releases_the_claim() {
        let port = {
            let reserved = ReservedPort::reserve();
            reserved.port()
        };
        assert!(!CLAIMED.lock().unwrap().contains(&port));
    }
}
