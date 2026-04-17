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

use crate::error;
use dns_lookup::{AddrInfo, AddrInfoHints, AddrInfoIter, LookupError};
use socket2::SockAddr;

#[cfg(unix)]
use libc::AF_INET;
#[cfg(all(unix, feature = "sync-sender-qwp-udp"))]
use libc::SOCK_DGRAM;
#[cfg(all(unix, feature = "sync-sender-tcp"))]
use libc::SOCK_STREAM;

#[cfg(windows)]
use winapi::shared::ws2def::AF_INET;
#[cfg(all(windows, feature = "sync-sender-qwp-udp"))]
use winapi::shared::ws2def::SOCK_DGRAM;
#[cfg(all(windows, feature = "sync-sender-tcp"))]
use winapi::shared::ws2def::SOCK_STREAM;

fn map_getaddrinfo_result(
    dest: &str,
    result: Result<AddrInfoIter, LookupError>,
) -> crate::Result<SockAddr> {
    match result {
        Ok(mut addrs) => map_first_addrinfo(dest, addrs.next()),
        Err(lookup_err) => {
            let io_err: std::io::Error = lookup_err.into();
            Err(error::fmt!(
                CouldNotResolveAddr,
                "Could not resolve {:?}: {}",
                dest,
                io_err
            ))
        }
    }
}

fn map_first_addrinfo(
    dest: &str,
    result: Option<std::io::Result<AddrInfo>>,
) -> crate::Result<SockAddr> {
    match result {
        Some(Ok(addr)) => Ok(addr.sockaddr.into()),
        Some(Err(io_err)) => Err(error::fmt!(
            CouldNotResolveAddr,
            "Could not resolve {:?}: {}",
            dest,
            io_err
        )),
        None => Err(error::fmt!(
            CouldNotResolveAddr,
            "Could not resolve {:?}: no addresses returned",
            dest
        )),
    }
}

#[cfg(feature = "sync-sender-tcp")]
pub(super) fn resolve_host(host: &str) -> super::Result<SockAddr> {
    resolve_host_with_socktype(host, SOCK_STREAM)
}

#[cfg(feature = "sync-sender-qwp-udp")]
pub(super) fn resolve_host_udp(host: &str) -> super::Result<SockAddr> {
    resolve_host_with_socktype(host, SOCK_DGRAM)
}

fn resolve_host_with_socktype(host: &str, socktype: i32) -> super::Result<SockAddr> {
    let hints = AddrInfoHints {
        socktype,
        address: AF_INET,
        ..AddrInfoHints::default()
    };
    map_getaddrinfo_result(host, dns_lookup::getaddrinfo(Some(host), None, Some(hints)))
}

#[cfg(feature = "sync-sender-tcp")]
pub(super) fn resolve_host_port(host: &str, port: &str) -> super::Result<SockAddr> {
    resolve_host_port_with_socktype(host, port, SOCK_STREAM)
}

#[cfg(feature = "sync-sender-qwp-udp")]
pub(super) fn resolve_host_port_udp(host: &str, port: &str) -> super::Result<SockAddr> {
    resolve_host_port_with_socktype(host, port, SOCK_DGRAM)
}

fn resolve_host_port_with_socktype(
    host: &str,
    port: &str,
    socktype: i32,
) -> super::Result<SockAddr> {
    let hints = AddrInfoHints {
        socktype,
        address: AF_INET,
        ..AddrInfoHints::default()
    };
    let host_port = format!("{host}:{port}");
    map_getaddrinfo_result(
        &host_port,
        dns_lookup::getaddrinfo(Some(host), Some(port), Some(hints)),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ErrorCode;

    #[test]
    fn empty_getaddrinfo_result_is_error() {
        let err = map_first_addrinfo("example.invalid:9009", None).unwrap_err();

        assert_eq!(err.code(), ErrorCode::CouldNotResolveAddr);
        assert!(
            err.msg()
                .contains("Could not resolve \"example.invalid:9009\": no addresses returned")
        );
    }
}
