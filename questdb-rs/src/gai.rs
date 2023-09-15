/*******************************************************************************
 *     ___                  _   ____  ____
 *    / _ \ _   _  ___  ___| |_|  _ \| __ )
 *   | | | | | | |/ _ \/ __| __| | | |  _ \
 *   | |_| | |_| |  __/\__ \ |_| |_| | |_) |
 *    \__\_\\__,_|\___||___/\__|____/|____/
 *
 *  Copyright (c) 2014-2019 Appsicle
 *  Copyright (c) 2019-2023 QuestDB
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
use libc::{AF_INET, SOCK_STREAM};

#[cfg(windows)]
use winapi::shared::ws2def::{AF_INET, SOCK_STREAM};

fn map_getaddrinfo_result(
    dest: &str,
    result: Result<AddrInfoIter, LookupError>,
) -> crate::Result<SockAddr> {
    match result {
        Ok(mut addrs) => {
            let addr: AddrInfo = addrs.next().unwrap().map_err(|io_err| {
                error::fmt!(
                    CouldNotResolveAddr,
                    "Could not resolve {:?}: {}",
                    dest,
                    io_err
                )
            })?;
            Ok(addr.sockaddr.into())
        }
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

pub(super) fn resolve_host(host: &str) -> super::Result<SockAddr> {
    let hints = AddrInfoHints {
        socktype: SOCK_STREAM,
        address: AF_INET,
        ..AddrInfoHints::default()
    };
    map_getaddrinfo_result(host, dns_lookup::getaddrinfo(Some(host), None, Some(hints)))
}

pub(super) fn resolve_host_port(host: &str, port: &str) -> super::Result<SockAddr> {
    let hints = AddrInfoHints {
        socktype: SOCK_STREAM,
        address: AF_INET,
        ..AddrInfoHints::default()
    };
    let host_port = format!("{}:{}", host, port);
    map_getaddrinfo_result(
        &host_port,
        dns_lookup::getaddrinfo(Some(host), Some(port), Some(hints)),
    )
}
