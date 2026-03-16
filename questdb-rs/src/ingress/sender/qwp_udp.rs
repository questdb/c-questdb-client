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
use crate::gai;
use crate::ingress::SyncProtocolHandler;
use crate::ingress::buffer::{QwpBuffer, QwpSendScratch};
use crate::ingress::conf::QwpUdpConfig;
use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};

pub(crate) struct SyncQwpUdpHandlerState {
    pub(crate) socket: UdpSocket,
    pub(crate) target_addr: SocketAddrV4,
    pub(crate) max_datagram_size: usize,
    #[allow(dead_code)]
    pub(crate) multicast_ttl: u32,
    pub(crate) scratch: QwpSendScratch,
}

fn resolve_udp_target(host: &str, port: &str) -> crate::Result<SocketAddrV4> {
    let sock_addr = gai::resolve_host_port(host, port)?;
    let addr = sock_addr.as_socket_ipv4().ok_or_else(|| {
        error::fmt!(
            CouldNotResolveAddr,
            "Could not resolve {:?}:{:?}: no IPv4 address found",
            host,
            port
        )
    })?;
    Ok(addr)
}

fn resolve_bind_addr(net_interface: &str) -> crate::Result<SocketAddrV4> {
    let sock_addr = gai::resolve_host(net_interface)?;
    let addr = sock_addr.as_socket_ipv4().ok_or_else(|| {
        error::fmt!(
            CouldNotResolveAddr,
            "Could not resolve interface address {:?}: no IPv4 address found",
            net_interface
        )
    })?;
    Ok(SocketAddrV4::new(*addr.ip(), 0))
}

pub(crate) fn connect_qwp_udp(
    host: &str,
    port: &str,
    net_interface: Option<&str>,
    qwp_udp: &QwpUdpConfig,
) -> crate::Result<SyncProtocolHandler> {
    let target_addr = resolve_udp_target(host, port)?;
    let bind_addr = match net_interface {
        Some(net_interface) => resolve_bind_addr(net_interface)?,
        None => SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0),
    };

    let socket = UdpSocket::bind(bind_addr).map_err(|io_err| {
        error::fmt!(
            SocketError,
            "Could not open UDP socket bound to {:?}: {}",
            bind_addr,
            io_err
        )
    })?;

    socket.connect(target_addr).map_err(|io_err| {
        error::fmt!(
            SocketError,
            "Could not connect UDP socket to {:?}: {}",
            target_addr,
            io_err
        )
    })?;

    socket
        .set_multicast_ttl_v4(*qwp_udp.multicast_ttl)
        .map_err(|io_err| {
            error::fmt!(
                SocketError,
                "Could not set UDP multicast TTL to {}: {}",
                *qwp_udp.multicast_ttl,
                io_err
            )
        })?;

    let max_datagram_size = *qwp_udp.max_datagram_size;

    Ok(SyncProtocolHandler::SyncQwpUdp(SyncQwpUdpHandlerState {
        socket,
        target_addr,
        max_datagram_size,
        multicast_ttl: *qwp_udp.multicast_ttl,
        scratch: QwpSendScratch::new(max_datagram_size),
    }))
}

pub(crate) fn flush_qwp_udp(
    state: &mut SyncQwpUdpHandlerState,
    buffer: &QwpBuffer,
) -> crate::Result<()> {
    let target_addr = state.target_addr;
    let max_datagram_size = state.max_datagram_size;

    buffer.flush_to_socket(
        &mut state.scratch,
        max_datagram_size,
        &mut |datagram: &[u8]| {
            let sent = state.socket.send(datagram).map_err(|io_err| {
                error::fmt!(
                    SocketError,
                    "Could not send UDP datagram to {:?}: {}",
                    target_addr,
                    io_err
                )
            })?;

            if sent != datagram.len() {
                return Err(error::fmt!(
                    SocketError,
                    "Could not send complete UDP datagram to {:?}: wrote {} of {} bytes",
                    target_addr,
                    sent,
                    datagram.len()
                ));
            }

            Ok(())
        },
    )
}
