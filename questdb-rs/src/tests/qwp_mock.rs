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

use crate::ingress::{Protocol, SenderBuilder};
use std::io;
use std::net::UdpSocket;
use std::time::Duration;

pub struct QwpUdpMock {
    socket: UdpSocket,
    host: &'static str,
    port: u16,
}

impl QwpUdpMock {
    pub fn new() -> io::Result<Self> {
        let socket = UdpSocket::bind("127.0.0.1:0")?;
        socket.set_read_timeout(Some(Duration::from_millis(500)))?;
        let port = socket.local_addr()?.port();
        Ok(Self {
            socket,
            host: "127.0.0.1",
            port,
        })
    }

    pub fn sender_builder(&self) -> SenderBuilder {
        SenderBuilder::new(Protocol::QwpUdp, self.host, self.port)
    }

    pub fn address(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }

    pub fn recv_datagram(&self) -> io::Result<Vec<u8>> {
        let mut buf = vec![0u8; 65_536];
        let (len, _) = self.socket.recv_from(&mut buf)?;
        buf.truncate(len);
        Ok(buf)
    }

    pub fn recv_datagrams(&self, count: usize) -> io::Result<Vec<Vec<u8>>> {
        let mut datagrams = Vec::with_capacity(count);
        for _ in 0..count {
            datagrams.push(self.recv_datagram()?);
        }
        Ok(datagrams)
    }
}
