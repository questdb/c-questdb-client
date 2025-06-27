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

use crate::ingress::{map_io_to_socket_err, parse_key_pair};
use rustls::{ClientConnection, StreamOwned};
use socket2::Socket;
use std::io::BufRead;
use std::io::{self, BufReader, Write as IoWrite};

#[cfg(feature = "aws-lc-crypto")]
use aws_lc_rs::rand::SystemRandom;

use crate::error;
#[cfg(feature = "ring-crypto")]
use ring::rand::SystemRandom;

pub(crate) enum SyncConnection {
    Direct(Socket),
    Tls(Box<StreamOwned<ClientConnection, Socket>>),
}

impl SyncConnection {
    fn send_key_id(&mut self, key_id: &str) -> crate::Result<()> {
        writeln!(self, "{}", key_id)
            .map_err(|io_err| map_io_to_socket_err("Failed to send key_id: ", io_err))?;
        Ok(())
    }

    fn read_challenge(&mut self) -> crate::Result<Vec<u8>> {
        let mut buf = Vec::new();
        let mut reader = BufReader::new(self);
        reader.read_until(b'\n', &mut buf).map_err(|io_err| {
            map_io_to_socket_err(
                "Failed to read authentication challenge (timed out?): ",
                io_err,
            )
        })?;
        if buf.last().copied().unwrap_or(b'\0') != b'\n' {
            return Err(if buf.is_empty() {
                error::fmt!(
                    AuthError,
                    concat!(
                        "Did not receive auth challenge. ",
                        "Is the database configured to require ",
                        "authentication?"
                    )
                )
            } else {
                error::fmt!(AuthError, "Received incomplete auth challenge: {:?}", buf)
            });
        }
        buf.pop(); // b'\n'
        Ok(buf)
    }

    pub(crate) fn authenticate(
        &mut self,
        auth: &crate::ingress::conf::EcdsaAuthParams,
    ) -> crate::Result<()> {
        use base64ct::{Base64, Encoding};

        if auth.key_id.contains('\n') {
            return Err(error::fmt!(
                AuthError,
                "Bad key id {:?}: Should not contain new-line char.",
                auth.key_id
            ));
        }
        let key_pair = parse_key_pair(auth)?;
        self.send_key_id(auth.key_id.as_str())?;
        let challenge = self.read_challenge()?;
        let rng = SystemRandom::new();
        let signature = key_pair
            .sign(&rng, &challenge[..])
            .map_err(|unspecified_err| {
                error::fmt!(AuthError, "Failed to sign challenge: {}", unspecified_err)
            })?;
        let mut encoded_sig = Base64::encode_string(signature.as_ref());
        encoded_sig.push('\n');
        let buf = encoded_sig.as_bytes();
        if let Err(io_err) = self.write_all(buf) {
            return Err(map_io_to_socket_err(
                "Could not send signed challenge: ",
                io_err,
            ));
        }
        Ok(())
    }
}

impl io::Read for SyncConnection {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Direct(sock) => sock.read(buf),
            Self::Tls(stream) => stream.read(buf),
        }
    }
}

impl IoWrite for SyncConnection {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Self::Direct(sock) => sock.write(buf),
            Self::Tls(stream) => stream.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::Direct(sock) => sock.flush(),
            Self::Tls(stream) => stream.flush(),
        }
    }
}
