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
use crate::ingress::tls::{configure_tls, TlsSettings};
use crate::ingress::{conf, map_io_to_socket_err, parse_key_pair, SyncProtocolHandler};
use rustls::{ClientConnection, StreamOwned};
use rustls_pki_types::ServerName;
use socket2::{Domain, Protocol as SockProtocol, SockAddr, Socket, Type};
use std::io::{self, BufReader, Write as IoWrite};
use std::io::{BufRead, ErrorKind};
use std::time::Duration;

#[cfg(feature = "aws-lc-crypto")]
use aws_lc_rs::rand::SystemRandom;

#[cfg(feature = "ring-crypto")]
use ring::rand::SystemRandom;

pub(crate) enum SyncConnection {
    Direct(Socket),
    Tls(Box<StreamOwned<ClientConnection, Socket>>),
}

impl SyncConnection {
    fn send_key_id(&mut self, key_id: &str) -> crate::Result<()> {
        writeln!(self, "{key_id}")
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

// This is important to make sure that any Windows socket is properly closed
// without dropping in-flight writes.
// We also set SO_LINGER to 120, but that is not enough apparently.
impl Drop for SyncProtocolHandler {
    fn drop(&mut self) {
        if let SyncProtocolHandler::SyncTcp(conn) = self {
            match conn {
                SyncConnection::Direct(sock) => {
                    let _ = sock.shutdown(std::net::Shutdown::Write);
                }
                SyncConnection::Tls(stream) => {
                    let _ = stream.get_ref().shutdown(std::net::Shutdown::Write);
                }
            }
        }
    }
}

pub(crate) fn connect_tcp(
    host: &str,
    port: &str,
    net_interface: Option<&str>,
    auth_timeout: Duration,
    tls_settings: Option<TlsSettings>,
    auth: &Option<conf::AuthParams>,
) -> crate::Result<SyncProtocolHandler> {
    let addr: SockAddr = gai::resolve_host_port(host, port)?;
    let mut sock = Socket::new(Domain::IPV4, Type::STREAM, Some(SockProtocol::TCP))
        .map_err(|io_err| map_io_to_socket_err("Could not open TCP socket: ", io_err))?;

    // See: https://idea.popcount.org/2014-04-03-bind-before-connect/
    // We set `SO_REUSEADDR` on the outbound socket to avoid issues where a client may exhaust
    // their interface's ports. See: https://github.com/questdb/py-questdb-client/issues/21
    sock.set_reuse_address(true)
        .map_err(|io_err| map_io_to_socket_err("Could not set SO_REUSEADDR: ", io_err))?;

    sock.set_linger(Some(Duration::from_secs(120)))
        .map_err(|io_err| map_io_to_socket_err("Could not set socket linger: ", io_err))?;
    sock.set_keepalive(true)
        .map_err(|io_err| map_io_to_socket_err("Could not set SO_KEEPALIVE: ", io_err))?;
    sock.set_nodelay(true)
        .map_err(|io_err| map_io_to_socket_err("Could not set TCP_NODELAY: ", io_err))?;
    if let Some(host) = net_interface {
        let bind_addr = gai::resolve_host(host)?;
        sock.bind(&bind_addr).map_err(|io_err| {
            map_io_to_socket_err(
                &format!("Could not bind to interface address {host:?}: "),
                io_err,
            )
        })?;
    }

    sock.connect(&addr).map_err(|io_err| {
        let host_port = format!("{host}:{port}");
        let prefix = format!("Could not connect to {host_port:?}: ");
        map_io_to_socket_err(&prefix, io_err)
    })?;

    // We read during both TLS handshake and authentication.
    // We set up a read timeout to prevent the client from "hanging"
    // should we be connecting to a server configured in a different way
    // from the client.
    sock.set_read_timeout(Some(auth_timeout))
        .map_err(|io_err| map_io_to_socket_err("Failed to set read timeout on socket: ", io_err))?;

    let mut conn = match tls_settings {
        Some(tls_settings) => {
            let tls_config = configure_tls(tls_settings)?;
            let server_name: ServerName = ServerName::try_from(host)
                .map_err(|inv_dns_err| error::fmt!(TlsError, "Bad host: {}", inv_dns_err))?
                .to_owned();
            let mut tls_conn =
                ClientConnection::new(tls_config, server_name).map_err(|rustls_err| {
                    error::fmt!(TlsError, "Could not create TLS client: {}", rustls_err)
                })?;
            while tls_conn.wants_write() || tls_conn.is_handshaking() {
                tls_conn.complete_io(&mut sock).map_err(|io_err| {
                    if (io_err.kind() == ErrorKind::TimedOut)
                        || (io_err.kind() == ErrorKind::WouldBlock)
                    {
                        error::fmt!(
                            TlsError,
                            concat!(
                                "Failed to complete TLS handshake:",
                                " Timed out waiting for server ",
                                "response after {:?}."
                            ),
                            auth_timeout
                        )
                    } else {
                        error::fmt!(TlsError, "Failed to complete TLS handshake: {}", io_err)
                    }
                })?;
            }
            SyncConnection::Tls(StreamOwned::new(tls_conn, sock).into())
        }
        None => SyncConnection::Direct(sock),
    };

    if let Some(conf::AuthParams::Ecdsa(auth)) = auth {
        conn.authenticate(auth)?;
    }

    Ok(SyncProtocolHandler::SyncTcp(conn))
}
