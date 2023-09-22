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

use crate::ingress::SenderBuilder;

use core::time::Duration;
use mio::net::TcpStream;
use mio::{Events, Interest, Poll, Token};
use rustls::{
    server::{NoClientAuth, ServerConnection},
    Certificate, ServerConfig, Stream,
};
use socket2::{Domain, Protocol, Socket, Type};
use std::io::{self, BufReader, Read};
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

const CLIENT: Token = Token(0);

#[derive(Debug)]
pub struct MockServer {
    poll: Poll,
    events: Events,
    listener: Socket,
    client: Option<TcpStream>,
    tls_conn: Option<ServerConnection>,
    pub host: &'static str,
    pub port: u16,
    pub msgs: Vec<String>,
}

fn load_certs(filename: &Path) -> Vec<Certificate> {
    let certfile = std::fs::File::open(filename).expect("cannot open certificate file");
    let mut reader = BufReader::new(certfile);
    rustls_pemfile::certs(&mut reader)
        .unwrap()
        .iter()
        .map(|v| Certificate(v.clone()))
        .collect()
}

fn load_private_key(filename: &Path) -> rustls::PrivateKey {
    let keyfile = std::fs::File::open(filename).expect("cannot open private key file");
    let mut reader = BufReader::new(keyfile);

    loop {
        match rustls_pemfile::read_one(&mut reader).expect("cannot parse private key .pem file") {
            Some(rustls_pemfile::Item::RSAKey(key)) => return rustls::PrivateKey(key),
            Some(rustls_pemfile::Item::PKCS8Key(key)) => return rustls::PrivateKey(key),
            Some(rustls_pemfile::Item::ECKey(key)) => return rustls::PrivateKey(key),
            None => break,
            _ => {}
        }
    }

    panic!(
        "no keys found in {:?} (encrypted keys not supported)",
        filename
    );
}

pub fn certs_dir() -> std::path::PathBuf {
    let mut certs_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    certs_dir.pop();
    certs_dir.push("tls_certs");
    certs_dir
}

fn tls_config() -> Arc<ServerConfig> {
    let certs_dir = certs_dir();
    let cert_chain = load_certs(&certs_dir.join("server.crt"));
    let key_der = load_private_key(&certs_dir.join("server.key"));
    let config = ServerConfig::builder()
        .with_safe_default_cipher_suites()
        .with_safe_default_kx_groups()
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_client_cert_verifier(NoClientAuth::boxed())
        .with_single_cert(cert_chain, key_der)
        .unwrap();
    Arc::new(config)
}

impl MockServer {
    pub fn new() -> io::Result<Self> {
        let listener = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))?;
        let address: SocketAddr = "127.0.0.1:0".parse().unwrap();
        listener.bind(&address.into())?;
        listener.listen(128)?;
        let port = listener.local_addr()?.as_socket_ipv4().unwrap().port();
        Ok(Self {
            poll: Poll::new()?,
            events: Events::with_capacity(128),
            listener,
            client: None,
            tls_conn: None,
            host: "localhost",
            port,
            msgs: Vec::new(),
        })
    }

    pub fn accept(&mut self) -> io::Result<()> {
        let (client, _) = self.listener.accept()?;
        client.set_nonblocking(true)?;
        let client: std::net::TcpStream = client.into();
        let mut client = TcpStream::from_std(client);
        self.poll
            .registry()
            .register(&mut client, CLIENT, Interest::READABLE)?;
        self.client = Some(client);
        Ok(())
    }

    pub fn accept_tls(mut self) -> std::thread::JoinHandle<io::Result<Self>> {
        std::thread::spawn(|| {
            self.accept()?;
            let client = self.client.as_mut().unwrap();
            self.poll.registry().reregister(
                client,
                CLIENT,
                Interest::READABLE | Interest::WRITABLE,
            )?;
            let mut tls_conn = ServerConnection::new(tls_config()).unwrap();
            let mut stream = Stream::new(&mut tls_conn, client);
            let begin = std::time::Instant::now();
            while stream.conn.is_handshaking() {
                match stream.conn.complete_io(&mut stream.sock) {
                    Ok(_) => (),
                    Err(err) => {
                        if err.kind() == io::ErrorKind::WouldBlock {
                            let now = std::time::Instant::now();
                            let elapsed = now.duration_since(begin);
                            if elapsed > Duration::from_secs(2) {
                                return Err(err);
                            }
                            self.poll
                                .poll(&mut self.events, Some(Duration::from_millis(200)))?;
                        } else {
                            return Err(err);
                        }
                    }
                }
            }
            self.poll
                .registry()
                .reregister(client, CLIENT, Interest::READABLE)?;
            self.tls_conn = Some(tls_conn);
            Ok(self)
        })
    }

    pub fn wait_for_data(&mut self, wait_timeout_sec: Option<f64>) -> io::Result<bool> {
        // To ensure a clean death if accept wasn't called.
        self.client.as_ref().unwrap();
        let timeout = wait_timeout_sec.map(|sec| Duration::from_micros((sec * 1000000.0) as u64));
        self.poll.poll(&mut self.events, timeout)?;
        let ready_for_read = !self.events.is_empty();
        Ok(ready_for_read)
    }

    fn do_read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let client = self.client.as_mut().unwrap();
        if let Some(tls_conn) = self.tls_conn.as_mut() {
            let mut stream = Stream::new(tls_conn, client);
            stream.read(buf)
        } else {
            client.read(buf)
        }
    }

    pub fn recv(&mut self, wait_timeout_sec: f64) -> io::Result<usize> {
        if !self.wait_for_data(Some(wait_timeout_sec))? {
            return Ok(0);
        }

        let mut accum = Vec::<u8>::new();
        let mut chunk = [0u8; 1024];
        loop {
            let count = match self.do_read(&mut chunk[..]) {
                Ok(count) => count,
                Err(ref err) if err.kind() == io::ErrorKind::WouldBlock => {
                    let poll_timeout = Some(Duration::from_millis(200));
                    self.poll.poll(&mut self.events, poll_timeout)?;
                    continue;
                }
                Err(err) => return Err(err),
            };
            accum.extend(&chunk[..count]);
            if accum.len() < 2 {
                continue;
            }
            if (accum[accum.len() - 1] == b'\n') && (accum[accum.len() - 2] != b'\\') {
                break;
            }
        }

        let mut received_count = 0usize;
        let mut head = 0usize;
        for index in 1..accum.len() {
            let last = accum[index];
            let prev = accum[index - 1];
            if (last == b'\n') && (prev != b'\\') {
                let tail = index + 1;
                let msg = std::str::from_utf8(&accum[head..tail]).unwrap();
                self.msgs.push(msg.to_owned());
                head = tail;
                received_count += 1;
            }
        }
        Ok(received_count)
    }

    pub fn recv_q(&mut self) -> io::Result<usize> {
        self.recv(0.1)
    }

    pub fn lsb(&self) -> SenderBuilder {
        SenderBuilder::new(self.host, self.port)
    }
}
