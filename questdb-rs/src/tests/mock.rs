/*******************************************************************************
 *     ___                  _   ____  ____
 *    / _ \ _   _  ___  ___| |_|  _ \| __ )
 *   | | | | | | |/ _ \/ __| __| | | |  _ \
 *   | |_| | |_| |  __/\__ \ |_| |_| | |_) |
 *    \__\_\\__,_|\___||___/\__|____/|____/
 *
 *  Copyright (c) 2014-2019 Appsicle
 *  Copyright (c) 2019-2024 QuestDB
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
use mio::event::Event;
use mio::net::TcpStream;
use mio::{Events, Interest, Poll, Token};
use rustls::{server::ServerConnection, ServerConfig, Stream};
use socket2::{Domain, Protocol, Socket, Type};
use std::fs::File;
use std::io::{self, BufReader, Read};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

#[cfg(feature = "ilp-over-http")]
use std::io::Write;

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

pub fn certs_dir() -> std::path::PathBuf {
    let mut certs_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    certs_dir.pop();
    certs_dir.push("tls_certs");
    certs_dir
}

fn tls_config() -> Arc<ServerConfig> {
    let certs_dir = certs_dir();
    let mut cert_file =
        File::open(certs_dir.join("server.crt")).expect("cannot open certificate file");
    let mut private_key_file =
        File::open(certs_dir.join("server.key")).expect("cannot open private key file");
    let certs = rustls_pemfile::certs(&mut BufReader::new(&mut cert_file))
        .collect::<Result<Vec<_>, _>>()
        .expect("cannot read certificate file");
    let private_key = rustls_pemfile::private_key(&mut BufReader::new(&mut private_key_file))
        .expect("cannot read private key file")
        .expect("no private key found");
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, private_key)
        .unwrap();
    Arc::new(config)
}

#[cfg(feature = "ilp-over-http")]
pub struct HttpRequest {
    method: String,
    path: String,
    headers: std::collections::HashMap<String, String>,
    body: Vec<u8>,
}

#[cfg(feature = "ilp-over-http")]
impl HttpRequest {
    pub fn method(&self) -> &str {
        &self.method
    }

    pub fn path(&self) -> &str {
        &self.path
    }

    pub fn header(&self, key: &str) -> Option<&str> {
        self.headers.get(key).map(|s| s.as_str())
    }

    pub fn body(&self) -> &[u8] {
        &self.body
    }

    pub fn body_str(&self) -> Result<&str, std::str::Utf8Error> {
        std::str::from_utf8(self.body())
    }
}

#[cfg(feature = "ilp-over-http")]
pub struct HttpResponse {
    status_code: u16,
    status_text: String,
    headers: std::collections::HashMap<String, String>,
    body: Vec<u8>,
}

#[cfg(feature = "ilp-over-http")]
impl HttpResponse {
    pub fn empty() -> Self {
        HttpResponse {
            status_code: 204,
            status_text: "No Content".to_string(),
            headers: std::collections::HashMap::new(),
            body: Vec::new(),
        }
    }

    pub fn with_status(mut self, code: u16, text: &str) -> Self {
        self.status_code = code;
        self.status_text = text.to_string();
        self
    }

    pub fn with_header(mut self, key: &str, value: &str) -> Self {
        self.headers.insert(key.to_string(), value.to_string());
        self
    }

    pub fn with_body(mut self, body: &[u8]) -> Self {
        self.body = body.to_vec();
        if self.status_code == 204 {
            self.status_code = 200;
            self.status_text = "OK".to_string();
        }
        if !self.headers.contains_key("content-length") {
            self.headers
                .insert("content-length".to_string(), self.body.len().to_string());
        }
        self
    }

    pub fn with_body_str(mut self, body: &str) -> Self {
        if !self.headers.contains_key("content-type") {
            self.headers
                .insert("content-type".to_string(), "text/plain".to_string());
        }
        self.with_body(body.as_bytes())
    }

    pub fn with_body_json(mut self, body: &serde_json::Value) -> Self {
        if !self.headers.contains_key("content-type") {
            self.headers
                .insert("content-type".to_string(), "application/json".to_string());
        }
        self.with_body_str(&body.to_string())
    }

    pub fn as_string(&self) -> String {
        let mut s = format!("HTTP/1.1 {} {}\r\n", self.status_code, self.status_text);
        for (key, value) in &self.headers {
            s.push_str(&format!("{}: {}\r\n", key, value));
        }
        s.push_str("\r\n");
        s.push_str(std::str::from_utf8(&self.body).unwrap());
        s
    }
}

#[cfg(feature = "ilp-over-http")]
fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

#[cfg(feature = "ilp-over-http")]
fn position(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
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
        self.poll.registry().register(
            &mut client,
            CLIENT,
            Interest::READABLE | Interest::WRITABLE,
        )?;
        self.client = Some(client);
        Ok(())
    }

    pub fn accept_tls_sync(&mut self) -> io::Result<()> {
        self.accept()?;
        let client = self.client.as_mut().unwrap();
        let mut tls_conn = ServerConnection::new(tls_config()).unwrap();
        let mut stream = Stream::new(&mut tls_conn, client);
        let begin = Instant::now();
        while stream.conn.is_handshaking() {
            match stream.conn.complete_io(&mut stream.sock) {
                Ok(_) => (),
                Err(err) => {
                    if err.kind() == io::ErrorKind::WouldBlock {
                        let now = Instant::now();
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
        self.tls_conn = Some(tls_conn);
        Ok(())
    }

    pub fn accept_tls(mut self) -> std::thread::JoinHandle<io::Result<Self>> {
        std::thread::spawn(|| {
            self.accept_tls_sync()?;
            Ok(self)
        })
    }

    fn wait_for<P>(&mut self, timeout: Option<Duration>, event_predicate: P) -> io::Result<bool>
    where
        P: Fn(&Event) -> bool,
    {
        // To ensure a clean death if accept wasn't called.
        self.client.as_ref().unwrap();
        let deadline = timeout.map(|d| Instant::now() + d);
        loop {
            let timeout = match deadline {
                Some(deadline) => {
                    let timeout = deadline.checked_duration_since(Instant::now());
                    if timeout.is_none() {
                        return Ok(false); // timed out
                    }
                    timeout
                }
                None => None,
            };
            self.poll.poll(&mut self.events, timeout)?;
            if self.events.iter().any(&event_predicate) {
                return Ok(true); // evt matched
            }
        }
    }

    pub fn wait_for_recv(&mut self, timeout: Option<Duration>) -> io::Result<bool> {
        self.wait_for(timeout, |event| event.is_readable())
    }

    #[cfg(feature = "ilp-over-http")]
    pub fn wait_for_send(&mut self, duration: Option<Duration>) -> io::Result<bool> {
        self.wait_for(duration, |event| event.is_writable())
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

    #[cfg(feature = "ilp-over-http")]
    fn do_write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let client = self.client.as_mut().unwrap();
        if let Some(tls_conn) = self.tls_conn.as_mut() {
            let mut stream = Stream::new(tls_conn, client);
            stream.write(buf)
        } else {
            client.write(buf)
        }
    }

    #[cfg(feature = "ilp-over-http")]
    fn do_write_all(&mut self, buf: &[u8], timeout_sec: Option<f64>) -> io::Result<()> {
        let deadline = timeout_sec.map(|sec| Instant::now() + Duration::from_secs_f64(sec));
        let mut pos = 0usize;
        loop {
            // `self.poll` is edge-triggered, so we need to write first
            // until we get an EAGAIN, then wait for the socket to become writable again.
            match self.do_write(&buf[pos..]) {
                Ok(count) => pos += count,
                Err(ref err) if err.kind() == io::ErrorKind::WouldBlock => (),
                Err(err) => return Err(err),
            }

            if pos == buf.len() {
                break;
            }

            let timeout = match deadline {
                Some(deadline) => Some(
                    deadline
                        .checked_duration_since(Instant::now())
                        .ok_or_else(|| {
                            io::Error::new(
                                io::ErrorKind::TimedOut,
                                "Timed out while waiting for send",
                            )
                        })?,
                ),
                None => None,
            };
            let _ = !self.wait_for_send(timeout)?;
        }
        Ok(())
    }

    #[cfg(feature = "ilp-over-http")]
    fn read_more(&mut self, accum: &mut Vec<u8>, deadline: Instant, stage: &str) -> io::Result<()> {
        let mut chunk = [0u8; 1024];
        let count = match self.do_read(&mut chunk[..]) {
            Ok(count) => count,
            Err(ref err) if err.kind() == io::ErrorKind::WouldBlock => {
                let timeout = match deadline.checked_duration_since(Instant::now()) {
                    Some(timeout) => timeout,
                    None => {
                        let mut so_far = String::new();
                        for &b in accum.iter() {
                            let part: Vec<u8> = std::ascii::escape_default(b).collect();
                            so_far.push_str(std::str::from_utf8(&part).unwrap());
                        }
                        return Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            format!(
                                "{} timed out while waiting for data. Received so far: {}",
                                stage, so_far
                            ),
                        ));
                    }
                };
                if self.wait_for_recv(Some(timeout))? {
                    // After blocking on poll, we've received a READABLE event.
                    // So we try again.
                    self.do_read(&mut chunk[..])?
                } else {
                    return Ok(()); // No more data
                }
            }
            Err(err) => return Err(err),
        };
        accum.extend(&chunk[..count]);

        Ok(())
    }

    #[cfg(feature = "ilp-over-http")]
    fn recv_http_method(
        &mut self,
        accum: &mut Vec<u8>,
        deadline: Instant,
    ) -> io::Result<(usize, String, String)> {
        let end_of_line_separator = b"\r\n";
        while !contains(&accum[..], end_of_line_separator) {
            self.read_more(accum, deadline, "Reading HTTP method line")?;
        }
        let end_of_line = position(&accum[..], b"\r\n").unwrap();
        let line = std::str::from_utf8(&accum[..end_of_line]).unwrap();
        let mut parts = line.splitn(3, ' ');
        let mut method = parts
            .next()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Missing HTTP method"))?
            .to_string();
        method.make_ascii_uppercase(); // case-insensitive method names
        let path = parts
            .next()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Missing HTTP path"))?
            .to_string();
        let _http_version = parts
            .next()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Missing HTTP version"))?;
        let body_start = end_of_line + end_of_line_separator.len();
        Ok((body_start, method, path))
    }

    #[cfg(feature = "ilp-over-http")]
    fn recv_http_headers(
        &mut self,
        pos: usize,
        accum: &mut Vec<u8>,
        deadline: Instant,
    ) -> io::Result<(usize, std::collections::HashMap<String, String>)> {
        let mut headers = std::collections::HashMap::<String, String>::new();

        let header_section_sep = b"\r\n\r\n";
        while !contains(&accum[pos..], header_section_sep) {
            self.read_more(accum, deadline, "Reading HTTP headers")?;
        }

        // The parseable headers are all the lines up to the first double newline
        let end_of_headers_pos = pos + position(&accum[pos..], header_section_sep).unwrap();
        let parseable = std::str::from_utf8(&accum[pos..end_of_headers_pos]).unwrap();
        for line in parseable.lines() {
            let mut parts = line.splitn(2, ": ");
            let mut key = parts.next().unwrap().to_string();
            key.make_ascii_lowercase(); // case-insensitive header keys
            let value = parts.next().unwrap().trim().to_string();
            headers.insert(key, value);
        }

        let body_start = end_of_headers_pos + header_section_sep.len();
        Ok((body_start, headers))
    }

    #[cfg(feature = "ilp-over-http")]
    pub fn send_http_response(
        &mut self,
        response: HttpResponse,
        timeout_sec: Option<f64>,
    ) -> io::Result<()> {
        self.do_write_all(response.as_string().as_bytes(), timeout_sec)?;
        Ok(())
    }

    #[cfg(feature = "ilp-over-http")]
    pub fn send_http_response_q(&mut self, response: HttpResponse) -> io::Result<()> {
        self.send_http_response(response, Some(5.0))
    }

    #[cfg(feature = "ilp-over-http")]
    pub fn recv_http(&mut self, wait_timeout_sec: f64) -> io::Result<HttpRequest> {
        let mut accum = Vec::<u8>::new();
        let deadline = Instant::now() + Duration::from_secs_f64(wait_timeout_sec);
        let (pos, method, path) = self.recv_http_method(&mut accum, deadline)?;
        let (pos, headers) = self.recv_http_headers(pos, &mut accum, deadline)?;
        let content_length = headers
            .get("content-length")
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Missing Content-Length"))?
            .parse::<usize>()
            .map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "Invalid Content-Length header")
            })?;
        while accum.len() < pos + content_length {
            self.read_more(&mut accum, deadline, "Reading HTTP body")?;
        }
        let body = accum[pos..(pos + content_length)].to_vec();
        Ok(HttpRequest {
            method,
            path,
            headers,
            body,
        })
    }

    #[cfg(feature = "ilp-over-http")]
    pub fn recv_http_q(&mut self) -> io::Result<HttpRequest> {
        self.recv_http(5.0)
    }

    pub fn recv(&mut self, wait_timeout_sec: f64) -> io::Result<usize> {
        let deadline = Instant::now() + Duration::from_secs_f64(wait_timeout_sec);

        let mut accum = Vec::<u8>::new();
        let mut chunk = [0u8; 1024];
        loop {
            let count = match self.do_read(&mut chunk[..]) {
                Ok(count) => count,
                Err(ref err) if err.kind() == io::ErrorKind::WouldBlock => {
                    let poll_timeout = match deadline.checked_duration_since(Instant::now()) {
                        Some(remain) => remain,
                        None => break,
                    };
                    if !self.wait_for_recv(Some(poll_timeout))? {
                        // Timed out waiting for data.
                        break;
                    }
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

    pub fn lsb(&self) -> crate::error::Result<SenderBuilder> {
        SenderBuilder::new(self.host, self.port)
    }
}
