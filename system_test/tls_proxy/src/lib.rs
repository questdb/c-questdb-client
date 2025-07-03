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

// See: https://zmedley.com/tcp-proxy.html
// and: https://github.com/tokio-rs/tls/blob/master/tokio-rustls/examples/server/src/main.rs

use std::fs::File;
use std::io;
use std::io::BufReader;
use std::sync::Arc;

use tokio::io as tio;
use tokio::net::TcpListener;
use tokio::net::TcpStream;
use tokio::select;
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::TlsAcceptor;
use tokio::io::{AsyncRead, AsyncWrite, AsyncReadExt, AsyncWriteExt};

fn certs_dir() -> std::path::PathBuf {
    let mut certs_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    certs_dir.push("..");
    certs_dir.push("..");
    certs_dir.push("tls_certs");
    certs_dir
}

pub fn tls_config() -> Arc<ServerConfig> {
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

async fn handle_conn(
    listener: &TcpListener,
    acceptor: &TlsAcceptor,
    dest_addr: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    eprintln!("[TLS PROXY] Waiting for a connection.");
    let (inbound_conn, _) = listener.accept().await?;
    inbound_conn.set_nodelay(true)?;
    eprintln!("[TLS PROXY] Accepted a client connection.");
    let acceptor = acceptor.clone();
    let inbound_conn = acceptor.accept(inbound_conn).await?;
    eprintln!("[TLS PROXY] Completed TLS handshake with client connection.");
    let outbound_conn = TcpStream::connect(dest_addr).await?;
    outbound_conn.set_nodelay(true)?;
    eprintln!("[TLS PROXY] Established outbound connection to {dest_addr}.");

    let (mut in_read, mut in_write) = tio::split(inbound_conn);
    let (mut out_read, mut out_write) = outbound_conn.into_split();

    let in_to_out = tokio::spawn(async move { copy_with_logging("in->out", &mut in_read, &mut out_write).await });
    let out_to_in = tokio::spawn(async move { copy_with_logging("out->in", &mut out_read, &mut in_write).await });

    select! {
        _ = in_to_out => eprintln!("[TLS PROXY] in_to_out shut down."),
        _ = out_to_in => eprintln!("[TLS PROXY] out_to_in shut down."),
    }

    Ok(())
}

async fn loop_server(
    dest_port: u16,
    listen_port_sender: tokio::sync::oneshot::Sender<u16>,
) -> anyhow::Result<()> {
    let dest_addr = format!("localhost:{dest_port}");
    eprintln!("[TLS PROXY] Destination address is {}.", &dest_addr);

    let config = tls_config();
    let acceptor = TlsAcceptor::from(config);

    let listener = TcpListener::bind("0.0.0.0:0").await?;
    let listen_port = listener.local_addr()?.port();
    eprintln!("[TLS PROXY] TLS Proxy is listening on localhost:{listen_port}.");
    listen_port_sender.send(listen_port).unwrap();

    loop {
        if let Err(err) = handle_conn(&listener, &acceptor, &dest_addr).await {
            eprintln!("[TLS PROXY] Error handling connection: {err}");
        }
    }
}

fn recv_port(port_receiver: &mut tokio::sync::oneshot::Receiver<u16>) -> anyhow::Result<u16> {
    loop {
        match port_receiver.try_recv() {
            Ok(port) => return Ok(port),
            Err(tokio::sync::oneshot::error::TryRecvError::Empty) => {
                std::thread::sleep(std::time::Duration::from_millis(100))
            }
            Err(tokio::sync::oneshot::error::TryRecvError::Closed) => {
                return Err(anyhow::anyhow!("Could not obtain listening port"))
            }
        }
    }
}

pub struct TlsProxy {
    _runtime: tokio::runtime::Runtime,
    loop_handle: Option<tokio::task::JoinHandle<anyhow::Result<()>>>,
    dest_port: u16,
    listen_port: u16,
}

impl TlsProxy {
    pub fn new(dest_port: u16) -> anyhow::Result<Self> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        let (port_sender, mut port_receiver) = tokio::sync::oneshot::channel();
        let loop_handle =
            Some(runtime.spawn(async move { loop_server(dest_port, port_sender).await }));
        let listen_port = recv_port(&mut port_receiver)?;
        Ok(Self {
            _runtime: runtime,
            loop_handle,
            dest_port,
            listen_port,
        })
    }

    pub fn run_indefinitely(mut self) -> anyhow::Result<()> {
        if self.loop_handle.is_none() {
            return Err(anyhow::anyhow!("TlsProxy already stopped"));
        }
        let loop_handle = self.loop_handle.take().unwrap();
        futures::executor::block_on(async { loop_handle.await? })
    }

    pub fn dest_port(&self) -> u16 {
        self.dest_port
    }

    pub fn listen_port(&mut self) -> u16 {
        self.listen_port
    }
}

impl Drop for TlsProxy {
    fn drop(&mut self) {
        if self.loop_handle.is_none() {
            return;
        }
        futures::executor::block_on(async {
            self.loop_handle.take().unwrap().abort();
        });
    }
}

struct DebugBytes<'a>(pub &'a [u8]);

impl<'a> std::fmt::Debug for DebugBytes<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "b\"")?;

        for &byte in self.0 {
            match byte {
                // Printable ASCII characters (except backslash and quote)
                0x20..=0x21 | 0x23..=0x5B | 0x5D..=0x7E => {
                    write!(f, "{}", byte as char)?;
                }
                // Common escape sequences
                b'\n' => write!(f, "\\n")?,
                b'\r' => write!(f, "\\r")?,
                b'\t' => write!(f, "\\t")?,
                b'\\' => write!(f, "\\\\")?,
                b'"' => write!(f, "\\\"")?,
                b'\0' => write!(f, "\\0")?,
                // Non-printable bytes as hex escapes
                _ => write!(f, "\\x{byte:02x}")?,
            }
        }

        write!(f, "\"")
    }
}

pub async fn copy_with_logging<R, W>(descr: &str, reader: &mut R, writer: &mut W) -> io::Result<u64>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = [0u8; 8192]; // 8KB buffer
    let mut total_copied = 0u64;

    loop {
        let n = reader.read(&mut buf).await?;
        
        // If we read 0 bytes, we've reached EOF
        if n == 0 {
            break;
        }

        // Write all the data we just read
        writer.write_all(&buf[..n]).await?;
        writer.flush().await?;

        eprintln!("[TLS PROXY:{}] Sent {} bytes: {:?}", descr, n, &DebugBytes(&buf[..n]));

        total_copied += n as u64;
    }

    // Make sure everything is flushed
    writer.flush().await?;

    eprintln!("[TLS PROXY:{}] Send complete: {} total bytes", descr, total_copied);
    Ok(total_copied)
}
