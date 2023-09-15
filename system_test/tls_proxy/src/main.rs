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

// See: https://zmedley.com/tcp-proxy.html
// and: https://github.com/tokio-rs/tls/blob/master/tokio-rustls/examples/server/src/main.rs

use std::io::BufReader;
use std::path::Path;
use std::sync::Arc;

use argh::FromArgs;
use tokio::io as tio;
use tokio::net::TcpListener;
use tokio::net::TcpStream;
use tokio::select;
use tokio_rustls::rustls::{self, server::NoClientAuth, Certificate, ServerConfig};
use tokio_rustls::TlsAcceptor;

/// Options for TLS localhost proxy
#[derive(FromArgs)]
struct Options {
    /// TCP destination port to connect to on localhost.
    #[argh(positional)]
    port: u16,
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

fn certs_dir() -> std::path::PathBuf {
    let mut certs_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    certs_dir.push("..");
    certs_dir.push("..");
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

async fn handle_conn(
    listener: &TcpListener,
    acceptor: &TlsAcceptor,
    dest_addr: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    eprintln!("Waiting for a connection.");
    let (inbound_conn, _) = listener.accept().await?;
    eprintln!("Accepted a client connection.");
    let acceptor = acceptor.clone();
    let inbound_conn = acceptor.accept(inbound_conn).await?;
    eprintln!("Completed TLS handshake with client connection.");
    let outbound_conn = TcpStream::connect(dest_addr).await?;
    eprintln!("Established outbound connection to {}.", dest_addr);

    let (mut in_read, mut in_write) = tio::split(inbound_conn);
    let (mut out_read, mut out_write) = outbound_conn.into_split();

    let in_to_out = tokio::spawn(async move { tio::copy(&mut in_read, &mut out_write).await });
    let out_to_in = tokio::spawn(async move { tio::copy(&mut out_read, &mut in_write).await });

    select! {
        _ = in_to_out => eprintln!("in_to_out shut down."),
        _ = out_to_in => eprintln!("out_to_in shut down."),
    }

    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let options: Options = argh::from_env();
    let dest_addr = format!("localhost:{}", options.port);
    eprintln!("Destination address is {}.", &dest_addr);

    let config = tls_config();
    let acceptor = TlsAcceptor::from(config);

    let listener = TcpListener::bind("0.0.0.0:0").await?;
    let listen_port = listener.local_addr()?.port();
    eprintln!("TLS Proxy is listening on localhost:{}.", listen_port);

    loop {
        if let Err(err) = handle_conn(&listener, &acceptor, &dest_addr).await {
            eprintln!("Error handling connection: {}", err);
        }
    }
}
