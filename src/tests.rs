use super::*;

use std::path::Path;
use core::time::Duration;
use mio::{Poll, Token, Events, Interest};
use mio::net::{TcpStream};
use std::io::{self, Read};
use std::net::{SocketAddr};
use std::sync::Arc;
use socket2::{Domain, Type, Protocol, Socket};
use rustls::{
    Certificate,
    ServerConfig,
    Stream,
    server::{ServerConnection, NoClientAuth}};

const CLIENT: Token = Token(0);

struct MockServer {
    poll: Poll,
    events: Events,
    listener: Socket,
    client: Option<TcpStream>,
    tls_conn: Option<ServerConnection>,
    pub host: &'static str,
    pub port: u16,
    pub msgs: Vec<String>
}

fn load_certs(filename: &Path) -> Vec<Certificate> {
    let certfile = std::fs::File::open(filename)
        .expect("cannot open certificate file");
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
    certs_dir.push("system_test");
    certs_dir.push("certs");
    certs_dir
}

fn tls_config() -> Arc<ServerConfig> {
    let certs_dir = certs_dir();
    let cert_chain = load_certs(&certs_dir.join("server.crt"));
    let key_der = load_private_key(&certs_dir.join("server.key"));
    let config = ServerConfig::builder()
        .with_safe_default_cipher_suites()
        .with_safe_default_kx_groups()
        .with_safe_default_protocol_versions().unwrap()
        .with_client_cert_verifier(NoClientAuth::new())
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
            listener: listener,
            client: None,
            tls_conn: None,
            host: "localhost",
            port: port,
            msgs: Vec::new()})
    }

    fn store_client(&mut self, client: Socket) -> io::Result<()> {
        client.set_nonblocking(true)?;
        let client: std::net::TcpStream = client.into();
        let mut client = TcpStream::from_std(client);
        self.poll.registry().register(&mut client, CLIENT,
            Interest::READABLE)?;
        self.client = Some(client);
        Ok(())
    }

    pub fn accept(&mut self) -> io::Result<()> {
        let (client, _) = self.listener.accept()?;
        self.store_client(client)
    }

    pub fn accept_tls(mut self) -> io::Result<Self> {
        self.accept()?;
        let client = self.client.as_mut().unwrap();
        self.poll.registry().reregister(
            client, CLIENT, Interest::READABLE | Interest::WRITABLE)?;
        let mut tls_conn = ServerConnection::new(tls_config()).unwrap();
        let mut stream = Stream::new(&mut tls_conn, client);
        while stream.conn.is_handshaking() {
            match stream.conn.complete_io(&mut stream.sock) {
                Ok(_) => {
                },
                Err(ref err) if err.kind() == io::ErrorKind::WouldBlock => {
                    self.poll.poll(&mut self.events, None)?;
                },
                Err(err) => {
                    return Err(err)
                }
            }
        }
        self.poll.registry().reregister(client, CLIENT, Interest::READABLE)?;
        self.tls_conn = Some(tls_conn);
        Ok(self)
    }

    pub fn wait_for_data(&mut self, wait_timeout_sec: Option<f64>) -> io::Result<bool> {
        self.client.as_ref().unwrap();  // To ensure a clean death if accept wasn't called.
        let timeout = wait_timeout_sec.map(|sec| {
            Duration::from_micros((sec * 1000000.0) as u64)
        });
        self.poll.poll(&mut self.events, timeout)?;
        let ready_for_read = !self.events.is_empty();
        Ok(ready_for_read)
    }

    fn do_read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let client = self.client.as_mut().unwrap();
        if let Some(tls_conn) = self.tls_conn.as_mut() {
            let mut stream = Stream::new(tls_conn, client);
            stream.read(buf)
        }
        else {
            client.read(buf)
        }
    }

    pub fn recv(&mut self, wait_timeout_sec: f64) -> io::Result<usize> {
        if !self.wait_for_data(Some(wait_timeout_sec))? {
            return Ok(0)
        }

        let mut accum = Vec::<u8>::new();
        let mut chunk = [0u8; 1024];
        loop {
            eprintln!("recv :: (A)");
            let count = match self.do_read(&mut chunk[..]) {
                Ok(count) => count,
                Err(ref err) if err.kind() == io::ErrorKind::WouldBlock => {
                    self.poll.poll(&mut self.events, Some(Duration::from_millis(200)))?;
                    continue;
                },
                Err(err) => return Err(err)
            };
            eprintln!("recv :: (B)");
            accum.extend(&chunk[..count]);
            if accum.len() < 2 {
                eprintln!("recv :: (C)");
                continue;
            }
            if (accum[accum.len() - 1] == b'\n') &&
                (accum[accum.len() - 2] != b'\\') {
                eprintln!("recv :: (D)");
                break;
            }
            let accum_str: String = accum.iter().map(|&c| c as char).collect();  //std::str::from_utf8(&accum[..]).unwrap();
            eprintln!("recv :: (E) accum: {:?}", accum_str);
        }
        let accum_str = std::str::from_utf8(&accum[..]).unwrap();
        eprintln!("recv :: (F) accum: {:?}", accum_str);

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
        eprintln!("recv :: (G) receive_count: {}, msgs: {:?}", received_count, self.msgs);
        Ok(received_count)
    }

    pub fn recv_q(&mut self) -> io::Result<usize> {
        self.recv(0.1)
    }

    pub fn lsb(&self) -> LineSenderBuilder {
        LineSenderBuilder::new(self.host, self.port)
    }
}

type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

#[test]
fn test_basics() -> TestResult {
    let mut server = MockServer::new()?;
    let mut sender = server.lsb().connect()?;
    assert_eq!(sender.must_close(), false);
    server.accept()?;

    assert_eq!(server.recv_q()?, 0);

    sender
        .table("test")?
        .symbol("t1", "v1")?
        .column_f64("f1", 0.5)?
        .at(10000000)?;

    assert_eq!(server.recv_q()?, 0);
    let exp = "test,t1=v1 f1=0.5 10000000\n";
    assert_eq!(sender.peek_pending(), exp);
    assert_eq!(sender.pending_size(), exp.len());
    sender.flush()?;
    assert_eq!(server.recv_q()?, 1);
    assert_eq!(server.msgs[0].as_str(), exp);
    Ok(())
}

#[cfg(feature = "insecure_skip_verify")]
#[test]
fn test_tls_insecure_skip_verify() -> TestResult {
    eprintln!("test_tls_insecure_skip_verify :: (A)");
    let server = MockServer::new()?;
    eprintln!("test_tls_insecure_skip_verify :: (B)");
    let mut lsb = server.lsb();
    eprintln!("test_tls_insecure_skip_verify :: (C)");
    lsb.tls(Tls::InsecureSkipVerify);
    let jh = std::thread::spawn(|| -> io::Result<MockServer> {
        eprintln!("test_tls_insecure_skip_verify.accept :: (A)");
        let server = server.accept_tls()?;
        eprintln!("test_tls_insecure_skip_verify.accept :: (B)");
        Ok(server)
    });
    eprintln!("test_tls_insecure_skip_verify :: (D)");
    let mut sender = lsb.connect()?;
    eprintln!("test_tls_insecure_skip_verify :: (E)");
    let mut server: MockServer = jh.join().unwrap()?;

    sender
        .table("test")?
        .symbol("t1", "v1")?
        .column_f64("f1", 0.5)?
        .at(10000000)?;

    assert_eq!(server.recv_q()?, 0);
    let exp = "test,t1=v1 f1=0.5 10000000\n";
    assert_eq!(sender.peek_pending(), exp);
    assert_eq!(sender.pending_size(), exp.len());

    eprintln!("test_tls_insecure_skip_verify :: (F)");
    sender.flush()?;

    eprintln!("test_tls_insecure_skip_verify :: (G)");
    assert_eq!(server.recv_q()?, 1);
    eprintln!("test_tls_insecure_skip_verify :: (H)");
    assert_eq!(server.msgs[0].as_str(), exp);
    eprintln!("test_tls_insecure_skip_verify :: (I)");
    Ok(())
}
