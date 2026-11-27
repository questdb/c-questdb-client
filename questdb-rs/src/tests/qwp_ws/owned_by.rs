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

//! `owned_by`: the owner of the tables and columns a QWP/WebSocket sender
//! auto-creates. It is named in `X-QWP-Owned-By` on the upgrade of every
//! connection, and a connection the server does not confirm it on fails.

use super::*;

use std::sync::Mutex;

use crate::QuestDb;
use crate::ingress::AckLevel;

const OWNER: &str = "caf\u{e9} team";
const OWNER_ENCODED: &str = "caf%C3%A9%20team";
const NO_ECHO: &str = "<no X-QWP-Owned-By header>";

/// How the mock server answers an upgrade.
#[derive(Clone, Copy, Debug)]
enum Answer {
    /// Echo the owner the request named, as a server that accepts it does.
    Confirm,
    /// Leave the echo out, as a server that predates `owned_by` does.
    Ignore,
    /// Echo this value instead of the owner the request named.
    Echo(&'static str),
    /// Refuse the upgrade with a 403 that gives this plain-text reason, as a
    /// server does with an owner the principal may not name.
    Refuse(&'static str),
}

/// What the mock server does on a connection it upgraded.
#[derive(Clone, Copy, Debug)]
enum Then {
    /// Acknowledge every frame until the client goes away.
    AckAll,
    /// Read one frame, then drop the connection without acknowledging it.
    DropAfterFirstFrame,
}

/// A mock QuestDB server. It answers the n-th connection as the n-th entry of
/// its plan says, the last entry standing for every later connection, and
/// records the `X-QWP-Owned-By` value of each upgrade request (`None` for a
/// request that named no owner) in the order the requests arrive.
struct OwnedByServer {
    port: u16,
    owned_by_requests: Arc<Mutex<Vec<Option<String>>>>,
    stop: Arc<AtomicBool>,
    accept_loop: Option<thread::JoinHandle<()>>,
}

impl OwnedByServer {
    fn spawn(plan: &[(Answer, Then)]) -> Self {
        assert!(!plan.is_empty());
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let port = listener.local_addr().unwrap().port();
        let owned_by_requests = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let plan = plan.to_vec();
        let accept_loop = {
            let owned_by_requests = Arc::clone(&owned_by_requests);
            let stop = Arc::clone(&stop);
            thread::spawn(move || {
                let mut connections = Vec::new();
                while !stop.load(Ordering::SeqCst) {
                    match listener.accept() {
                        Ok((stream, _)) => {
                            let (answer, then) = plan[connections.len().min(plan.len() - 1)];
                            let owned_by_requests = Arc::clone(&owned_by_requests);
                            let stop = Arc::clone(&stop);
                            connections.push(thread::spawn(move || {
                                serve(stream, answer, then, &owned_by_requests, &stop)
                            }));
                        }
                        Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(5));
                        }
                        Err(_) => break,
                    }
                }
                for connection in connections {
                    let _ = connection.join();
                }
            })
        };
        Self {
            port,
            owned_by_requests,
            stop,
            accept_loop: Some(accept_loop),
        }
    }

    fn owned_by_requests(&self) -> Vec<Option<String>> {
        self.owned_by_requests.lock().unwrap().clone()
    }

    /// Waits until `count` upgrade requests have arrived, and returns them.
    fn await_owned_by_requests(&self, count: usize) -> Vec<Option<String>> {
        assert!(
            wait_until(Duration::from_secs(10), || self.owned_by_requests().len()
                >= count),
            "expected {count} upgrade requests, got {:?}",
            self.owned_by_requests()
        );
        self.owned_by_requests()
    }
}

impl Drop for OwnedByServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(accept_loop) = self.accept_loop.take() {
            let _ = accept_loop.join();
        }
    }
}

fn serve(
    mut stream: TcpStream,
    answer: Answer,
    then: Then,
    owned_by_requests: &Mutex<Vec<Option<String>>>,
    stop: &AtomicBool,
) {
    stream.set_nonblocking(false).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let Ok(request) = read_request_until_blank(&mut stream) else {
        return;
    };
    if !request.windows(4).any(|w| w == b"\r\n\r\n") {
        // A client that gave up on this connection before sending its request.
        return;
    }
    let request = String::from_utf8_lossy(&request).into_owned();
    let owned_by = parse_header(&request, "X-QWP-Owned-By");
    owned_by_requests.lock().unwrap().push(owned_by.clone());

    let response = match answer {
        Answer::Refuse(reason) => format!(
            "HTTP/1.1 403 Forbidden\r\n\
             Content-Type: text/plain\r\n\
             Content-Length: {}\r\n\
             \r\n\
             {reason}",
            reason.len()
        ),
        Answer::Confirm | Answer::Ignore | Answer::Echo(_) => {
            let key =
                parse_header(&request, "Sec-WebSocket-Key").expect("missing Sec-WebSocket-Key");
            let echo = match (answer, owned_by) {
                (Answer::Confirm, Some(owned_by)) => Some(owned_by),
                (Answer::Echo(value), _) => Some(value.to_owned()),
                _ => None,
            };
            format!(
                "HTTP/1.1 101 Switching Protocols\r\n\
                 Upgrade: websocket\r\n\
                 Connection: Upgrade\r\n\
                 Sec-WebSocket-Accept: {}\r\n\
                 X-QWP-Version: 1\r\n\
                 {}\
                 \r\n",
                compute_accept(&key),
                echo.map_or_else(String::new, |echo| format!("X-QWP-Owned-By: {echo}\r\n"))
            )
        }
    };
    if stream.write_all(response.as_bytes()).is_err() {
        return;
    }
    if !matches!(answer, Answer::Confirm) {
        // Whatever the client does now, it must not write: it either failed the
        // upgrade or was refused. Wait for it to hang up.
        let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
        let mut buf = [0u8; 256];
        while matches!(stream.read(&mut buf), Ok(n) if n > 0) && !stop.load(Ordering::SeqCst) {}
        return;
    }

    let _ = stream.set_read_timeout(Some(Duration::from_millis(50)));
    let mut next_wire_seq = 0u64;
    while !stop.load(Ordering::SeqCst) {
        match read_frame(&mut stream) {
            Ok((_, 0x8, _)) => break,
            Ok((_, 0x2, _)) => {
                if matches!(then, Then::DropAfterFirstFrame) {
                    break;
                }
                if write_qwp_ok_response(&mut stream, next_wire_seq).is_err() {
                    break;
                }
                next_wire_seq += 1;
            }
            Ok(_) => {}
            Err(err)
                if matches!(
                    err.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) => {}
            Err(_) => break,
        }
    }
}

fn add_row(sender: &crate::ingress::Sender) -> Buffer {
    let mut buf = sender.new_buffer();
    buf.table("trades")
        .unwrap()
        .symbol("sym", "ETH-USD")
        .unwrap()
        .column_i64("qty", 7)
        .unwrap()
        .at_now()
        .unwrap();
    buf
}

fn unconfirmed_owner_message(port: u16, echo: &str) -> String {
    format!(
        "WebSocket upgrade failed: server did not confirm owned_by, it cannot set the owner of \
         auto-created tables and columns [host=127.0.0.1, port={port}, owned_by={OWNER}, \
         echoed={echo}]"
    )
}

/// The connect string of a manually driven sender that adopts the orphan slot
/// `seed_orphan_slot` left in `sf_dir`.
fn orphan_drain_conf(port: u16, sf_dir: &Path) -> String {
    format!(
        "ws::addr=127.0.0.1:{port};qwp_ws_progress=manual;owned_by={OWNER};\
         sf_dir={};sender_id=primary;drain_orphans=on;max_background_drainers=1;\
         sf_max_segment_bytes=256;sf_max_total_bytes=1024;\
         reconnect_initial_backoff_millis=10;reconnect_max_backoff_millis=20;",
        sf_dir.display()
    )
}

/// The orphan slot keeps its frames for the next session, is not quarantined,
/// and names the unconfirmed owner as the reason they were not delivered.
fn assert_orphan_slot_kept(orphan_slot: &Path, port: u16) {
    assert!(
        slot_has_sfa_file(orphan_slot),
        "the orphan frames were dropped"
    );
    assert!(
        !orphan_slot.join(".failed").exists(),
        "the orphan slot was quarantined"
    );
    let last_error = std::fs::read_to_string(orphan_slot.join(".last_error")).unwrap_or_default();
    assert!(
        last_error.contains(&unconfirmed_owner_message(port, NO_ECHO)),
        "{last_error:?}"
    );
}

#[test]
fn owned_by_is_sent_percent_encoded_and_confirmed_in_all_progress_modes() {
    for progress in [ProgressCase::Background, ProgressCase::Manual] {
        let server = OwnedByServer::spawn(&[(Answer::Confirm, Then::AckAll)]);
        let conf = format!(
            "ws::addr=127.0.0.1:{};qwp_ws_progress={};owned_by={OWNER};",
            server.port,
            progress.name()
        );
        let mut sender = SenderBuilder::from_conf(conf).unwrap().build().unwrap();
        let mut buf = add_row(&sender);
        sender.flush(&mut buf).unwrap();
        sender
            .wait(AckLevel::Ok, Duration::from_secs(10))
            .unwrap_or_else(|err| panic!("mode={}: {err}", progress.name()));
        drop(sender);
        assert_eq!(
            server.owned_by_requests(),
            [Some(OWNER_ENCODED.to_owned())],
            "mode={}",
            progress.name()
        );
    }
}

#[test]
fn owned_by_from_the_builder_is_sent() {
    let server = OwnedByServer::spawn(&[(Answer::Confirm, Then::AckAll)]);
    let sender = SenderBuilder::new(Protocol::Ws, "127.0.0.1", server.port)
        .owned_by("team_a")
        .unwrap()
        .build()
        .unwrap();
    drop(sender);
    assert_eq!(server.owned_by_requests(), [Some("team_a".to_owned())]);
}

#[test]
fn no_owned_by_header_without_an_owner() {
    // Even against a server that would echo another owner: without an owner
    // the client neither names nor checks one.
    let server = OwnedByServer::spawn(&[(Answer::Echo("other"), Then::AckAll)]);
    let mut sender = SenderBuilder::new(Protocol::Ws, "127.0.0.1", server.port)
        .build()
        .unwrap();
    let mut buf = add_row(&sender);
    sender.flush(&mut buf).unwrap();
    drop(sender);
    assert_eq!(server.owned_by_requests(), [None]);
}

#[test]
fn an_unconfirmed_owner_fails_the_initial_connect() {
    // A server that predates `owned_by` ignores the header and leaves the echo
    // out; the tables it auto-created would not get the owner.
    for (answer, echo) in [
        (Answer::Ignore, NO_ECHO),
        (Answer::Echo("other"), "other"),
        (Answer::Echo(OWNER), OWNER),
    ] {
        let server = OwnedByServer::spawn(&[(answer, Then::AckAll)]);
        let conf = format!("ws::addr=127.0.0.1:{};owned_by={OWNER};", server.port);
        let err = SenderBuilder::from_conf(conf)
            .unwrap()
            .build()
            .expect_err("a sender must not connect where its owner is not confirmed");
        assert_eq!(err.code(), ErrorCode::ProtocolVersionError, "{answer:?}");
        assert_eq!(
            err.msg(),
            unconfirmed_owner_message(server.port, echo),
            "{answer:?}"
        );
        assert_eq!(
            server.owned_by_requests(),
            [Some(OWNER_ENCODED.to_owned())],
            "{answer:?}"
        );
    }
}

#[test]
fn an_unconfirmed_owner_is_not_retried_by_a_sync_initial_connect() {
    // A sync initial connect retries a failed connect within its budget, but
    // not a server without the capability: that is the caller's to see now.
    let server = OwnedByServer::spawn(&[(Answer::Ignore, Then::AckAll)]);
    let conf = format!(
        "ws::addr=127.0.0.1:{};owned_by={OWNER};initial_connect_retry=sync;\
         reconnect_initial_backoff_millis=10;reconnect_max_backoff_millis=20;\
         reconnect_max_duration_millis=5000;",
        server.port
    );
    let started = Instant::now();
    let err = SenderBuilder::from_conf(conf)
        .unwrap()
        .build()
        .expect_err("a sender must not connect where its owner is not confirmed");
    assert!(started.elapsed() < Duration::from_secs(4), "it was retried");
    assert_eq!(err.code(), ErrorCode::ProtocolVersionError);
    assert_eq!(err.msg(), unconfirmed_owner_message(server.port, NO_ECHO));
    assert_eq!(server.owned_by_requests().len(), 1);
}

#[test]
fn a_refused_owner_fails_the_initial_connect_with_the_server_reason() {
    let reason = "owned_by refused: bob is not part of group team";
    let server = OwnedByServer::spawn(&[(Answer::Refuse(reason), Then::AckAll)]);
    let conf = format!("ws::addr=127.0.0.1:{};owned_by={OWNER};", server.port);
    let err = SenderBuilder::from_conf(conf)
        .unwrap()
        .build()
        .expect_err("a refused owner must fail the connect");
    // A refusal holds on every node, like a rejected credential, and says why:
    // without the reason it would read like a rejected credential.
    assert_eq!(err.code(), ErrorCode::AuthError);
    assert_eq!(
        err.msg(),
        format!("WebSocket upgrade authentication failed: HTTP status 403 [reason={reason}]")
    );
}

#[test]
fn owned_by_is_sent_again_on_a_reconnect() {
    // The owner travels in every upgrade, so the tables a re-established
    // connection auto-creates get it too.
    let server = OwnedByServer::spawn(&[
        (Answer::Confirm, Then::DropAfterFirstFrame),
        (Answer::Confirm, Then::AckAll),
    ]);
    let conf = format!(
        "ws::addr=127.0.0.1:{};owned_by={OWNER};\
         reconnect_initial_backoff_millis=1;reconnect_max_backoff_millis=1;\
         reconnect_max_duration_millis=10000;",
        server.port
    );
    let mut sender = SenderBuilder::from_conf(conf).unwrap().build().unwrap();
    let mut buf = add_row(&sender);
    sender.flush(&mut buf).unwrap();
    sender
        .wait(AckLevel::Ok, Duration::from_secs(10))
        .expect("the frame must be replayed over the second connection");
    drop(sender);
    assert_eq!(
        server.owned_by_requests(),
        [
            Some(OWNER_ENCODED.to_owned()),
            Some(OWNER_ENCODED.to_owned())
        ]
    );
}

#[test]
fn a_reconnect_to_a_server_that_does_not_confirm_the_owner_is_terminal() {
    // As for a missing durable-ACK echo, the only endpoint lacks a capability
    // the sender needs, so it stops instead of writing without the owner.
    let server = OwnedByServer::spawn(&[
        (Answer::Confirm, Then::DropAfterFirstFrame),
        (Answer::Ignore, Then::AckAll),
    ]);
    let conf = format!(
        "ws::addr=127.0.0.1:{};owned_by={OWNER};\
         reconnect_initial_backoff_millis=1;reconnect_max_backoff_millis=1;\
         reconnect_max_duration_millis=10000;",
        server.port
    );
    let mut sender = SenderBuilder::from_conf(conf).unwrap().build().unwrap();
    let mut buf = add_row(&sender);
    sender.flush(&mut buf).unwrap();
    let err = sender
        .wait(AckLevel::Ok, Duration::from_secs(10))
        .expect_err("the frame must not be replayed where the owner is not confirmed");
    assert!(
        err.msg()
            .contains(&unconfirmed_owner_message(server.port, NO_ECHO)),
        "{}",
        err.msg()
    );
    assert!(sender.must_close());
    assert_eq!(
        server.owned_by_requests(),
        [
            Some(OWNER_ENCODED.to_owned()),
            Some(OWNER_ENCODED.to_owned())
        ]
    );
}

#[test]
fn an_orphan_drainer_names_the_owner() {
    // A drainer connects with the configuration of the sender that adopted the
    // orphan slot, so the tables its replay auto-creates get the owner too.
    let sf_dir = tempfile::TempDir::new().unwrap();
    seed_orphan_slot(sf_dir.path());
    let server = OwnedByServer::spawn(&[(Answer::Confirm, Then::AckAll)]);
    let mut sender = SenderBuilder::from_conf(orphan_drain_conf(server.port, sf_dir.path()))
        .unwrap()
        .build()
        .unwrap();
    let orphan_slot = sf_dir.path().join("orphan");
    assert!(
        wait_until(Duration::from_secs(10), || {
            let _ = sender.drive_once().unwrap();
            !slot_has_sfa_file(&orphan_slot)
        }),
        "the orphan slot was not drained"
    );
    drop(sender);
    // The foreground sender's upgrade and the drainer's.
    assert_eq!(
        server.await_owned_by_requests(2),
        [
            Some(OWNER_ENCODED.to_owned()),
            Some(OWNER_ENCODED.to_owned())
        ]
    );
}

#[test]
fn an_orphan_drainer_retries_a_server_that_does_not_confirm_the_owner() {
    // As after any failed connect, the drainer keeps the slot and dials again
    // later: the server may yet be upgraded to one that confirms the owner.
    let sf_dir = tempfile::TempDir::new().unwrap();
    seed_orphan_slot(sf_dir.path());
    let server = OwnedByServer::spawn(&[
        (Answer::Confirm, Then::AckAll),
        (Answer::Ignore, Then::AckAll),
    ]);
    let mut sender = SenderBuilder::from_conf(orphan_drain_conf(server.port, sf_dir.path()))
        .unwrap()
        .build()
        .unwrap();
    // The foreground sender's upgrade, then three of the drainer's.
    assert!(
        wait_until(Duration::from_secs(10), || {
            let _ = sender.drive_once().unwrap();
            server.owned_by_requests().len() >= 4
        }),
        "the drainer did not dial again: {:?}",
        server.owned_by_requests()
    );
    assert!(!sender.must_close());
    assert_orphan_slot_kept(&sf_dir.path().join("orphan"), server.port);
}

#[test]
fn an_orphan_drainer_retires_its_slot_when_a_reconnect_does_not_confirm_the_owner() {
    // As for the foreground sender, losing the owner on a reconnect is
    // terminal: the drainer gives the slot up for this session instead of
    // dialling again, and leaves its frames for the next session.
    let sf_dir = tempfile::TempDir::new().unwrap();
    seed_orphan_slot(sf_dir.path());
    let server = OwnedByServer::spawn(&[
        (Answer::Confirm, Then::AckAll),
        (Answer::Confirm, Then::DropAfterFirstFrame),
        (Answer::Ignore, Then::AckAll),
    ]);
    let mut sender = SenderBuilder::from_conf(orphan_drain_conf(server.port, sf_dir.path()))
        .unwrap()
        .build()
        .unwrap();
    let orphan_slot = sf_dir.path().join("orphan");
    let last_error = orphan_slot.join(".last_error");
    // Until the reconnect has failed and the slot was retired, quarantined or
    // dialled again.
    assert!(
        wait_until(Duration::from_secs(10), || {
            let _ = sender.drive_once().unwrap();
            server.owned_by_requests().len() > 3
                || orphan_slot.join(".failed").exists()
                || std::fs::read_to_string(&last_error)
                    .is_ok_and(|reason| reason.contains("did not confirm owned_by"))
        }),
        "the drainer's reconnect did not fail: {:?}",
        server.owned_by_requests()
    );
    // Driven on for ten times its reconnect backoff, a retired drainer does
    // not dial again.
    let started = Instant::now();
    while started.elapsed() < Duration::from_millis(200) {
        let _ = sender.drive_once().unwrap();
        thread::sleep(Duration::from_millis(1));
    }
    // The foreground sender's upgrade, the drainer's, and its reconnect's.
    assert_eq!(
        server.owned_by_requests().len(),
        3,
        "the drainer dialled again"
    );
    assert!(!sender.must_close());
    assert_orphan_slot_kept(&orphan_slot, server.port);
}

#[test]
fn a_pool_names_the_owner_on_its_sender_connections() {
    let server = OwnedByServer::spawn(&[(Answer::Confirm, Then::AckAll)]);
    // No reader warms up (`query_pool_min=0`): this mock serves ingestion only.
    // `egress_silently_accepts_owned_by` covers the reader side of the string.
    let db = QuestDb::connect(&format!(
        "ws::addr=127.0.0.1:{};owned_by={OWNER};sender_pool_min=1;sender_pool_max=1;\
         query_pool_min=0;pool_reap=manual;",
        server.port
    ))
    .unwrap();
    let mut sender = db.borrow_sender().unwrap();
    let mut buf = sender.new_buffer();
    buf.table("trades")
        .unwrap()
        .column_i64("qty", 7)
        .unwrap()
        .at_now()
        .unwrap();
    sender.flush_buffer(&mut buf).unwrap();
    sender.wait(AckLevel::Ok, Duration::from_secs(10)).unwrap();
    drop(sender);
    drop(db);
    assert_eq!(server.owned_by_requests(), [Some(OWNER_ENCODED.to_owned())]);
}
