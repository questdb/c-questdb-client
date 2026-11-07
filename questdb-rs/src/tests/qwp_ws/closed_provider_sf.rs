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

//! A closed OIDC provider terminalizes a disk-backed QWP/WebSocket sender's
//! publication store, but must never cost it the frames it already accepted:
//! the slot keeps its `.sfa` segments, gets no `.failed` marker, and a later
//! sender with the same `sender_id` replays them (`oidc.h`,
//! `questdb_oidc_auth_close`).

use super::*;

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::ingress::AckLevel;
use crate::oidc::{
    OidcDeviceAuth, OidcError, OidcErrorKind, PersistedToken, TokenStore, TokenStoreKey,
    TokenStoreResult,
};

const IDP_TOKEN: &str = "https://idp.example.com/token";
const IDP_DEVICE: &str = "https://idp.example.com/device";

#[derive(Default)]
struct MemStore {
    entries: Mutex<HashMap<String, PersistedToken>>,
    coordination: Mutex<()>,
}

impl TokenStore for MemStore {
    fn load(&self, key: &TokenStoreKey) -> TokenStoreResult<Option<PersistedToken>> {
        Ok(self.entries.lock().unwrap().get(&key.hash()).cloned())
    }

    fn save(&self, key: &TokenStoreKey, token: &PersistedToken) -> TokenStoreResult<()> {
        self.entries
            .lock()
            .unwrap()
            .insert(key.hash(), token.clone());
        Ok(())
    }

    fn clear(&self, key: &TokenStoreKey) -> TokenStoreResult<()> {
        self.entries.lock().unwrap().remove(&key.hash());
        Ok(())
    }

    fn in_lock(
        &self,
        _key: &TokenStoreKey,
        action: &mut dyn FnMut() -> TokenStoreResult<()>,
    ) -> TokenStoreResult<()> {
        let _guard = self.coordination.lock().unwrap();
        action()
    }
}

/// A real `OidcDeviceAuth` whose store already holds a valid credential, so
/// `token()` serves it without any IdP traffic.
fn signed_in_auth() -> Arc<OidcDeviceAuth> {
    let store = MemStore::default();
    let key = TokenStoreKey::from_config(
        "questdb", IDP_TOKEN, IDP_DEVICE, "openid", None, false, None,
    );
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs_f64();
    store.entries.lock().unwrap().insert(
        key.hash(),
        PersistedToken::new(
            Some("AT-live".to_string()),
            None,
            Some("RT-live".to_string()),
            now + 3600.0,
            3600.0,
        ),
    );
    let auth = OidcDeviceAuth::builder()
        .client_id("questdb")
        .device_authorization_endpoint(IDP_DEVICE)
        .token_endpoint(IDP_TOKEN)
        .scope("openid")
        .interactive(false)
        .open_browser(false)
        .token_store(store)
        .build()
        .expect("build offline auth");
    assert_eq!(auth.token().expect("seeded token"), "AT-live");
    Arc::new(auth)
}

fn authorization(lines: &[String]) -> Option<String> {
    lines.iter().find_map(|line| {
        let (key, value) = line.split_once(':')?;
        key.trim()
            .eq_ignore_ascii_case("authorization")
            .then(|| value.trim().to_string())
    })
}

struct HoldThenDropServer {
    port: u16,
    first_data: mpsc::Receiver<(Vec<String>, Vec<u8>)>,
    drop_tx: mpsc::Sender<()>,
    stop_tx: mpsc::Sender<()>,
    later_conns: mpsc::Receiver<usize>,
    handle: thread::JoinHandle<()>,
}

/// Upgrades one connection, reports its first data frame without ACKing it,
/// and drops the socket on `drop_tx` so the sender must reconnect. Any later
/// connection attempt is counted until `stop_tx`.
fn spawn_hold_then_drop_server() -> HoldThenDropServer {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let (first_tx, first_rx) = mpsc::channel();
    let (drop_tx, drop_rx) = mpsc::channel::<()>();
    let (stop_tx, stop_rx) = mpsc::channel::<()>();
    let (later_tx, later_rx) = mpsc::channel();
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let lines = perform_server_upgrade(&mut stream).unwrap();
        loop {
            let (_fin, opcode, payload) = read_frame(&mut stream).unwrap();
            match opcode {
                0x2 if qwp_frame_has_tables(&payload) => {
                    first_tx.send((lines, payload)).unwrap();
                    break;
                }
                0x2 => {}
                0x9 => write_server_frame(&mut stream, 0xA, &payload, false).unwrap(),
                other => panic!("unexpected opcode {other} before the first data frame"),
            }
        }
        let _ = drop_rx.recv_timeout(Duration::from_secs(30));
        drop(stream);
        listener.set_nonblocking(true).unwrap();
        let deadline = Instant::now() + Duration::from_secs(60);
        let mut later = 0usize;
        loop {
            match listener.accept() {
                Ok((stream, _)) => {
                    later += 1;
                    drop(stream);
                }
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(err) => panic!("accept failed: {err}"),
            }
            match stop_rx.try_recv() {
                Ok(()) | Err(mpsc::TryRecvError::Disconnected) => break,
                Err(mpsc::TryRecvError::Empty) => {}
            }
            if Instant::now() > deadline {
                break;
            }
            thread::sleep(Duration::from_millis(5));
        }
        let _ = later_tx.send(later);
    });
    HoldThenDropServer {
        port,
        first_data: first_rx,
        drop_tx,
        stop_tx,
        later_conns: later_rx,
        handle,
    }
}

/// Upgrade request lines and the data frames a recovery server received.
type Received = (Vec<String>, Vec<Vec<u8>>);

/// Upgrades one connection, skips catch-up frames, ACKs the first data frame
/// and reports what it received.
fn spawn_recovery_ack_server() -> (u16, mpsc::Receiver<Received>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let lines = perform_server_upgrade(&mut stream).unwrap();
        let mut wire_seq = FIRST_WIRE_SEQUENCE;
        let mut data = Vec::new();
        loop {
            match read_frame(&mut stream) {
                Ok((_fin, 0x2, payload)) => {
                    let seq = wire_seq;
                    wire_seq += 1;
                    if qwp_frame_has_tables(&payload) {
                        data.push(payload);
                        write_qwp_ok_response(&mut stream, seq).unwrap();
                        break;
                    }
                }
                Ok((_fin, 0x9, payload)) => {
                    write_server_frame(&mut stream, 0xA, &payload, false).unwrap()
                }
                Ok(_) | Err(_) => break,
            }
        }
        let _ = tx.send((lines, data));
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut sink = [0u8; 256];
        while matches!(stream.read(&mut sink), Ok(n) if n > 0) {}
    });
    (port, rx)
}

enum ProviderKind {
    /// A real `OidcDeviceAuth`, closed with `close()`.
    RealOidcClose,
    /// A provider that starts returning `OidcError::cancelled` on a flag.
    SimulatedCancelled,
}

fn closed_provider_keeps_sf_slot_replayable(progress: ProgressCase, kind: ProviderKind) {
    let label = format!(
        "mode={} provider={}",
        progress.name(),
        match kind {
            ProviderKind::RealOidcClose => "real-oidc-close",
            ProviderKind::SimulatedCancelled => "simulated-cancelled",
        }
    );
    let sf_dir = tempfile::TempDir::new().unwrap();
    let slot = sf_dir.path().join("primary");
    let server = spawn_hold_then_drop_server();

    let auth = signed_in_auth();
    let closed_flag = Arc::new(AtomicBool::new(false));
    let conf = format!(
        "ws::addr=127.0.0.1:{};sf_dir={};sender_id=primary;\
         reconnect_initial_backoff_millis=10;reconnect_max_backoff_millis=20;\
         sf_max_segment_bytes=256;sf_max_total_bytes=1024;",
        server.port,
        sf_dir.path().display()
    );
    let builder = SenderBuilder::from_conf(&conf).unwrap();
    let builder = match kind {
        ProviderKind::RealOidcClose => builder
            .bearer_token_provider({
                let auth = Arc::clone(&auth);
                move || auth.token()
            })
            .unwrap(),
        ProviderKind::SimulatedCancelled => builder
            .qwp_ws_token_provider({
                let closed = Arc::clone(&closed_flag);
                move || {
                    if closed.load(Ordering::SeqCst) {
                        Err(OidcError::cancelled(
                            "The OIDC authentication provider is closed.",
                        ))
                    } else {
                        Ok("AT-live".to_string())
                    }
                }
            })
            .unwrap(),
    };
    let mut sender = build_qwp_ws_sender_from_builder(progress, builder);

    let mut buf = sender.new_buffer();
    buf.table("trades")
        .unwrap()
        .symbol("src", "alpha")
        .unwrap()
        .column_i64("qty", 7)
        .unwrap()
        .at_now()
        .unwrap();
    sender.flush(&mut buf).unwrap();

    let deadline = Instant::now() + Duration::from_secs(10);
    let (lines, first_payload) = loop {
        if progress == ProgressCase::Manual {
            let _ = sender.drive_once();
        }
        match server.first_data.try_recv() {
            Ok(received) => break received,
            Err(_) if Instant::now() < deadline => thread::sleep(Duration::from_millis(5)),
            Err(err) => panic!("{label}: the first data frame never reached the server: {err:?}"),
        }
    };
    assert_eq!(
        authorization(&lines).as_deref(),
        Some("Bearer AT-live"),
        "{label}"
    );
    assert!(slot_has_sfa_file(&slot), "{label}: no .sfa after publish");

    // Close the provider while the connection is healthy, then break the
    // connection so the reconnect has to pull a token.
    match kind {
        ProviderKind::RealOidcClose => {
            auth.close();
            assert_eq!(
                auth.token().unwrap_err().kind(),
                OidcErrorKind::Cancelled,
                "{label}"
            );
        }
        ProviderKind::SimulatedCancelled => closed_flag.store(true, Ordering::SeqCst),
    }
    server.drop_tx.send(()).unwrap();

    let err = sender
        .wait(AckLevel::Ok, Duration::from_secs(15))
        .expect_err("wait must fail once the closed provider terminalizes the store");
    assert_eq!(err.code(), ErrorCode::AuthError, "{label}: {err}");
    assert_eq!(
        err.oidc_error().map(OidcError::kind),
        Some(OidcErrorKind::Cancelled),
        "{label}"
    );

    let mut refused = sender.new_buffer();
    refused
        .table("trades")
        .unwrap()
        .column_i64("qty", 8)
        .unwrap()
        .at_now()
        .unwrap();
    assert!(
        sender.flush(&mut refused).is_err(),
        "{label}: a terminal store accepted a new frame"
    );
    assert!(
        slot_has_sfa_file(&slot),
        "{label}: .sfa removed while terminal"
    );
    assert!(!slot.join(".failed").exists(), "{label}: .failed written");

    let _ = sender.close_drain();
    drop(sender);
    assert!(slot_has_sfa_file(&slot), "{label}: .sfa removed on close");
    assert!(
        !slot.join(".failed").exists(),
        "{label}: .failed written on close"
    );

    server.stop_tx.send(()).unwrap();
    let later = server
        .later_conns
        .recv_timeout(Duration::from_secs(5))
        .unwrap();
    server.handle.join().unwrap();
    assert_eq!(later, 0, "{label}: a closed provider must not dial");

    // A later sender with the same sender_id replays the queued frame.
    let (recovery_port, recovery_rx) = spawn_recovery_ack_server();
    let recovery_conf = format!(
        "ws::addr=127.0.0.1:{recovery_port};sf_dir={};sender_id=primary;\
         sf_max_segment_bytes=256;sf_max_total_bytes=1024;",
        sf_dir.path().display()
    );
    let retry_deadline = Instant::now() + Duration::from_secs(5);
    let mut recovery = loop {
        let built = SenderBuilder::from_conf(&recovery_conf)
            .unwrap()
            .qwp_ws_token_provider(|| Ok::<_, crate::Error>("AT-fresh".to_string()))
            .unwrap()
            .build();
        match built {
            Ok(sender) => break sender,
            // The previous owner's slot lock may still be releasing.
            Err(_) if Instant::now() < retry_deadline => thread::sleep(Duration::from_millis(10)),
            Err(err) => panic!("{label}: the slot is not reusable: {err}"),
        }
    };
    let (recovery_lines, replayed) = recovery_rx
        .recv_timeout(Duration::from_secs(10))
        .unwrap_or_else(|err| panic!("{label}: the recovery server got nothing: {err:?}"));
    assert_eq!(
        authorization(&recovery_lines).as_deref(),
        Some("Bearer AT-fresh")
    );
    assert_eq!(
        replayed,
        vec![first_payload],
        "{label}: the queued frame was not replayed verbatim"
    );
    recovery.close_drain().unwrap();
    drop(recovery);
    assert!(
        wait_until(Duration::from_secs(5), || !slot_has_sfa_file(&slot)),
        "{label}: the replayed frame was not completed"
    );
    assert!(!slot.join(".failed").exists());
}

#[test]
fn closed_oidc_provider_keeps_sf_slot_replayable_background() {
    closed_provider_keeps_sf_slot_replayable(ProgressCase::Background, ProviderKind::RealOidcClose);
}

#[test]
fn closed_oidc_provider_keeps_sf_slot_replayable_manual() {
    closed_provider_keeps_sf_slot_replayable(ProgressCase::Manual, ProviderKind::RealOidcClose);
}

#[test]
fn cancelled_provider_keeps_sf_slot_replayable_background() {
    closed_provider_keeps_sf_slot_replayable(
        ProgressCase::Background,
        ProviderKind::SimulatedCancelled,
    );
}

#[test]
fn cancelled_provider_keeps_sf_slot_replayable_manual() {
    closed_provider_keeps_sf_slot_replayable(
        ProgressCase::Manual,
        ProviderKind::SimulatedCancelled,
    );
}
