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

//! End-to-end live-broker auth smoke for the QWP egress reader.
//!
//! The mock-driven auth tests in `egress_failover.rs` verify that the
//! client builds the right `Authorization` header on the wire. They do
//! NOT exercise an actual broker decoding that header — a base64
//! padding bug that only manifests at specific username/password
//! lengths, or a server-side rejection edge case, would slip past the
//! mocks and only surface in production.
//!
//! This test connects to an externally-provisioned QuestDB instance
//! and drives a single `select 1` through the full Basic-auth path.
//! Gated on `QDB_LIVE_BROKER_AUTH=user:pass` because the submodule-
//! launched QuestDB used by the rest of the live suite does not have
//! auth configured by default; running this test requires an operator
//! to point it at a real authenticated broker.
//!
//! Configuration via environment:
//!
//! - `QDB_LIVE_BROKER_AUTH=user:pass` — credentials. **Required**;
//!   the test skips with a noisy `eprintln!` when this is unset, which
//!   is the expected default in CI.
//! - `QDB_LIVE_BROKER_ADDR=host:port` — broker address. Defaults to
//!   `localhost:9000` when unset.
//!
//! Run manually with:
//!
//! ```text
//! QDB_LIVE_BROKER_AUTH=admin:quest \
//!   cargo test --features sync-reader-ws --test egress_live_auth -- --nocapture
//! ```

#![cfg(feature = "sync-reader-ws")]

use std::env;

use questdb::egress::Reader;

const AUTH_ENV: &str = "QDB_LIVE_BROKER_AUTH";
const ADDR_ENV: &str = "QDB_LIVE_BROKER_ADDR";
const DEFAULT_ADDR: &str = "localhost:9000";

/// Skip silently when `QDB_LIVE_BROKER_AUTH` is unset (the CI default).
/// Otherwise drive a real `qwp://` connect + Basic-auth handshake +
/// trivial query against the broker named by `QDB_LIVE_BROKER_ADDR`
/// (or `localhost:9000`). Catches base64 padding / encoding regressions
/// in the `Authorization` header that the mock-driven tests can't see.
#[test]
fn live_basic_auth_handshake_and_query() {
    let creds = match env::var(AUTH_ENV) {
        Ok(v) => v,
        Err(_) => {
            eprintln!(
                "skipping live auth smoke: {AUTH_ENV} not set. \
                 Run with `{AUTH_ENV}=user:pass cargo test ... --test egress_live_auth` \
                 to exercise the real-broker handshake."
            );
            return;
        }
    };
    let (user, pass) = match creds.split_once(':') {
        Some((u, p)) => (u, p),
        None => panic!(
            "{AUTH_ENV} must be in `user:pass` form (colon-separated); got {:?}",
            creds
        ),
    };
    if user.is_empty() {
        panic!("{AUTH_ENV} username is empty; expected `user:pass`");
    }

    let addr = env::var(ADDR_ENV).unwrap_or_else(|_| DEFAULT_ADDR.to_string());

    // `failover=off` keeps the diagnostic clean: a single endpoint
    // means a single auth attempt; any error surfaces directly from
    // that endpoint instead of being wrapped in a multi-endpoint
    // aggregation. Useful when the operator is debugging credentials.
    let conf = format!("qwp::addr={addr};username={user};password={pass};failover=off");
    eprintln!("live auth smoke: connecting to {addr} as {user:?}");

    let mut reader = match Reader::from_conf(&conf) {
        Ok(r) => r,
        Err(e) => panic!(
            "live broker at {addr} rejected basic auth as user {user:?}; \
             code={:?} msg={}. Check {AUTH_ENV} credentials and that the broker \
             actually requires auth.",
            e.code(),
            e.msg()
        ),
    };

    let mut cursor = reader
        .query("select 1")
        .execute()
        .expect("execute `select 1` under basic auth");

    // Drain to terminal so we exercise post-handshake decoding too —
    // an auth bug that lets the handshake through but corrupts a
    // later frame would otherwise slip past.
    let mut batches = 0usize;
    while let Some(_view) = cursor.next_batch().expect("next_batch under basic auth") {
        batches += 1;
        if batches > 16 {
            panic!("`select 1` produced too many batches; broker likely misconfigured");
        }
    }
    assert!(
        cursor.terminal().is_some(),
        "cursor must reach terminal (RESULT_END / EXEC_DONE) under basic auth; \
         got batches={batches}"
    );
}

/// Quick negative check: when `QDB_LIVE_BROKER_AUTH` is set, also
/// confirm that *wrong* credentials are rejected. Catches a regression
/// where the server silently accepts unauthenticated connections
/// (which would make the positive smoke vacuous).
#[test]
fn live_basic_auth_rejects_wrong_password() {
    let Ok(creds) = env::var(AUTH_ENV) else {
        eprintln!("skipping wrong-password smoke: {AUTH_ENV} not set");
        return;
    };
    let user = creds.split_once(':').map(|(u, _)| u).unwrap_or(&creds);
    if user.is_empty() {
        return;
    }
    let addr = env::var(ADDR_ENV).unwrap_or_else(|_| DEFAULT_ADDR.to_string());
    let bad_pass = "definitely-not-the-real-password-xyzzy-9c1f";
    let conf = format!("qwp::addr={addr};username={user};password={bad_pass};failover=off");
    match Reader::from_conf(&conf) {
        Ok(_) => panic!(
            "live broker at {addr} accepted clearly-wrong password for user {user:?}; \
             either the broker isn't enforcing auth or the username matched a different \
             account with a coincidentally weak password"
        ),
        Err(e) => {
            // The most diagnostic outcome is `AuthError`. We tolerate
            // `HandshakeError` too (some QuestDB versions return 403
            // without the `WWW-Authenticate` header that triggers the
            // 401/403 → AuthError mapping); anything in the
            // transport/handshake family disproves "silently accepted."
            use questdb::egress::ErrorCode;
            assert!(
                matches!(e.code(), ErrorCode::AuthError | ErrorCode::HandshakeError),
                "wrong-password rejection should surface as AuthError or HandshakeError; \
                 got {:?}: {}",
                e.code(),
                e.msg()
            );
            eprintln!(
                "wrong-password smoke: broker correctly rejected with {:?}",
                e.code()
            );
        }
    }
}
