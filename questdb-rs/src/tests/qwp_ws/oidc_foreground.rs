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

//! The synchronous initial connect is a connect its caller waits for, so an
//! OIDC provider that needs an explicit sign-in fails it immediately instead
//! of spending the whole reconnect budget (`reconnect_error_is_foreground_terminal`).
//! A provider that is only busy -- another thread is acquiring -- keeps
//! retrying.

use super::*;

use crate::oidc::{OidcError, OidcErrorKind};

fn sync_initial_connect_with(error: fn() -> OidcError) -> (crate::Result<()>, usize, Duration) {
    // Bound but never accepted: the provider runs before any dial.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let calls = Arc::new(AtomicUsize::new(0));
    let conf = format!(
        "ws::addr=127.0.0.1:{port};initial_connect_retry=sync;\
         reconnect_initial_backoff_millis=10;reconnect_max_backoff_millis=10;\
         reconnect_max_duration_millis=1500;"
    );
    let builder = SenderBuilder::from_conf(&conf)
        .unwrap()
        .qwp_ws_token_provider({
            let calls = Arc::clone(&calls);
            move || -> std::result::Result<String, OidcError> {
                calls.fetch_add(1, Ordering::SeqCst);
                Err(error())
            }
        })
        .unwrap();
    let started = Instant::now();
    let result = builder.build().map(drop);
    let elapsed = started.elapsed();
    drop(listener);
    (result, calls.load(Ordering::SeqCst), elapsed)
}

#[test]
fn sync_initial_connect_fails_fast_when_sign_in_is_required() {
    let (result, calls, elapsed) =
        sync_initial_connect_with(|| OidcError::interaction_required("sign in first"));
    let err = result.expect_err("a provider that needs a sign-in cannot connect");
    assert_eq!(
        err.oidc_error().map(OidcError::kind),
        Some(OidcErrorKind::InteractionRequired),
        "{err}"
    );
    assert_eq!(
        calls, 1,
        "the waiting connect retried a sign-in it cannot get"
    );
    assert!(
        elapsed < Duration::from_millis(1000),
        "the waiting connect spent its reconnect budget: {elapsed:?}"
    );
}

#[test]
fn sync_initial_connect_retries_a_busy_acquisition() {
    let (result, calls, _elapsed) = sync_initial_connect_with(|| {
        OidcError::interaction_required_busy("another thread is acquiring")
    });
    let err = result.expect_err("a provider that stays busy cannot connect");
    assert_eq!(
        err.oidc_error().map(OidcError::kind),
        Some(OidcErrorKind::InteractionRequired),
        "{err}"
    );
    assert!(
        calls > 1,
        "a busy acquisition must be retried within the budget, got {calls} call(s)"
    );
}
