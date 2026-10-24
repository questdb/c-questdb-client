/*******************************************************************************
 *     ___                  _   ____  ____
 *    / _ \ _   _  ___  ___| |_|  _ \| __ )
 *   | | | | | | |/ _ \/ __| __| | | |  _ \
 *   | |_| | |_| |  __/\__ \ |_| |_| | |_) |
 *    \__\_\\__,_|\___||___/\__|____/|____/
 *
 *  Copyright (c) 2014-2019 Appsicle
 *  Copyright (c) 2019-2026 QuestDB
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

//! A `RefreshingTokenProvider` must not call into the `log` backend while it
//! holds its state lock. `Debug` takes that lock, and the thread formatting
//! the provider may hold the backend's own output lock at the time --
//! `eprintln!("{provider:?}")` formats under the stderr lock. A forced refresh
//! that logged under the state lock deadlocked the two threads for good.
//!
//! This is its own test binary: `log::set_logger` is process-wide.

#![cfg(any(
    feature = "_sender-http",
    feature = "_sender-qwp-ws",
    feature = "_egress"
))]

use std::sync::{Mutex, OnceLock, mpsc};
use std::thread;
use std::time::Duration;

use questdb::token_provider::{ExpiringToken, RefreshingTokenProvider};

/// Stands in for a log backend's output lock.
static OUTPUT: Mutex<()> = Mutex::new(());

/// Told when the forced refresh's log record reaches the backend.
static FORCED_REFRESH_LOGGED: OnceLock<Mutex<Option<mpsc::Sender<()>>>> = OnceLock::new();

/// A backend that takes its output lock to emit every record.
struct LockingLogger;

impl log::Log for LockingLogger {
    fn enabled(&self, _: &log::Metadata<'_>) -> bool {
        true
    }

    fn log(&self, record: &log::Record<'_>) {
        if record.args().to_string().contains("refreshing early")
            && let Some(logged) = FORCED_REFRESH_LOGGED
                .get()
                .and_then(|slot| slot.lock().unwrap().take())
        {
            let _ = logged.send(());
        }
        let _output = OUTPUT.lock().unwrap_or_else(|err| err.into_inner());
    }

    fn flush(&self) {}
}

static LOGGER: LockingLogger = LockingLogger;

#[test]
fn a_forced_refresh_logs_without_holding_the_state_lock() {
    log::set_logger(&LOGGER).unwrap();
    log::set_max_level(log::LevelFilter::Info);
    let provider = RefreshingTokenProvider::builder(|| {
        Ok(ExpiringToken::expires_in("T0", Duration::from_secs(3600)))
    })
    .build()
    .unwrap();
    assert!(provider.await_ready(Duration::from_secs(5)));

    let (logged_tx, logged_rx) = mpsc::channel();
    FORCED_REFRESH_LOGGED
        .set(Mutex::new(Some(logged_tx)))
        .unwrap();
    let (holding_tx, holding_rx) = mpsc::channel();
    let (done_tx, done_rx) = mpsc::channel();

    // Holds the backend's output lock, and formats the provider once the
    // forced refresh's record is on its way to the backend.
    let formatter = {
        let provider = provider.clone();
        let done = done_tx.clone();
        thread::spawn(move || {
            let output = OUTPUT.lock().unwrap();
            holding_tx.send(()).unwrap();
            logged_rx.recv().unwrap();
            let rendered = format!("{provider:?}");
            drop(output);
            let _ = done.send(());
            rendered
        })
    };
    holding_rx.recv().unwrap();

    // A server rejects the current token: a forced refresh, which logs.
    let rejecter = {
        let provider = provider.clone();
        thread::spawn(move || {
            provider.on_rejected("T0", 401);
            let _ = done_tx.send(());
        })
    };

    for _ in 0..2 {
        done_rx.recv_timeout(Duration::from_secs(10)).expect(
            "deadlock: the forced refresh logged while holding the provider's state lock, \
             which `Debug` needed",
        );
    }
    assert!(
        formatter
            .join()
            .unwrap()
            .starts_with("RefreshingTokenProvider")
    );
    rejecter.join().unwrap();
    provider.close();
}
