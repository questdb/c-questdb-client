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

//! Conformance tests C1-C8 and the cache half of C20
//! (design/qwp-token-provider-spec.md §10), ported from the Java client's
//! `RefreshingTokenProviderTest`. A manual clock and a provider without a
//! refresher thread make them deterministic: the test runs due fetches itself.

use super::*;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, AtomicUsize, Ordering};
use std::thread;

const T0: i64 = 1_700_000_000_000;
const SEC: i64 = 1_000;
const MIN: i64 = 60 * SEC;
const HOUR: i64 = 60 * MIN;
const DAY: i64 = 24 * HOUR;

struct ManualClock {
    wall_ms: AtomicI64,
    mono_ns: AtomicU64,
}

impl ManualClock {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            wall_ms: AtomicI64::new(T0),
            mono_ns: AtomicU64::new(1_000_000_000),
        })
    }

    fn advance_ms(&self, ms: i64) {
        self.wall_ms.fetch_add(ms, Ordering::SeqCst);
        self.mono_ns
            .fetch_add((ms as u64) * 1_000_000, Ordering::SeqCst);
    }

    /// Move only the wall clock, as when a host sleeps.
    fn jump_wall_ms(&self, ms: i64) {
        self.wall_ms.fetch_add(ms, Ordering::SeqCst);
    }

    fn now_ms(&self) -> i64 {
        self.wall_ms.load(Ordering::SeqCst)
    }
}

impl Clock for ManualClock {
    fn wall_millis(&self) -> i64 {
        self.wall_ms.load(Ordering::SeqCst)
    }

    fn monotonic(&self) -> Duration {
        Duration::from_nanos(self.mono_ns.load(Ordering::SeqCst))
    }
}

/// A source whose results are scripted; an exhausted script fails retryably.
#[derive(Default)]
struct Script {
    results: Mutex<VecDeque<crate::Result<ExpiringToken>>>,
    calls: AtomicUsize,
}

impl Script {
    fn push(&self, result: crate::Result<ExpiringToken>) {
        self.results.lock().unwrap().push_back(result);
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }

    fn source(self: &Arc<Self>) -> impl TokenSource + 'static {
        let script = Arc::clone(self);
        move || -> crate::Result<ExpiringToken> {
            script.calls.fetch_add(1, Ordering::SeqCst);
            script
                .results
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or_else(|| Err(Error::token_unavailable(true, None, "script exhausted")))
        }
    }
}

fn token(name: &str, expires_at_ms: i64) -> ExpiringToken {
    ExpiringToken::new(name, system_time(expires_at_ms))
}

fn manual(clock: &Arc<ManualClock>, script: &Arc<Script>) -> RefreshingTokenProviderBuilder {
    RefreshingTokenProvider::builder(script.source())
        .clock(Arc::clone(clock) as Arc<dyn Clock>)
        .uniform(|| 0.5)
        .manual()
}

/// Wait (in real time) until `condition` holds.
fn await_true(what: &str, condition: impl Fn() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !condition() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        thread::sleep(Duration::from_millis(1));
    }
}

fn assert_refresh_delay(floor: i64, life: i64, u: f64, hint: Option<i64>, expected: i64) {
    let r = compute_refresh_at_millis(T0, T0 + life, hint, u, 5 * MIN, 30 * SEC, floor);
    assert_eq!(
        r - T0,
        expected,
        "life={life}, u={u}, hint={hint:?}, floor={floor}"
    );
}

#[test]
fn c1_refresh_schedule_follows_the_spec() {
    // u = 0 is the earliest jitter (0.45 L), 0.5 the middle, 1 the latest (0.55 L).
    assert_refresh_delay(0, DAY, 0.0, None, 38_880_000);
    assert_refresh_delay(0, DAY, 0.5, None, 43_200_000);
    assert_refresh_delay(0, DAY, 1.0, None, 47_520_000);
    assert_refresh_delay(0, HOUR, 0.0, None, 1_620_000);
    assert_refresh_delay(0, HOUR, 0.5, None, 1_800_000);
    assert_refresh_delay(0, HOUR, 1.0, None, 1_980_000);
    // L = 5 min: the margin is min(5 min, L/2) = 2.5 min.
    assert_refresh_delay(0, 5 * MIN, 0.0, None, 135_000);
    assert_refresh_delay(0, 5 * MIN, 0.5, None, 150_000);
    assert_refresh_delay(0, 5 * MIN, 1.0, None, 150_000);
    // An earlier refresh hint wins ...
    assert_refresh_delay(0, HOUR, 0.5, Some(T0 + 10 * MIN), 10 * MIN);
    assert_refresh_delay(0, DAY, 0.5, Some(T0 + 6 * HOUR), 6 * HOUR);
    // ... but never earlier than min_refresh_interval.
    assert_refresh_delay(0, HOUR, 0.5, Some(T0 + 5 * SEC), 30 * SEC);
    assert_refresh_delay(0, HOUR, 0.5, Some(T0 - HOUR), 30 * SEC);
    // A later hint does not delay the refresh.
    assert_refresh_delay(0, HOUR, 0.5, Some(T0 + 50 * MIN), 30 * MIN);
    assert_refresh_delay(0, 5 * MIN, 0.5, Some(T0 + 4 * MIN), 150_000);
    // A 50 s token: min_refresh_interval shrinks to L/2 = 25 s.
    assert_refresh_delay(0, 50 * SEC, 0.0, None, 25 * SEC);
}

#[test]
fn c1_refresh_schedule_keeps_the_refresh_inside_the_handout_window() {
    let floor = 60 * SEC;
    // Long-lived tokens keep their schedule.
    assert_refresh_delay(floor, DAY, 0.5, None, 43_200_000);
    assert_refresh_delay(floor, HOUR, 1.0, None, 1_980_000);
    assert_refresh_delay(floor, 5 * MIN, 0.5, None, 150_000);
    assert_refresh_delay(floor, 180 * SEC, 0.5, None, 90 * SEC);
    // A shorter-lived token is refreshed 30 s before its window closes ...
    assert_refresh_delay(floor, 150 * SEC, 0.0, None, 60 * SEC);
    assert_refresh_delay(floor, 150 * SEC, 0.5, None, 60 * SEC);
    assert_refresh_delay(floor, 120 * SEC, 0.5, None, 30 * SEC);
    // ... but no sooner than 30 s after the fetch.
    assert_refresh_delay(floor, 100 * SEC, 0.0, None, 30 * SEC);
    assert_refresh_delay(floor, 100 * SEC, 1.0, None, 30 * SEC);
    // An earlier hint still wins.
    assert_refresh_delay(floor, 150 * SEC, 0.5, Some(T0 + 40 * SEC), 40 * SEC);
    // Handed out for 15 s: the 30 s spacing wins.
    assert_refresh_delay(floor, 75 * SEC, 0.5, None, 30 * SEC);
}

#[test]
fn c1_the_provider_schedules_the_computed_refresh() {
    let clock = ManualClock::new();
    let script = Arc::new(Script::default());
    script.push(Ok(token("T1", T0 + HOUR)));
    let provider = manual(&clock, &script).build().unwrap();
    assert!(provider.run_due_fetch());
    assert_eq!(provider.scheduled_in(), Some(Duration::from_secs(30 * 60)));
    // A short token, refreshed before its hand-out window closes.
    script.push(Ok(token("T2", T0 + 100 * SEC)));
    clock.advance_ms(30 * MIN);
    let now = clock.now_ms();
    script.push(Ok(token("T3", now + 100 * SEC)));
    // T2 expires before it is received: rejected. Fetch again after backoff.
    assert!(provider.run_due_fetch());
    assert_eq!(provider.status().consecutive_failures, 1);
    clock.advance_ms(SEC);
    assert!(provider.run_due_fetch());
    assert_eq!(provider.token().unwrap(), "T3");
    assert_eq!(provider.scheduled_in(), Some(Duration::from_secs(30)));
}

#[test]
fn c2_same_token_converges_and_stays_usable_until_the_floor() {
    let clock = ManualClock::new();
    let script = Arc::new(Script::default());
    let expires = T0 + 10 * MIN;
    for _ in 0..5 {
        script.push(Ok(token("SAME", expires)));
    }
    let provider = manual(&clock, &script).build().unwrap();
    let mut delays = Vec::new();
    assert!(provider.run_due_fetch());
    for _ in 0..4 {
        let delay = provider.scheduled_in().unwrap();
        delays.push(delay.as_millis() as i64);
        assert_eq!(provider.token().unwrap(), "SAME");
        clock.advance_ms(delay.as_millis() as i64);
        assert!(provider.run_due_fetch());
    }
    // Each refresh at about half the remaining lifetime, pulled ahead of the
    // hand-out cutoff once the token is short-lived.
    assert_eq!(delays, vec![300 * SEC, 150 * SEC, 60 * SEC, 30 * SEC]);
    // The last fetch returned the token inside handout_floor: a retryable
    // failure that names handout_floor, and the token is no longer handed out.
    let status = provider.status();
    assert_eq!(status.consecutive_failures, 1);
    let failure = status.last_failure.unwrap();
    assert!(failure.retryable());
    assert!(failure.message().contains("handout_floor"), "{failure:?}");
    assert_eq!(script.calls(), 5);
}

#[test]
fn c3_cold_burst_causes_exactly_one_fetch() {
    let clock = ManualClock::new();
    let script = Arc::new(Script::default());
    script.push(Ok(token("T1", T0 + HOUR)));
    let provider = manual(&clock, &script).build().unwrap();
    let callers: Vec<_> = (0..64)
        .map(|_| {
            let provider = provider.clone();
            thread::spawn(move || provider.token())
        })
        .collect();
    thread::sleep(Duration::from_millis(50));
    assert!(provider.run_due_fetch());
    for caller in callers {
        assert_eq!(caller.join().unwrap().unwrap(), "T1");
    }
    assert_eq!(script.calls(), 1);
    assert!(!provider.run_due_fetch(), "no second fetch may be due");
}

#[test]
fn c4_cold_failure_raises_a_retryable_error_within_cold_wait() {
    let clock = ManualClock::new();
    let script = Arc::new(Script::default());
    let provider = manual(&clock, &script)
        .cold_wait(Duration::from_secs(5))
        .build()
        .unwrap();
    let caller = {
        let provider = provider.clone();
        thread::spawn(move || provider.token())
    };
    // Fetches keep failing retryably until the caller's cold_wait elapses.
    for _ in 0..10 {
        let _ = provider.run_due_fetch();
        clock.advance_ms(SEC);
        thread::sleep(Duration::from_millis(10));
    }
    let err = caller.join().unwrap().unwrap_err();
    let classification = err.as_token_unavailable().expect("token-unavailable");
    assert!(classification.retryable(), "{err}");
    assert!(err.msg().contains("script exhausted"), "{err}");
    assert_eq!(err.code(), ErrorCode::SocketError);
}

#[test]
fn c4_cold_failure_passes_a_permanent_classification_through() {
    let clock = ManualClock::new();
    let script = Arc::new(Script::default());
    script.push(Err(Error::token_unavailable(
        false,
        None,
        "identity not assigned",
    )));
    // A backoff that outlasts cold_wait ends the wait at once.
    let provider = manual(&clock, &script)
        .cold_wait(Duration::from_secs(1))
        .backoff_initial(Duration::from_secs(10))
        .backoff_max(Duration::from_secs(10))
        .build()
        .unwrap();
    let caller = {
        let provider = provider.clone();
        thread::spawn(move || provider.token())
    };
    await_true("the cold caller to request the fetch", || {
        provider.scheduled_in() == Some(Duration::ZERO)
    });
    assert!(provider.run_due_fetch());
    let err = caller.join().unwrap().unwrap_err();
    let classification = err.as_token_unavailable().unwrap();
    assert!(!classification.retryable());
    assert!(classification.retry_after().is_some());
    assert_eq!(err.code(), ErrorCode::AuthError);
    assert!(err.msg().contains("identity not assigned"), "{err}");
    // A later caller fails at once too: the next fetch is beyond cold_wait.
    let err = provider.token().unwrap_err();
    assert!(!err.as_token_unavailable().unwrap().retryable());
}

#[test]
fn c5_backoff_follows_the_spec() {
    let expect = |u: f64, delays: [i64; 9]| {
        for (n, expected) in delays.iter().enumerate() {
            assert_eq!(
                backoff_delay_millis(n as u32 + 1, None, u, 500, 60_000, 300_000),
                *expected,
                "failure {} with u={u}",
                n + 1
            );
        }
    };
    expect(
        0.0,
        [250, 500, 1_000, 2_000, 4_000, 8_000, 16_000, 30_000, 30_000],
    );
    expect(
        0.5,
        [
            375, 750, 1_500, 3_000, 6_000, 12_000, 24_000, 45_000, 45_000,
        ],
    );
    // A positive delay, even at a 1 ms initial backoff.
    assert_eq!(backoff_delay_millis(1, None, 0.0, 1, 1, 0), 1);
    // A huge failure count saturates at backoff_max.
    assert_eq!(
        backoff_delay_millis(u32::MAX, None, 0.0, 500, 60_000, 0),
        30_000
    );
}

#[test]
fn c5_retry_after_is_honoured_and_capped() {
    assert_eq!(
        backoff_delay_millis(1, Some(10_000), 0.5, 500, 60_000, 300_000),
        10_000
    );
    assert_eq!(
        backoff_delay_millis(1, Some(900_000), 0.5, 500, 60_000, 300_000),
        300_000
    );
    // A shorter hint does not shorten the backoff.
    assert_eq!(
        backoff_delay_millis(5, Some(1), 0.5, 500, 60_000, 300_000),
        6_000
    );

    let clock = ManualClock::new();
    let script = Arc::new(Script::default());
    script.push(Err(Error::token_unavailable(
        true,
        Some(Duration::from_secs(20)),
        "throttled",
    )));
    let provider = manual(&clock, &script).build().unwrap();
    assert!(provider.run_due_fetch());
    assert_eq!(provider.scheduled_in(), Some(Duration::from_secs(20)));
}

#[test]
fn c5_success_resets_the_backoff() {
    let clock = ManualClock::new();
    let script = Arc::new(Script::default());
    script.push(Err(Error::token_unavailable(true, None, "blip 1")));
    script.push(Err(Error::token_unavailable(true, None, "blip 2")));
    script.push(Ok(token("T1", T0 + HOUR)));
    script.push(Err(Error::token_unavailable(true, None, "blip 3")));
    let provider = manual(&clock, &script).build().unwrap();
    assert!(provider.run_due_fetch());
    assert_eq!(provider.scheduled_in(), Some(Duration::from_millis(375)));
    clock.advance_ms(375);
    assert!(provider.run_due_fetch());
    assert_eq!(provider.scheduled_in(), Some(Duration::from_millis(750)));
    clock.advance_ms(750);
    assert!(provider.run_due_fetch());
    assert_eq!(provider.status().consecutive_failures, 0);
    let delay = provider.scheduled_in().unwrap();
    clock.advance_ms(delay.as_millis() as i64);
    assert!(provider.run_due_fetch());
    // The first failure after a success starts the ladder again.
    assert_eq!(provider.scheduled_in(), Some(Duration::from_millis(375)));
    // ... and the current token is still served meanwhile.
    assert_eq!(provider.token().unwrap(), "T1");
}

#[test]
fn c6_a_token_inside_handout_floor_is_never_handed_out() {
    let clock = ManualClock::new();
    let script = Arc::new(Script::default());
    // Exactly handout_floor of lifetime on arrival: never usable.
    script.push(Ok(token("FLOOR", T0 + 60 * SEC)));
    // One millisecond more is usable.
    script.push(Ok(token("PLUS", T0 + 60 * SEC + 1)));
    let provider = manual(&clock, &script).build().unwrap();
    assert!(provider.run_due_fetch());
    let failure = provider.status().last_failure.unwrap();
    assert!(failure.retryable());
    assert!(failure.message().contains("handout_floor"), "{failure:?}");
    // Run the retry after its backoff without moving the wall clock, so the
    // second token arrives at the same wall time as the first.
    let delay = provider.scheduled_in().unwrap();
    clock
        .mono_ns
        .fetch_add(delay.as_nanos() as u64, Ordering::SeqCst);
    assert!(provider.run_due_fetch());
    assert_eq!(provider.token().unwrap(), "PLUS");
    // One millisecond later it enters the floor and is no longer handed out:
    // a caller that will not wait gets nothing.
    clock.advance_ms(1);
    assert!(matches!(
        provider.token_until(Some(&|| true)),
        Err(TokenWait::Cancelled)
    ));
}

#[test]
fn c7_a_cancelled_wait_returns_promptly() {
    let clock = ManualClock::new();
    let script = Arc::new(Script::default());
    let provider = manual(&clock, &script).build().unwrap();
    let cancelled = Arc::new(AtomicBool::new(false));
    let caller = {
        let provider = provider.clone();
        let cancelled = Arc::clone(&cancelled);
        thread::spawn(move || {
            let started = Instant::now();
            let outcome = provider.token_until(Some(&|| cancelled.load(Ordering::SeqCst)));
            (
                matches!(outcome, Err(TokenWait::Cancelled)),
                started.elapsed(),
            )
        })
    };
    thread::sleep(Duration::from_millis(30));
    cancelled.store(true, Ordering::SeqCst);
    let (was_cancelled, _) = caller.join().unwrap();
    assert!(was_cancelled);
    // The wait itself is bounded by the caller's predicate, not cold_wait:
    // the manual clock never advanced past it.
    assert_eq!(script.calls(), 0);
}

#[test]
fn c8_forced_refresh_is_rate_limited_ignores_stale_tokens_and_accepts_the_same_token() {
    let clock = ManualClock::new();
    let script = Arc::new(Script::default());
    script.push(Ok(token("T1", T0 + HOUR)));
    script.push(Ok(token("T2", T0 + 2 * HOUR)));
    let provider = manual(&clock, &script).build().unwrap();
    assert!(provider.run_due_fetch());
    let proactive = provider.scheduled_in();

    // Not a 401, or not the current token: ignored.
    provider.on_rejected("T1", 403);
    provider.on_rejected("stale", 401);
    assert_eq!(provider.scheduled_in(), proactive);

    // A 401 for the current token forces a fetch and waits for it.
    let rejecter = {
        let provider = provider.clone();
        thread::spawn(move || provider.on_rejected("T1", 401))
    };
    await_true("the forced fetch to be scheduled", || {
        provider.scheduled_in() == Some(Duration::ZERO)
    });
    assert!(provider.run_due_fetch());
    rejecter.join().unwrap();
    assert_eq!(provider.token().unwrap(), "T2");

    // Within forced_min_interval: rate limited.
    let after_forced = provider.scheduled_in();
    provider.on_rejected("T2", 401);
    assert_eq!(provider.scheduled_in(), after_forced);

    // After the interval, a stale token is still ignored ...
    clock.advance_ms(31 * SEC);
    let before = provider.scheduled_in();
    provider.on_rejected("T1", 401);
    assert_eq!(provider.scheduled_in(), before);

    // ... and a forced fetch that returns the same token is a success.
    script.push(Ok(token("T2", T0 + 2 * HOUR)));
    let rejecter = {
        let provider = provider.clone();
        thread::spawn(move || provider.on_rejected("T2", 401))
    };
    await_true("the second forced fetch to be scheduled", || {
        provider.scheduled_in() == Some(Duration::ZERO)
    });
    assert!(provider.run_due_fetch());
    rejecter.join().unwrap();
    assert_eq!(provider.status().consecutive_failures, 0);
    assert_eq!(provider.token().unwrap(), "T2");
}

#[test]
fn c8_forced_wait_is_bounded_and_cancellable() {
    let clock = ManualClock::new();
    let script = Arc::new(Script::default());
    script.push(Ok(token("T1", T0 + HOUR)));
    let provider = manual(&clock, &script).build().unwrap();
    assert!(provider.run_due_fetch());
    // Nobody runs the forced fetch: the wait ends at forced_wait ...
    let rejecter = {
        let provider = provider.clone();
        thread::spawn(move || provider.on_rejected("T1", 401))
    };
    await_true("the forced fetch to be scheduled", || {
        provider.scheduled_in() == Some(Duration::ZERO)
    });
    clock.advance_ms(6 * SEC);
    rejecter.join().unwrap();
    // ... or when the caller is cancelled.
    clock.advance_ms(31 * SEC);
    let cancelled = AtomicBool::new(true);
    provider.on_rejected_until("T1", 401, Some(&|| cancelled.load(Ordering::SeqCst)));
}

#[test]
fn close_fails_token_permanently_and_wakes_every_cold_caller() {
    let clock = ManualClock::new();
    let script = Arc::new(Script::default());
    let provider = manual(&clock, &script).build().unwrap();
    let callers: Vec<_> = (0..4)
        .map(|_| {
            let provider = provider.clone();
            thread::spawn(move || provider.token())
        })
        .collect();
    thread::sleep(Duration::from_millis(30));
    provider.close();
    for caller in callers {
        let err = caller.join().unwrap().unwrap_err();
        let classification = err.as_token_unavailable().unwrap();
        assert!(!classification.retryable());
        assert!(classification.provider_closed());
    }
    assert!(provider.is_closed());
    assert!(!provider.await_ready(Duration::from_secs(1)));
    assert!(!provider.run_due_fetch());
    let err = provider.token().unwrap_err();
    assert!(err.msg().contains("is closed"), "{err}");
}

#[test]
fn dropping_the_last_clone_closes_the_provider() {
    let clock = ManualClock::new();
    let script = Arc::new(Script::default());
    let provider = manual(&clock, &script).build().unwrap();
    let shared = Arc::clone(&provider.handle.shared);
    let clone = provider.clone();
    drop(provider);
    assert!(!shared.lock().closed);
    drop(clone);
    assert!(shared.lock().closed);
}

#[test]
fn wall_clock_overdue_refresh_starts_in_the_background() {
    let clock = ManualClock::new();
    let script = Arc::new(Script::default());
    script.push(Ok(token("T1", T0 + HOUR)));
    let provider = manual(&clock, &script).build().unwrap();
    assert!(provider.run_due_fetch());
    // The host slept: the wall clock passed the refresh time, but the
    // monotonic schedule did not.
    clock.jump_wall_ms(31 * MIN);
    assert_eq!(provider.token().unwrap(), "T1");
    assert_eq!(provider.scheduled_in(), Some(Duration::ZERO));
}

#[test]
fn unclassified_and_invalid_results_are_retryable_failures() {
    let clock = ManualClock::new();
    let script = Arc::new(Script::default());
    script.push(Err(Error::new(ErrorCode::ConfigError, "plain error")));
    script.push(Ok(token("bad\r\ntoken", T0 + HOUR)));
    script.push(Ok(token("   ", T0 + HOUR)));
    script.push(Ok(token("EXPIRED", T0 - 1)));
    let provider = manual(&clock, &script).build().unwrap();
    let mut messages = Vec::new();
    for _ in 0..4 {
        let delay = provider.scheduled_in().unwrap();
        clock.advance_ms(delay.as_millis() as i64);
        assert!(provider.run_due_fetch());
        let failure = provider.status().last_failure.unwrap();
        assert!(failure.retryable(), "{failure:?}");
        messages.push(failure.message().to_string());
    }
    assert!(messages[0].contains("plain error"));
    assert!(messages[1].contains("printable ASCII"));
    assert!(!messages[1].contains("bad"), "the token must not be echoed");
    assert!(messages[2].contains("blank"));
    assert!(messages[3].contains("expired"));
    assert_eq!(provider.status().consecutive_failures, 4);
}

#[cfg_attr(panic = "abort", ignore)]
#[test]
fn a_panicking_source_is_a_retryable_failed_fetch() {
    let clock = ManualClock::new();
    let calls = Arc::new(AtomicUsize::new(0));
    let source = {
        let calls = Arc::clone(&calls);
        move || -> crate::Result<ExpiringToken> {
            if calls.fetch_add(1, Ordering::SeqCst) == 0 {
                panic!("synthetic source panic");
            }
            Ok(ExpiringToken::new("T1", system_time(T0 + HOUR)))
        }
    };
    let provider = RefreshingTokenProvider::builder(source)
        .clock(Arc::clone(&clock) as Arc<dyn Clock>)
        .uniform(|| 0.5)
        .manual()
        .build()
        .unwrap();
    assert!(provider.run_due_fetch());
    assert!(
        provider
            .status()
            .last_failure
            .unwrap()
            .message()
            .contains("panicked")
    );
    clock.advance_ms(SEC);
    assert!(provider.run_due_fetch());
    assert_eq!(provider.token().unwrap(), "T1");
}

#[test]
fn c20_the_token_is_never_rendered() {
    const SENTINEL: &str = "SENTINEL-c20-secret";
    let clock = ManualClock::new();
    let script = Arc::new(Script::default());
    script.push(Ok(token(SENTINEL, T0 + HOUR)));
    let provider = manual(&clock, &script).name("c20").build().unwrap();
    assert!(provider.run_due_fetch());
    assert_eq!(provider.token().unwrap(), SENTINEL);
    let rendered = [
        format!("{provider:?}"),
        format!("{:?}", provider.status()),
        format!("{:?}", token(SENTINEL, T0 + HOUR)),
    ];
    for text in &rendered {
        assert!(!text.contains(SENTINEL), "{text}");
    }
    assert!(rendered[0].contains("sha256:"), "{}", rendered[0]);
    // A failure message is sanitized before it is stored.
    script.push(Err(Error::token_unavailable(
        true,
        None,
        "endpoint said \u{1b}[31mno\r\n\u{202e}",
    )));
    clock.advance_ms(31 * MIN);
    assert!(provider.run_due_fetch());
    let failure = provider.status().last_failure.unwrap();
    assert_eq!(failure.message(), "endpoint said [31mno");
}

#[test]
fn await_ready_gates_on_the_first_fetch() {
    let clock = ManualClock::new();
    let script = Arc::new(Script::default());
    script.push(Ok(token("T1", T0 + HOUR)));
    let provider = manual(&clock, &script).build().unwrap();
    let waiter = {
        let provider = provider.clone();
        thread::spawn(move || provider.await_ready(Duration::from_secs(5)))
    };
    assert!(!waiter.is_finished());
    assert!(provider.run_due_fetch());
    await_true("ready waiter", || waiter.is_finished());
    assert!(waiter.join().unwrap());

    let empty = Arc::new(Script::default());
    let cold = manual(&clock, &empty).build().unwrap();
    let waiter = {
        let cold = cold.clone();
        thread::spawn(move || cold.await_ready(Duration::from_secs(1)))
    };
    // The waiter may not have established its deadline yet. Keep advancing
    // until it completes instead of assuming a sleep scheduled that thread.
    let watchdog = Instant::now() + Duration::from_secs(10);
    while !waiter.is_finished() {
        if Instant::now() >= watchdog {
            cold.close();
            panic!("cold await_ready did not reach its manual-clock deadline");
        }
        clock.advance_ms(2 * SEC);
        thread::sleep(Duration::from_millis(5));
    }
    assert!(!waiter.join().unwrap());
}

#[test]
fn the_builder_rejects_an_invalid_configuration() {
    let script = Arc::new(Script::default());
    let err = RefreshingTokenProvider::builder(script.source())
        .backoff_initial(Duration::ZERO)
        .build()
        .unwrap_err();
    assert_eq!(err.code(), ErrorCode::ConfigError);
    let err = RefreshingTokenProvider::builder(script.source())
        .backoff_initial(Duration::from_secs(10))
        .backoff_max(Duration::from_secs(1))
        .build()
        .unwrap_err();
    assert!(err.msg().contains("backoff_max"), "{err}");
    let err = RefreshingTokenProvider::builder(script.source())
        .name(" ")
        .build()
        .unwrap_err();
    assert!(err.msg().contains("name"), "{err}");
}

#[test]
fn fmt_instant_renders_utc() {
    assert_eq!(fmt_instant(0), "1970-01-01T00:00:00.000Z");
    assert_eq!(fmt_instant(T0), "2023-11-14T22:13:20.000Z");
    assert_eq!(fmt_instant(951_782_400_123), "2000-02-29T00:00:00.123Z");
    assert_eq!(fmt_instant(-1), "1969-12-31T23:59:59.999Z");
}

/// With the real refresher thread: the provider prefetches and refreshes
/// proactively.
#[test]
fn the_refresher_thread_prefetches_and_refreshes_proactively() {
    let calls = Arc::new(AtomicUsize::new(0));
    let source = {
        let calls = Arc::clone(&calls);
        move || -> crate::Result<ExpiringToken> {
            let n = calls.fetch_add(1, Ordering::SeqCst) + 1;
            Ok(ExpiringToken::expires_in(
                format!("T{n}"),
                Duration::from_millis(2_000),
            ))
        }
    };
    let provider = RefreshingTokenProvider::builder(source)
        .handout_floor(Duration::from_secs(1))
        .min_refresh_interval(Duration::from_millis(100))
        .refresh_margin(Duration::from_secs(1))
        .build()
        .unwrap();
    assert!(provider.await_ready(Duration::from_secs(5)));
    assert!(provider.token().unwrap().starts_with('T'));
    await_true("a proactive refresh", || calls.load(Ordering::SeqCst) >= 2);
    provider.close();
}
