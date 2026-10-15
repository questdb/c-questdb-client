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

//! A proactively refreshing token cache in front of a [`TokenSource`]: the
//! refreshing provider of the dynamic-credential specification
//! (design/qwp-token-provider-spec.md v0.7, §4-§5, in the Java client).

use super::BearerTokenProvider;
use super::redaction::{describe_token, sanitize_error_text};
use crate::{Error, ErrorCode};
use std::fmt;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// A failed fetch is logged at most this often per provider.
const FAILURE_LOG_INTERVAL: Duration = Duration::from_secs(60);
/// How often a cancellable wait polls its cancellation predicate.
const CANCEL_POLL: Duration = Duration::from_millis(5);
/// Longest delay ever scheduled or waited for: a token that "never expires"
/// must not overflow the arithmetic on monotonic deadlines.
const MAX_DELAY: Duration = Duration::from_secs(100 * 365 * 24 * 3600);

// ---------------------------------------------------------------------------
// Token source contract (spec §4)
// ---------------------------------------------------------------------------

/// A token and when it expires: the result of one [`TokenSource`] fetch.
///
/// The token is opaque and is sent as `Authorization: Bearer <token>`, so it is
/// given without the `Bearer ` prefix. Its [`Debug`](fmt::Debug) rendering
/// never shows it.
#[derive(Clone)]
pub struct ExpiringToken {
    token: String,
    expires_at: SystemTime,
    refresh_at: Option<SystemTime>,
}

impl ExpiringToken {
    /// A token that expires at the absolute instant `expires_at`.
    ///
    /// If the platform gives a relative lifetime, such as OAuth's
    /// `expires_in`, use [`expires_in`](Self::expires_in): computing the expiry
    /// from the local time of receipt makes the cache robust to clock skew. If
    /// the expiry is unknown, give a conservative one.
    pub fn new(token: impl Into<String>, expires_at: SystemTime) -> Self {
        Self {
            token: token.into(),
            expires_at,
            refresh_at: None,
        }
    }

    /// A token that expires `lifetime` from now.
    pub fn expires_in(token: impl Into<String>, lifetime: Duration) -> Self {
        let now = SystemTime::now();
        let expires_at = now
            .checked_add(lifetime.min(MAX_DELAY))
            .unwrap_or(now + MAX_DELAY);
        Self::new(token, expires_at)
    }

    /// The earliest instant the platform suggests refreshing, such as Azure
    /// Identity's `refresh_on`. It can only make a refresh happen sooner.
    pub fn with_refresh_at(mut self, refresh_at: SystemTime) -> Self {
        self.refresh_at = Some(refresh_at);
        self
    }

    /// The token, without the `Bearer ` prefix.
    pub fn token(&self) -> &str {
        &self.token
    }

    /// When the token expires.
    pub fn expires_at(&self) -> SystemTime {
        self.expires_at
    }

    /// When the platform suggested refreshing it, if it did.
    pub fn refresh_at(&self) -> Option<SystemTime> {
        self.refresh_at
    }
}

impl fmt::Debug for ExpiringToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExpiringToken")
            .field("token", &format_args!("{}", describe_token(&self.token)))
            .field(
                "expires_at",
                &format_args!("{}", fmt_instant(epoch_millis(self.expires_at))),
            )
            .field(
                "refresh_at",
                &format_args!(
                    "{}",
                    self.refresh_at
                        .map_or_else(|| "none".to_string(), |t| fmt_instant(epoch_millis(t)))
                ),
            )
            .finish()
    }
}

/// Obtains a new token from an identity platform: the source behind a
/// [`RefreshingTokenProvider`] (spec §4).
///
/// Implemented for closures `Fn() -> questdb::Result<ExpiringToken>`, so a
/// source can be a closure or a type of your own. Fetch the token however you
/// like: Azure Identity, an OAuth2 client-credentials or PKCE flow, a device
/// flow, a secrets vault.
///
/// - The provider calls `fetch_token` only on its own refresher thread, and
///   never concurrently with itself.
/// - It may block, but should bound its own network operations: 30 s per
///   attempt is recommended.
/// - Report a failure with [`Error::token_unavailable`], which says whether
///   retrying can succeed. Network failures, timeouts, HTTP 429 and 5xx are
///   retryable; missing or wrong configuration is not. Any other error counts
///   as retryable.
/// - An error message must not contain a token or a raw response body.
pub trait TokenSource: Send + Sync {
    /// Obtain a new token.
    fn fetch_token(&self) -> crate::Result<ExpiringToken>;
}

impl<F> TokenSource for F
where
    F: Fn() -> crate::Result<ExpiringToken> + Send + Sync,
{
    fn fetch_token(&self) -> crate::Result<ExpiringToken> {
        self()
    }
}

// ---------------------------------------------------------------------------
// Pure schedule and backoff (spec §5.2, §5.4)
// ---------------------------------------------------------------------------

/// The refresh instant of spec §5.2, in epoch milliseconds, for a token
/// received at `f` that expires at `e`, given a uniform sample `u` in [0, 1).
pub(crate) fn compute_refresh_at_millis(
    f: i64,
    e: i64,
    refresh_at: Option<i64>,
    u: f64,
    refresh_margin_ms: i64,
    min_refresh_interval_ms: i64,
    handout_floor_ms: i64,
) -> i64 {
    let life = e.saturating_sub(f);
    let half = life / 2;
    let margin = refresh_margin_ms.min(half);
    // the least time between a fetch and the refresh that follows it: p
    let spacing = min_refresh_interval_ms.min(half);
    let fraction = 0.45 + 0.10 * u.clamp(0.0, 1.0);
    let mut r = f.saturating_add((life as f64 * fraction) as i64);
    r = r.min(e.saturating_sub(margin));
    r = r.max(f.saturating_add(spacing));
    if let Some(hint) = refresh_at {
        r = r.min(hint.max(f.saturating_add(spacing)));
    }
    // Leave room to fetch before the hand-out cutoff, without breaking the
    // minimum spacing after the fetch.
    r.min(
        e.saturating_sub(handout_floor_ms)
            .saturating_sub(spacing)
            .max(f.saturating_add(spacing)),
    )
}

/// The retry delay after the `failures`-th consecutive failed fetch (spec
/// §5.4), in milliseconds, given a uniform sample `u` in [0, 1). At least 1 ms.
pub(crate) fn backoff_delay_millis(
    failures: u32,
    retry_after_ms: Option<i64>,
    u: f64,
    backoff_initial_ms: i64,
    backoff_max_ms: i64,
    retry_after_max_ms: i64,
) -> i64 {
    let shift = failures.saturating_sub(1).min(40);
    let base = backoff_initial_ms
        .checked_mul(1i64 << shift)
        .unwrap_or(backoff_max_ms)
        .min(backoff_max_ms);
    let half = base / 2;
    let mut delay = half.saturating_add((half as f64 * u.clamp(0.0, 1.0)) as i64);
    if let Some(retry_after) = retry_after_ms {
        delay = delay.max(retry_after.min(retry_after_max_ms));
    }
    // Millisecond rounding must not turn a positive backoff into an
    // immediate retry.
    delay.max(1)
}

// ---------------------------------------------------------------------------
// Clocks
// ---------------------------------------------------------------------------

/// Time source: expiry comparisons use the wall clock; delays and waits use a
/// monotonic clock (spec §5.6). A seam for tests.
pub(crate) trait Clock: Send + Sync {
    /// Wall-clock time in epoch milliseconds.
    fn wall_millis(&self) -> i64;
    /// Monotonic time since an arbitrary, fixed origin.
    fn monotonic(&self) -> Duration;
}

struct SystemClock {
    origin: Instant,
}

impl Clock for SystemClock {
    fn wall_millis(&self) -> i64 {
        epoch_millis(SystemTime::now())
    }

    fn monotonic(&self) -> Duration {
        self.origin.elapsed()
    }
}

pub(crate) fn epoch_millis(t: SystemTime) -> i64 {
    match t.duration_since(UNIX_EPOCH) {
        Ok(d) => i64::try_from(d.as_millis()).unwrap_or(i64::MAX),
        Err(e) => i64::try_from(e.duration().as_millis()).map_or(i64::MIN, |ms| -ms),
    }
}

pub(crate) fn system_time(epoch_ms: i64) -> SystemTime {
    let offset = Duration::from_millis(epoch_ms.unsigned_abs());
    let t = if epoch_ms >= 0 {
        UNIX_EPOCH.checked_add(offset)
    } else {
        UNIX_EPOCH.checked_sub(offset)
    };
    t.unwrap_or(UNIX_EPOCH)
}

/// `YYYY-MM-DDTHH:MM:SS.sssZ`, for log lines and errors.
pub(crate) fn fmt_instant(epoch_ms: i64) -> String {
    let days = epoch_ms.div_euclid(86_400_000);
    let ms_of_day = epoch_ms.rem_euclid(86_400_000);
    // Howard Hinnant's civil_from_days.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{:03}Z",
        ms_of_day / 3_600_000,
        ms_of_day / 60_000 % 60,
        ms_of_day / 1_000 % 60,
        ms_of_day % 1_000
    )
}

fn duration_millis(d: Duration) -> i64 {
    i64::try_from(d.min(MAX_DELAY).as_millis()).unwrap_or(i64::MAX)
}

fn delay_from_millis(ms: i64) -> Duration {
    Duration::from_millis(ms.max(0) as u64).min(MAX_DELAY)
}

/// A uniform sample in [0, 1) for the refresh and backoff jitter.
fn default_uniform() -> f64 {
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let mut hasher = RandomState::new().build_hasher();
    hasher.write_u64(COUNTER.fetch_add(1, Ordering::Relaxed));
    hasher.write_u128(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos()),
    );
    (hasher.finish() >> 11) as f64 / (1u64 << 53) as f64
}

// ---------------------------------------------------------------------------
// Observability (spec §5.7)
// ---------------------------------------------------------------------------

/// A failed fetch: its classification, sanitized message and time. Never
/// carries the token.
#[derive(Clone, PartialEq, Eq)]
pub struct FetchFailure {
    retryable: bool,
    retry_after: Option<Duration>,
    message: String,
    at_ms: i64,
}

impl FetchFailure {
    fn new(retryable: bool, retry_after: Option<Duration>, message: String, at_ms: i64) -> Self {
        let message = sanitize_error_text(&message);
        Self {
            retryable,
            retry_after,
            message: if message.is_empty() {
                "the token source failed without a message".to_string()
            } else {
                message
            },
            at_ms,
        }
    }

    fn from_error(err: &Error, at_ms: i64) -> Self {
        // An unclassified failure is retryable: the spec's rule when unsure.
        let (retryable, retry_after) = err
            .as_token_unavailable()
            .map_or((true, None), |t| (t.retryable(), t.retry_after()));
        Self::new(retryable, retry_after, err.msg().to_string(), at_ms)
    }

    /// Whether the source classified the failure as retryable.
    pub fn retryable(&self) -> bool {
        self.retryable
    }

    /// The source's suggested wait before retrying, if it gave one.
    pub fn retry_after(&self) -> Option<Duration> {
        self.retry_after
    }

    /// The failure message, sanitized and at most 256 characters.
    pub fn message(&self) -> &str {
        &self.message
    }

    /// When the fetch failed.
    pub fn at(&self) -> SystemTime {
        system_time(self.at_ms)
    }
}

impl fmt::Debug for FetchFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FetchFailure")
            .field("retryable", &self.retryable)
            .field("retry_after", &self.retry_after)
            .field("at", &format_args!("{}", fmt_instant(self.at_ms)))
            .field("message", &self.message)
            .finish()
    }
}

/// A snapshot of a [`RefreshingTokenProvider`]'s state. Never contains the
/// token.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct TokenProviderStatus {
    /// When the held token expires, if one is held.
    pub token_expires_at: Option<SystemTime>,
    /// When the last successful fetch completed.
    pub last_success_at: Option<SystemTime>,
    /// Failed fetches since the last successful one.
    pub consecutive_failures: u32,
    /// The most recent failed fetch. Kept after the source recovers.
    pub last_failure: Option<FetchFailure>,
    /// Whether the provider is closed.
    pub closed: bool,
}

// ---------------------------------------------------------------------------
// The provider
// ---------------------------------------------------------------------------

/// A shared, proactively refreshing cache in front of a [`TokenSource`].
///
/// Hand it to a sender, reader or [`QuestDb`](crate::QuestDb) pool as a
/// [`BearerTokenProvider`]. Every connection then reads the cached token, and
/// the provider fetches a new one in the background well before the current
/// one expires.
///
/// ```no_run
/// # fn fetch_from_idp() -> questdb::Result<(String, std::time::Duration)> { unimplemented!() }
/// use questdb::ingress::SenderBuilder;
/// use questdb::token_provider::{ExpiringToken, RefreshingTokenProvider};
///
/// # fn main() -> questdb::Result<()> {
/// let tokens = RefreshingTokenProvider::builder(|| -> questdb::Result<ExpiringToken> {
///     let (token, lifetime) = fetch_from_idp()?;
///     Ok(ExpiringToken::expires_in(token, lifetime))
/// })
/// .build()?;
/// let sender = SenderBuilder::from_conf("wss::addr=db.example.com:9000;")?
///     .bearer_token_provider(tokens.clone())?
///     .build()?;
/// # Ok(())
/// # }
/// ```
///
/// # Behaviour
///
/// - **Prefetch.** The first fetch starts as soon as the provider is built, on
///   its own refresher thread. [`await_ready`](Self::await_ready) gates
///   startup on it.
/// - **Proactive refresh.** After a fetch received at `f` with expiry `e`, the
///   next fetch is scheduled at a jittered half-life, `f + (e - f) * U(0.45,
///   0.55)`, no later than `e - min(refresh_margin, (e - f) / 2)` or the
///   platform's refresh hint, and no sooner than `f + p`, where `p =
///   min(min_refresh_interval, (e - f) / 2)`. It also starts at least `p`
///   before the token leaves its hand-out window at `e - handout_floor`,
///   unless that is sooner than `f + p`.
/// - **Hand-out.** A token is usable only while `now < e - handout_floor`.
///   [`token`](Self::token) returns a usable token at once, with no I/O. With
///   none, it starts a fetch, unless one is running or the provider is
///   backing off, and waits up to `cold_wait`. It then fails with a
///   [token-unavailable](Error::token_unavailable) error classified like the
///   most recent failed fetch, or retryable when none failed. Any number of
///   concurrent callers cause at most one fetch. A fetch whose token is
///   already within `handout_floor` of its expiry is a retryable failure whose
///   message names `handout_floor`.
/// - **Failures.** A failed fetch is retried with jittered exponential backoff
///   from `backoff_initial` up to `backoff_max`, honouring the source's
///   `retry_after` up to `retry_after_max`. Retries continue whatever the
///   classification, the current token is served while it remains usable,
///   and failures are logged at most once a minute per provider.
/// - **Forced refresh.** [`on_rejected`](Self::on_rejected) with HTTP 401 for
///   the current token starts a fetch, at most once per `forced_min_interval`,
///   and waits up to `forced_wait` for it. Clients call it when a server
///   rejects the token.
/// - **Close.** [`close`](Self::close) stops the refresher and wakes every
///   waiter; [`token`](Self::token) then fails as permanent. Clients never
///   close a provider: close it once every client using it is closed. When
///   the last clone is dropped, the provider closes itself.
///
/// Its [`Debug`](fmt::Debug) rendering, log lines and errors show at most a
/// token's length and an 8-hex-digit SHA-256 fingerprint.
#[derive(Clone)]
pub struct RefreshingTokenProvider {
    handle: Arc<Handle>,
}

/// The last clone of a provider closes it when dropped.
struct Handle {
    shared: Arc<Shared>,
}

impl Drop for Handle {
    fn drop(&mut self) {
        // In a forked child the state mutex may be held by a parent thread
        // that no longer exists: leave the provider alone rather than block.
        if !self.shared.is_inherited() {
            self.shared.close();
        }
    }
}

#[derive(Clone, Copy)]
struct Config {
    refresh_margin_ms: i64,
    min_refresh_interval_ms: i64,
    handout_floor_ms: i64,
    cold_wait: Duration,
    backoff_initial_ms: i64,
    backoff_max_ms: i64,
    retry_after_max_ms: i64,
    forced_min_interval: Duration,
    forced_wait: Duration,
}

struct Shared {
    name: String,
    source: Box<dyn TokenSource>,
    config: Config,
    clock: Arc<dyn Clock>,
    uniform: Box<dyn Fn() -> f64 + Send + Sync>,
    /// For a clock other than the system clock, waiters re-check it this often
    /// so that a test advancing it is noticed.
    clock_poll: Option<Duration>,
    state: Mutex<State>,
    /// Signalled on every fetch completion, schedule change and close.
    changed: Condvar,
    /// The process that built the provider. Its refresher thread does not
    /// survive `fork()`, and a parent thread may hold the state mutex at the
    /// fork, so a child never touches the state.
    creator_pid: u32,
}

#[derive(Default)]
struct State {
    closed: bool,
    held: Option<Held>,
    fetch_running: bool,
    completed_fetches: u64,
    consecutive_failures: u32,
    /// Monotonic instant before which no fetch may start, after failures.
    backoff_until: Option<Duration>,
    /// Monotonic instant at which the refresher starts the next fetch.
    next_fetch: Option<Duration>,
    last_failure: Option<FetchFailure>,
    last_success_ms: Option<i64>,
    last_failure_log: Option<Duration>,
    last_forced: Option<Duration>,
    short_window_warned: bool,
}

struct Held {
    token: String,
    expires_at_ms: i64,
    refresh_at_ms: i64,
    /// The scheduled refresh on the monotonic clock.
    refresh_due: Duration,
}

/// Why a cancellable wait for a token ended without one.
pub(crate) enum TokenWait {
    /// The caller's cancellation predicate fired.
    Cancelled,
    /// No usable token arrived, or the provider is closed.
    Failed(Error),
}

impl RefreshingTokenProvider {
    /// Default `refresh_margin`: upper bound on how close to expiry a
    /// scheduled refresh may run.
    pub const DEFAULT_REFRESH_MARGIN: Duration = Duration::from_secs(300);
    /// Default `min_refresh_interval`: lower bound on the time between a fetch
    /// and the next scheduled refresh.
    pub const DEFAULT_MIN_REFRESH_INTERVAL: Duration = Duration::from_secs(30);
    /// Default `handout_floor`: a token is usable only while `now < expires_at
    /// - handout_floor`.
    pub const DEFAULT_HANDOUT_FLOOR: Duration = Duration::from_secs(60);
    /// Default `cold_wait`: the longest a caller waits when no usable token is
    /// held.
    pub const DEFAULT_COLD_WAIT: Duration = Duration::from_secs(30);
    /// Default `backoff_initial`: the first retry delay after a failed fetch.
    pub const DEFAULT_BACKOFF_INITIAL: Duration = Duration::from_millis(500);
    /// Default `backoff_max`: the largest retry delay after failed fetches.
    pub const DEFAULT_BACKOFF_MAX: Duration = Duration::from_secs(60);
    /// Default `retry_after_max`: the cap applied to a source's `retry_after`.
    pub const DEFAULT_RETRY_AFTER_MAX: Duration = Duration::from_secs(300);
    /// Default `forced_min_interval`: minimum spacing between forced refreshes.
    pub const DEFAULT_FORCED_MIN_INTERVAL: Duration = Duration::from_secs(30);
    /// Default `forced_wait`: the longest [`on_rejected`](Self::on_rejected)
    /// waits for a forced refresh.
    pub const DEFAULT_FORCED_WAIT: Duration = Duration::from_secs(5);

    /// Start building a provider around `source`, a closure or a
    /// [`TokenSource`] of your own.
    pub fn builder<S: TokenSource + 'static>(source: S) -> RefreshingTokenProviderBuilder {
        RefreshingTokenProviderBuilder {
            source: Box::new(source),
            name: "token-provider".to_string(),
            refresh_margin: Self::DEFAULT_REFRESH_MARGIN,
            min_refresh_interval: Self::DEFAULT_MIN_REFRESH_INTERVAL,
            handout_floor: Self::DEFAULT_HANDOUT_FLOOR,
            cold_wait: Self::DEFAULT_COLD_WAIT,
            backoff_initial: Self::DEFAULT_BACKOFF_INITIAL,
            backoff_max: Self::DEFAULT_BACKOFF_MAX,
            retry_after_max: Self::DEFAULT_RETRY_AFTER_MAX,
            forced_min_interval: Self::DEFAULT_FORCED_MIN_INTERVAL,
            forced_wait: Self::DEFAULT_FORCED_WAIT,
            clock: None,
            uniform: None,
            spawn_refresher: true,
        }
    }

    fn shared(&self) -> &Shared {
        &self.handle.shared
    }

    /// A usable token: at once when one is held, otherwise after waiting up to
    /// `cold_wait` for a fetch.
    ///
    /// Fails with a [token-unavailable](Error::token_unavailable) error when no
    /// usable token arrives in time, classified like the most recent failed
    /// fetch (retryable when none failed), or as permanent once the provider
    /// is closed.
    pub fn token(&self) -> crate::Result<String> {
        match self.shared().token_until(None) {
            Ok(token) => Ok(token),
            Err(TokenWait::Failed(err)) => Err(err),
            Err(TokenWait::Cancelled) => Err(Error::token_unavailable(
                true,
                None,
                "the wait for a token was cancelled",
            )),
        }
    }

    /// [`token`](Self::token), ending the wait promptly with
    /// [`TokenWait::Cancelled`] once `cancel` returns true. Without `cancel`
    /// the wait is bounded by `cold_wait` alone.
    pub(crate) fn token_until(
        &self,
        cancel: Option<&dyn Fn() -> bool>,
    ) -> Result<String, TokenWait> {
        self.shared().token_until(cancel)
    }

    /// Forced refresh (spec §5.5). When a server answered HTTP 401 to `token`
    /// and that token is still the current one, start a fetch now -- joining
    /// one already running, and respecting failure backoff -- and wait up to
    /// `forced_wait` for it.
    ///
    /// Ignored for any other status, for a token that has already rotated,
    /// and within `forced_min_interval` of the previous forced refresh. A
    /// forced fetch that returns the same token counts as a normal success.
    pub fn on_rejected(&self, token: &str, http_status: u16) {
        self.shared().on_rejected(token, http_status, None);
    }

    /// [`on_rejected`](Self::on_rejected), giving up the wait once `cancel`
    /// returns true.
    pub(crate) fn on_rejected_until(
        &self,
        token: &str,
        http_status: u16,
        cancel: Option<&dyn Fn() -> bool>,
    ) {
        self.shared().on_rejected(token, http_status, cancel);
    }

    /// Wait until the provider holds a usable token, starting a fetch if none
    /// is running and the provider is not backing off. Use it to gate startup
    /// on the first fetch.
    ///
    /// Returns false on timeout or once the provider is closed.
    pub fn await_ready(&self, timeout: Duration) -> bool {
        self.shared().await_ready(timeout)
    }

    /// Stop the refresher and wake every waiter. Afterwards
    /// [`token`](Self::token) fails as permanent, and every client using the
    /// provider stops reconnecting. Idempotent.
    ///
    /// Clients never close a provider: close it once every client using it is
    /// closed.
    pub fn close(&self) {
        self.shared().close();
    }

    /// Whether [`close`](Self::close) has been called. A provider inherited
    /// across `fork()` counts as closed.
    pub fn is_closed(&self) -> bool {
        let shared = self.shared();
        shared.is_inherited() || shared.lock().closed
    }

    /// The non-secret label this provider uses in log lines and errors.
    pub fn name(&self) -> &str {
        &self.shared().name
    }

    /// A snapshot of the provider's state (spec §5.7). Never contains the
    /// token.
    pub fn status(&self) -> TokenProviderStatus {
        let shared = self.shared();
        if shared.is_inherited() {
            return TokenProviderStatus {
                token_expires_at: None,
                last_success_at: None,
                consecutive_failures: 0,
                last_failure: None,
                closed: true,
            };
        }
        let st = shared.lock();
        TokenProviderStatus {
            token_expires_at: st.held.as_ref().map(|h| system_time(h.expires_at_ms)),
            last_success_at: st.last_success_ms.map(system_time),
            consecutive_failures: st.consecutive_failures,
            last_failure: st.last_failure.clone(),
            closed: st.closed,
        }
    }
}

impl BearerTokenProvider for RefreshingTokenProvider {
    fn token(&self) -> crate::Result<String> {
        RefreshingTokenProvider::token(self)
    }

    fn on_rejected(&self, token: &str, http_status: u16) {
        RefreshingTokenProvider::on_rejected(self, token, http_status);
    }
}

impl fmt::Debug for RefreshingTokenProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let shared = self.shared();
        if shared.is_inherited() {
            return f
                .debug_struct("RefreshingTokenProvider")
                .field("name", &shared.name)
                .field("inherited_across_fork", &true)
                .finish();
        }
        let st = shared.lock();
        let mut d = f.debug_struct("RefreshingTokenProvider");
        d.field("name", &shared.name);
        match &st.held {
            Some(h) => {
                d.field("token", &format_args!("{}", describe_token(&h.token)));
                d.field(
                    "expires_at",
                    &format_args!("{}", fmt_instant(h.expires_at_ms)),
                );
                d.field(
                    "refresh_at",
                    &format_args!("{}", fmt_instant(h.refresh_at_ms)),
                );
            }
            None => {
                d.field("token", &format_args!("<none>"));
            }
        }
        d.field("consecutive_failures", &st.consecutive_failures);
        if let Some(failure) = &st.last_failure {
            d.field("last_failure", failure);
        }
        d.field("closed", &st.closed);
        d.finish()
    }
}

impl Shared {
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Wait for a state change, for at most `timeout` (`None`: indefinitely).
    /// `poll` shortens the wait so that a cancellation predicate is re-checked.
    fn wait<'a>(
        &self,
        guard: MutexGuard<'a, State>,
        timeout: Option<Duration>,
        poll: bool,
    ) -> MutexGuard<'a, State> {
        let slice = match (poll, self.clock_poll) {
            (true, Some(clock)) => Some(clock.min(CANCEL_POLL)),
            (true, None) => Some(CANCEL_POLL),
            (false, clock) => clock,
        };
        let timeout = match (timeout, slice) {
            (Some(t), Some(s)) => Some(t.min(s)),
            (None, s) => s,
            (t, None) => t,
        };
        match timeout {
            Some(t) => {
                self.changed
                    .wait_timeout(guard, t.min(MAX_DELAY))
                    .unwrap_or_else(PoisonError::into_inner)
                    .0
            }
            None => self
                .changed
                .wait(guard)
                .unwrap_or_else(PoisonError::into_inner),
        }
    }

    fn usable(&self, expires_at_ms: i64, wall_ms: i64) -> bool {
        wall_ms < expires_at_ms.saturating_sub(self.config.handout_floor_ms)
    }

    fn usable_token(&self, st: &State, wall_ms: i64) -> Option<String> {
        st.held
            .as_ref()
            .filter(|h| self.usable(h.expires_at_ms, wall_ms))
            .map(|h| h.token.clone())
    }

    fn in_backoff(st: &State, now: Duration) -> bool {
        st.backoff_until.is_some_and(|until| now < until)
    }

    /// Start a fetch now, unless one is running, one is already due, or the
    /// provider is backing off after failures.
    fn request_fetch_now_locked(&self, st: &mut State, now: Duration) {
        if st.closed || st.fetch_running || Self::in_backoff(st, now) {
            return;
        }
        if st.next_fetch.is_some_and(|due| due <= now) {
            return; // already due: the refresher starts it as soon as it can
        }
        st.next_fetch = Some(now);
        self.changed.notify_all();
    }

    fn is_inherited(&self) -> bool {
        std::process::id() != self.creator_pid
    }

    fn inherited_error(&self) -> Error {
        Error::token_provider_closed(format!(
            "token provider {} was inherited across fork and cannot be used in this process; \
             build a new provider in the child",
            self.name
        ))
    }

    fn closed_error(&self) -> Error {
        Error::token_provider_closed(format!("token provider {} is closed", self.name))
    }

    fn token_until(&self, cancel: Option<&dyn Fn() -> bool>) -> Result<String, TokenWait> {
        if self.is_inherited() {
            return Err(TokenWait::Failed(self.inherited_error()));
        }
        let mut st = self.lock();
        if st.closed {
            return Err(TokenWait::Failed(self.closed_error()));
        }
        let wall_ms = self.clock.wall_millis();
        if let Some(token) = self.usable_token(&st, wall_ms) {
            // Warm path: no I/O and no waiting. Only a refresh that is overdue
            // -- its scheduled fetch has not run, say because the host slept
            // through it -- starts a fetch, in the background.
            let now = self.clock.monotonic();
            let overdue = st
                .held
                .as_ref()
                .is_some_and(|h| wall_ms >= h.refresh_at_ms || now >= h.refresh_due);
            if overdue && !st.fetch_running && st.consecutive_failures == 0 {
                self.request_fetch_now_locked(&mut st, now);
            }
            return Ok(token);
        }

        // Cold path. Start one fetch -- unless one is running or the provider
        // is backing off -- and wait for it or for the fetches already
        // scheduled. Do not start another each time a fetch completes: a source
        // that keeps returning a token inside the hand-out floor would
        // otherwise be fetched in a tight loop for the whole wait.
        let start = self.clock.monotonic();
        let deadline = start.saturating_add(self.config.cold_wait.min(MAX_DELAY));
        self.request_fetch_now_locked(&mut st, start);
        loop {
            if st.closed {
                return Err(TokenWait::Failed(self.closed_error()));
            }
            if let Some(token) = self.usable_token(&st, self.clock.wall_millis()) {
                return Ok(token);
            }
            let now = self.clock.monotonic();
            // The earliest permitted fetch lies beyond the deadline: nothing
            // can arrive in time, so say so now.
            if !st.fetch_running
                && Self::in_backoff(&st, now)
                && st.backoff_until.is_some_and(|until| until > deadline)
            {
                return Err(TokenWait::Failed(self.unavailable_locked(&st, now, start)));
            }
            if now >= deadline {
                return Err(TokenWait::Failed(self.unavailable_locked(&st, now, start)));
            }
            if cancel.is_some_and(|cancel| cancel()) {
                return Err(TokenWait::Cancelled);
            }
            st = self.wait(st, Some(deadline - now), cancel.is_some());
        }
    }

    fn unavailable_locked(&self, st: &State, now: Duration, start: Duration) -> Error {
        let waited_ms = now.saturating_sub(start).as_millis();
        match st
            .last_failure
            .as_ref()
            .filter(|_| st.consecutive_failures > 0)
        {
            None => Error::token_unavailable(
                true,
                None,
                format!(
                    "no usable token from token provider {} after waiting {} ms",
                    self.name, waited_ms
                ),
            ),
            Some(failure) => {
                let retry_after = st
                    .backoff_until
                    .filter(|until| *until > now)
                    .map(|until| until - now);
                Error::token_unavailable(
                    failure.retryable,
                    retry_after,
                    format!(
                        "no usable token from token provider {} after waiting {} ms \
                         [retryable={}, consecutive_failures={}]: {}",
                        self.name,
                        waited_ms,
                        failure.retryable,
                        st.consecutive_failures,
                        failure.message
                    ),
                )
            }
        }
    }

    fn await_ready(&self, timeout: Duration) -> bool {
        if self.is_inherited() {
            return false;
        }
        let mut st = self.lock();
        let start = self.clock.monotonic();
        let deadline = start.saturating_add(timeout.min(MAX_DELAY));
        if self.usable_token(&st, self.clock.wall_millis()).is_none() {
            self.request_fetch_now_locked(&mut st, start);
        }
        loop {
            if st.closed {
                return false;
            }
            if self.usable_token(&st, self.clock.wall_millis()).is_some() {
                return true;
            }
            let now = self.clock.monotonic();
            if now >= deadline {
                return false;
            }
            st = self.wait(st, Some(deadline - now), false);
        }
    }

    fn on_rejected(&self, token: &str, http_status: u16, cancel: Option<&dyn Fn() -> bool>) {
        if http_status != 401 || self.is_inherited() {
            return;
        }
        let mut st = self.lock();
        if st.closed || st.held.as_ref().is_none_or(|h| h.token != token) {
            return; // stale: the token has already rotated
        }
        let now = self.clock.monotonic();
        if st
            .last_forced
            .is_some_and(|last| now.saturating_sub(last) < self.config.forced_min_interval)
        {
            return;
        }
        st.last_forced = Some(now);
        log::info!(
            "questdb: token provider {}: the server rejected the current token with HTTP 401, \
             refreshing early",
            self.name
        );
        let target = st.completed_fetches + 1;
        self.request_fetch_now_locked(&mut st, now);
        let deadline = now.saturating_add(self.config.forced_wait.min(MAX_DELAY));
        while !st.closed && st.completed_fetches < target {
            let now = self.clock.monotonic();
            if now >= deadline || cancel.is_some_and(|cancel| cancel()) {
                break;
            }
            st = self.wait(st, Some(deadline - now), cancel.is_some());
        }
    }

    fn close(&self) {
        if self.is_inherited() {
            return;
        }
        let mut st = self.lock();
        if st.closed {
            return;
        }
        st.closed = true;
        st.held = None;
        st.next_fetch = None;
        self.changed.notify_all();
        drop(st);
        log::debug!("questdb: token provider {} closed", self.name);
    }

    /// Block until a fetch is due, then claim it. False once closed.
    fn wait_for_due_fetch(&self) -> bool {
        let mut st = self.lock();
        loop {
            if st.closed {
                return false;
            }
            let now = self.clock.monotonic();
            match st.next_fetch {
                Some(due) if due <= now => {
                    st.next_fetch = None;
                    st.fetch_running = true;
                    return true;
                }
                Some(due) => st = self.wait(st, Some(due - now), false),
                None => st = self.wait(st, None, false),
            }
        }
    }

    /// Run one claimed fetch and apply its result.
    fn run_fetch(&self) {
        // Every failure, a panic included, is a failed fetch to retry with
        // backoff. (A `panic = "abort"` build cannot contain a panic.)
        let outcome = catch_unwind(AssertUnwindSafe(|| self.source.fetch_token()));
        let received_ms = self.clock.wall_millis();
        let received = self.clock.monotonic();
        let result = match outcome {
            Ok(Ok(token)) => match self.check_result(&token, received_ms) {
                None => Ok(token),
                Some(failure) => Err(failure),
            },
            Ok(Err(err)) => Err(FetchFailure::from_error(&err, received_ms)),
            Err(_) => Err(FetchFailure::new(
                true,
                None,
                "the token source panicked".to_string(),
                received_ms,
            )),
        };
        let mut logs = Vec::new();
        {
            let mut st = self.lock();
            st.fetch_running = false;
            st.completed_fetches += 1;
            if !st.closed {
                match result {
                    Ok(token) => {
                        self.on_success_locked(&mut st, token, received_ms, received, &mut logs)
                    }
                    Err(failure) => self.on_failure_locked(&mut st, failure, received, &mut logs),
                }
            }
            self.changed.notify_all();
        }
        for (level, line) in logs {
            log::log!(level, "{line}");
        }
    }

    /// A result the provider must treat as a retryable failure (spec §4).
    fn check_result(&self, token: &ExpiringToken, received_ms: i64) -> Option<FetchFailure> {
        let failure = |message: String| Some(FetchFailure::new(true, None, message, received_ms));
        if token.token.trim().is_empty() {
            return failure("the token source returned an empty or blank token".to_string());
        }
        if !token.token.bytes().all(|b| (0x20..=0x7e).contains(&b)) {
            return failure(
                "the token source returned a token with a character outside printable ASCII"
                    .to_string(),
            );
        }
        let expires_ms = epoch_millis(token.expires_at);
        if expires_ms <= received_ms {
            return failure(format!(
                "the token source returned a token that expired at {}, not after it was \
                 received at {}",
                fmt_instant(expires_ms),
                fmt_instant(received_ms)
            ));
        }
        if !self.usable(expires_ms, received_ms) {
            // Never usable, so it could never be handed out. Recorded as a
            // success, it would leave every caller waiting out cold_wait for
            // an error that names no cause.
            return failure(format!(
                "the token source returned a token that expires {} ms after it was received, \
                 within handout_floor ({} ms): it can never be handed out; issue longer-lived \
                 tokens or lower handout_floor",
                expires_ms - received_ms,
                self.config.handout_floor_ms
            ));
        }
        None
    }

    fn on_success_locked(
        &self,
        st: &mut State,
        token: ExpiringToken,
        received_ms: i64,
        received: Duration,
        logs: &mut Vec<(log::Level, String)>,
    ) {
        let cfg = &self.config;
        let expires_at_ms = epoch_millis(token.expires_at);
        let refresh_at_ms = compute_refresh_at_millis(
            received_ms,
            expires_at_ms,
            token.refresh_at.map(epoch_millis),
            (self.uniform)(),
            cfg.refresh_margin_ms,
            cfg.min_refresh_interval_ms,
            cfg.handout_floor_ms,
        );
        let delay = delay_from_millis(refresh_at_ms.saturating_sub(received_ms));
        let failures = st.consecutive_failures;
        let described = describe_token(&token.token);
        st.held = Some(Held {
            token: token.token,
            expires_at_ms,
            refresh_at_ms,
            refresh_due: received.saturating_add(delay),
        });
        st.last_success_ms = Some(received_ms);
        st.consecutive_failures = 0;
        st.backoff_until = None;
        st.next_fetch = Some(received.saturating_add(delay));
        if failures > 0 {
            logs.push((
                log::Level::Info,
                format!(
                    "questdb: token provider {}: fetch succeeded after {} consecutive \
                     failure(s) [token={}, expires_at={}]",
                    self.name,
                    failures,
                    described,
                    fmt_instant(expires_at_ms)
                ),
            ));
        } else {
            logs.push((
                log::Level::Debug,
                format!(
                    "questdb: token provider {}: fetched [token={}, expires_at={}, refresh_at={}]",
                    self.name,
                    described,
                    fmt_instant(expires_at_ms),
                    fmt_instant(refresh_at_ms)
                ),
            ));
        }
        let handout_end = expires_at_ms.saturating_sub(cfg.handout_floor_ms);
        if !st.short_window_warned && refresh_at_ms > handout_end {
            // The token stops being handed out before the next refresh may
            // run, so callers will wait for a fetch. Say why, once.
            st.short_window_warned = true;
            logs.push((
                log::Level::Warn,
                format!(
                    "questdb: token provider {}: a token from the source is handed out for only \
                     {} ms -- it expires {} ms after it arrives and handout_floor is {} ms -- but \
                     the next refresh cannot run sooner than {} ms after a fetch, so callers wait \
                     for a fetch whenever a token stops being usable; lower handout_floor or \
                     min_refresh_interval, or issue longer-lived tokens",
                    self.name,
                    handout_end - received_ms,
                    expires_at_ms - received_ms,
                    cfg.handout_floor_ms,
                    refresh_at_ms - received_ms
                ),
            ));
        }
    }

    fn on_failure_locked(
        &self,
        st: &mut State,
        failure: FetchFailure,
        received: Duration,
        logs: &mut Vec<(log::Level, String)>,
    ) {
        let cfg = &self.config;
        let failures = st.consecutive_failures.saturating_add(1);
        st.consecutive_failures = failures;
        let delay_ms = backoff_delay_millis(
            failures,
            failure.retry_after.map(duration_millis),
            (self.uniform)(),
            cfg.backoff_initial_ms,
            cfg.backoff_max_ms,
            cfg.retry_after_max_ms,
        );
        let delay = delay_from_millis(delay_ms);
        st.backoff_until = Some(received.saturating_add(delay));
        st.next_fetch = Some(received.saturating_add(delay));
        let log_now = st
            .last_failure_log
            .is_none_or(|last| received.saturating_sub(last) >= FAILURE_LOG_INTERVAL);
        if log_now {
            st.last_failure_log = Some(received);
            logs.push((
                log::Level::Warn,
                format!(
                    "questdb: token provider {}: fetch failed [retryable={}, \
                     consecutive_failures={}, retry_in_ms={}]: {}",
                    self.name, failure.retryable, failures, delay_ms, failure.message
                ),
            ));
        }
        st.last_failure = Some(failure);
    }
}

fn refresher_loop(shared: Arc<Shared>) {
    while shared.wait_for_due_fetch() {
        shared.run_fetch();
    }
}

/// Builds a [`RefreshingTokenProvider`]. Every parameter defaults to the
/// specification's value (§5.1).
pub struct RefreshingTokenProviderBuilder {
    source: Box<dyn TokenSource>,
    name: String,
    refresh_margin: Duration,
    min_refresh_interval: Duration,
    handout_floor: Duration,
    cold_wait: Duration,
    backoff_initial: Duration,
    backoff_max: Duration,
    retry_after_max: Duration,
    forced_min_interval: Duration,
    forced_wait: Duration,
    clock: Option<Arc<dyn Clock>>,
    uniform: Option<Box<dyn Fn() -> f64 + Send + Sync>>,
    spawn_refresher: bool,
}

impl RefreshingTokenProviderBuilder {
    /// A non-secret label for log lines, errors and the refresher thread.
    /// Default `token-provider`.
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.name = name.into();
        self
    }

    /// Upper bound on how close to expiry a scheduled refresh may run.
    /// Default 5 min.
    pub fn refresh_margin(mut self, value: Duration) -> Self {
        self.refresh_margin = value;
        self
    }

    /// Lower bound on the time between a fetch and the next scheduled
    /// refresh. Default 30 s.
    pub fn min_refresh_interval(mut self, value: Duration) -> Self {
        self.min_refresh_interval = value;
        self
    }

    /// A token is usable only while `now < expires_at - handout_floor`.
    /// Default 60 s.
    ///
    /// A fetched token that is not usable on arrival counts as a failed fetch,
    /// so a source whose tokens live no longer than this needs a lower value.
    /// A token handed out for less than `min_refresh_interval` cannot be
    /// refreshed while it is still handed out, so callers then wait for a
    /// fetch whenever it stops being usable.
    pub fn handout_floor(mut self, value: Duration) -> Self {
        self.handout_floor = value;
        self
    }

    /// The longest [`token`](RefreshingTokenProvider::token) waits when no
    /// usable token is held. Default 30 s.
    pub fn cold_wait(mut self, value: Duration) -> Self {
        self.cold_wait = value;
        self
    }

    /// First retry delay after a failed fetch. Default 500 ms; must be
    /// positive.
    pub fn backoff_initial(mut self, value: Duration) -> Self {
        self.backoff_initial = value;
        self
    }

    /// Largest retry delay after failed fetches. Default 60 s; must be at
    /// least `backoff_initial`.
    pub fn backoff_max(mut self, value: Duration) -> Self {
        self.backoff_max = value;
        self
    }

    /// Cap applied to a source's `retry_after`. Default 5 min.
    pub fn retry_after_max(mut self, value: Duration) -> Self {
        self.retry_after_max = value;
        self
    }

    /// Minimum spacing between forced refreshes. Default 30 s.
    pub fn forced_min_interval(mut self, value: Duration) -> Self {
        self.forced_min_interval = value;
        self
    }

    /// The longest [`on_rejected`](RefreshingTokenProvider::on_rejected)
    /// waits for a forced refresh. Default 5 s.
    pub fn forced_wait(mut self, value: Duration) -> Self {
        self.forced_wait = value;
        self
    }

    /// Test seam: the clock for expiry comparisons, delays and waits.
    #[cfg(test)]
    pub(crate) fn clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.clock = Some(clock);
        self
    }

    /// Test seam: uniform samples in [0, 1) for the jitter.
    #[cfg(test)]
    pub(crate) fn uniform(mut self, uniform: impl Fn() -> f64 + Send + Sync + 'static) -> Self {
        self.uniform = Some(Box::new(uniform));
        self
    }

    /// Test seam: start no refresher thread; the test runs due fetches with
    /// [`RefreshingTokenProvider::run_due_fetch`].
    #[cfg(test)]
    pub(crate) fn manual(mut self) -> Self {
        self.spawn_refresher = false;
        self
    }

    /// Build the provider and start its first fetch in the background.
    pub fn build(self) -> crate::Result<RefreshingTokenProvider> {
        if self.name.trim().is_empty() {
            return Err(Error::new(
                ErrorCode::ConfigError,
                "token provider name must not be empty",
            ));
        }
        if self.backoff_initial.is_zero() {
            return Err(Error::new(
                ErrorCode::ConfigError,
                "backoff_initial must be greater than zero",
            ));
        }
        if self.backoff_max < self.backoff_initial {
            return Err(Error::new(
                ErrorCode::ConfigError,
                format!(
                    "backoff_max must be at least backoff_initial \
                     [backoff_max={:?}, backoff_initial={:?}]",
                    self.backoff_max, self.backoff_initial
                ),
            ));
        }
        let config = Config {
            refresh_margin_ms: duration_millis(self.refresh_margin),
            min_refresh_interval_ms: duration_millis(self.min_refresh_interval),
            handout_floor_ms: duration_millis(self.handout_floor),
            cold_wait: self.cold_wait.min(MAX_DELAY),
            backoff_initial_ms: duration_millis(self.backoff_initial).max(1),
            backoff_max_ms: duration_millis(self.backoff_max).max(1),
            retry_after_max_ms: duration_millis(self.retry_after_max),
            forced_min_interval: self.forced_min_interval.min(MAX_DELAY),
            forced_wait: self.forced_wait.min(MAX_DELAY),
        };
        let clock_poll = self.clock.as_ref().map(|_| CANCEL_POLL);
        let clock = self.clock.unwrap_or_else(|| {
            Arc::new(SystemClock {
                origin: Instant::now(),
            })
        });
        let name = crate::display_text::sanitize_display_text(&self.name);
        let shared = Arc::new(Shared {
            name,
            source: self.source,
            config,
            uniform: self.uniform.unwrap_or_else(|| Box::new(default_uniform)),
            clock_poll,
            state: Mutex::new(State {
                // Prefetch: the first fetch starts at once.
                next_fetch: Some(clock.monotonic()),
                ..State::default()
            }),
            changed: Condvar::new(),
            creator_pid: std::process::id(),
            clock,
        });
        if self.spawn_refresher {
            let refresher = Arc::clone(&shared);
            std::thread::Builder::new()
                .name("questdb-token-refresh".to_string())
                .spawn(move || refresher_loop(refresher))
                .map_err(|err| {
                    Error::new(
                        ErrorCode::SocketError,
                        format!("could not start the token refresher thread: {err}"),
                    )
                })?;
        }
        Ok(RefreshingTokenProvider {
            handle: Arc::new(Handle { shared }),
        })
    }
}

impl fmt::Debug for RefreshingTokenProviderBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RefreshingTokenProviderBuilder")
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
impl RefreshingTokenProvider {
    /// Run the next fetch if one is due by the provider's clock.
    pub(crate) fn run_due_fetch(&self) -> bool {
        let shared = self.shared();
        {
            let mut st = shared.lock();
            let now = shared.clock.monotonic();
            if st.closed || st.fetch_running || st.next_fetch.is_none_or(|due| due > now) {
                return false;
            }
            st.next_fetch = None;
            st.fetch_running = true;
        }
        shared.run_fetch();
        true
    }

    /// How long until the next scheduled fetch, if one is scheduled.
    pub(crate) fn scheduled_in(&self) -> Option<Duration> {
        let shared = self.shared();
        let st = shared.lock();
        let now = shared.clock.monotonic();
        st.next_fetch.map(|due| due.saturating_sub(now))
    }
}

#[cfg(test)]
#[path = "refreshing_tests.rs"]
mod tests;
