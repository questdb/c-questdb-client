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

//! What a QWP/WebSocket connection does when a server rejects the credential
//! it presented while reconnecting: HTTP 401 or 403 on the upgrade
//! (design/qwp-token-provider-spec.md §8.3).
//!
//! - **Initialization**, before the first connection: terminal, so a wrong
//!   credential reaches the caller (`reconnect_error_is_terminal`).
//! - **An established sender** retries indefinitely with capped backoff
//!   (decision D1). An identity-provider or key-set outage makes a server
//!   answer 401 for a while, and store-and-forward must not drop a live
//!   producer over it. Every failed round is reported as an `auth_failed`
//!   connection event, and an ACK wait that times out meanwhile names the
//!   rejection.
//! - **An orphan drainer** with a rotating credential rides the rejections
//!   out, then retires the slot: once [`OrphanAuthRideOut::MIN_REJECTIONS`]
//!   rejections have persisted for `min(reconnect_max_duration, 5 min)`, or
//!   after [`OrphanAuthRideOut::MAX_REJECTIONS_PER_EPISODE`]. With a static
//!   credential it retires the slot at the first rejection.
//!
//! Retiring a slot is this client's counterpart of the Java client's
//! quarantine. The drainer stops draining the slot for the rest of the session
//! and records why in its `.last_error`, but writes no `.failed` sentinel: the
//! slot stays on disk, and the next session tries it again.

use std::time::{Duration, Instant};

use crate::{Error, ErrorCode};

/// Whether `err` is a server's rejection of the credential presented on a
/// WebSocket upgrade: HTTP 401 or 403, the spec's *auth-rejected* class
/// (§8.1). A token provider that fails to supply a credential is not one, nor
/// is a closed provider, although both can carry `AuthError`.
pub(crate) fn is_upgrade_auth_rejection(err: &Error) -> bool {
    err.code() == ErrorCode::AuthError && matches!(err.ws_http_status(), Some(401 | 403))
}

/// The shortest spacing of the warning an established sender logs while it
/// rides out rejections, as the Java client's reconnect loop throttles it.
const ESTABLISHED_WARNING_INTERVAL: Duration = Duration::from_secs(5);

/// How a send core treats a server's 401 or 403 on a reconnect upgrade that
/// is not terminal by itself. Initialization never gets here: it ends on the
/// first rejection.
#[derive(Debug)]
pub(crate) enum AuthRejectionPolicy {
    /// A sender that has connected keeps retrying (D1), and logs a throttled
    /// warning besides the per-round connection event.
    Established { last_warning: Option<Instant> },
    /// An orphan drainer rides the rejections out, then retires the slot.
    Orphan(OrphanAuthRideOut),
}

impl Default for AuthRejectionPolicy {
    fn default() -> Self {
        Self::Established { last_warning: None }
    }
}

impl AuthRejectionPolicy {
    /// A reconnect attempt failed with `err`, which is not terminal by itself.
    /// Returns the error to stop with when the policy gives up.
    pub(crate) fn on_failed_attempt(&mut self, err: &Error, now: Instant) -> Option<Error> {
        match self {
            Self::Established { last_warning } => {
                if is_upgrade_auth_rejection(err)
                    && last_warning.is_none_or(|at| {
                        now.saturating_duration_since(at) >= ESTABLISHED_WARNING_INTERVAL
                    })
                {
                    *last_warning = Some(now);
                    log::warn!(
                        "questdb: QWP/WebSocket reconnect rejected by the server: {err}. \
                         The sender keeps reconnecting with capped backoff and keeps the \
                         unacknowledged data until the credential is accepted again; close \
                         it to stop."
                    );
                }
                None
            }
            Self::Orphan(ride_out) => {
                if is_upgrade_auth_rejection(err) {
                    ride_out.on_rejection(err, now)
                } else {
                    ride_out.on_other_failure();
                    None
                }
            }
        }
    }

    /// The server acknowledged data it had not acknowledged before.
    pub(crate) fn on_ack_progress(&mut self) {
        if let Self::Orphan(ride_out) = self {
            ride_out.on_ack_progress();
        }
    }
}

/// An orphan drainer's ride-out of credential rejections, for one slot
/// (design/qwp-token-provider-spec.md §8.3, "Ride out, then quarantine").
///
/// It spans the slot's whole drain: the rejections that keep the drainer from
/// adopting the slot and those that end a mid-drain reconnect count alike.
///
/// - **Episode.** Only acknowledgement progress ends an episode: a successful
///   connect delivers nothing, so a cluster that accepts the upgrade and then
///   drops the connection does not reset the count.
/// - **Persistence.** The rejections must persist for the dwell: a failure of
///   another class in between (a transport error, a role reject, a token
///   provider that cannot supply a credential) restarts that clock, because
///   time the drainer spent unable to reach a server is not time the
///   credential spent rejected. The count is kept, so a credential that
///   alternates between rejected and unreachable still reaches the cap.
/// - **Static credentials** are rejected the same way on every attempt, so
///   the first rejection retires the slot.
#[derive(Debug, Clone)]
pub(crate) struct OrphanAuthRideOut {
    /// The slot, for log lines.
    slot: String,
    rotating: bool,
    dwell: Duration,
    rejections: u32,
    first_rejection_at: Option<Instant>,
}

impl OrphanAuthRideOut {
    /// Rejections a rotating credential gets before the slot may be retired,
    /// so that a rejected token is replaced, and a server's key-set cache can
    /// catch up, a few times over.
    pub(crate) const MIN_REJECTIONS: u32 = 6;
    /// Rejections in one episode that retire the slot whatever the dwell says.
    /// Failures of other classes restart the dwell, so a cluster alternating
    /// between rejecting the credential and being unreachable could otherwise
    /// keep the slot, and a drainer worker, forever.
    pub(crate) const MAX_REJECTIONS_PER_EPISODE: u32 = 256;
    /// Longest dwell, whatever `reconnect_max_duration` says: a large value
    /// there asks for persistent reconnects, not for hiding a rejected
    /// credential from an operator for longer.
    pub(crate) const MAX_DWELL: Duration = Duration::from_secs(300);

    pub(crate) fn new(
        slot: impl Into<String>,
        rotating_credential: bool,
        reconnect_max_duration: Duration,
    ) -> Self {
        Self {
            slot: slot.into(),
            rotating: rotating_credential,
            dwell: reconnect_max_duration.min(Self::MAX_DWELL),
            rejections: 0,
            first_rejection_at: None,
        }
    }

    /// The server rejected the credential with `err`. Returns the error to
    /// retire the slot with, or `None` to retry after backoff.
    pub(crate) fn on_rejection(&mut self, err: &Error, now: Instant) -> Option<Error> {
        self.rejections = self.rejections.saturating_add(1);
        let first = *self.first_rejection_at.get_or_insert(now);
        let persisted = now.saturating_duration_since(first);
        if self.rotating
            && (self.rejections < Self::MIN_REJECTIONS || persisted < self.dwell)
            && self.rejections < Self::MAX_REJECTIONS_PER_EPISODE
        {
            log::warn!(
                "questdb: QWP/WebSocket orphan slot {}: the server rejected the rotating \
                 credential [rejections={}/{}, persisted_ms={}/{}]; retrying with a freshly \
                 pulled token after backoff: {err}",
                self.slot,
                self.rejections,
                Self::MIN_REJECTIONS,
                persisted.as_millis(),
                self.dwell.as_millis()
            );
            return None;
        }
        let msg = if self.rotating {
            format!(
                "orphan slot given up for this session after the server rejected the \
                 rotating credential {} times over {} ms; the slot stays on disk for the \
                 next session: {}",
                self.rejections,
                persisted.as_millis(),
                err.msg()
            )
        } else {
            format!(
                "orphan slot given up for this session because the server rejected the \
                 static credential; the slot stays on disk for the next session: {}",
                err.msg()
            )
        };
        log::error!("questdb: QWP/WebSocket orphan slot {}: {msg}", self.slot);
        Some(err.clone().reclassified(ErrorCode::AuthError, msg))
    }

    /// A reconnect failed for another reason: restart the persistence clock,
    /// keep the count.
    pub(crate) fn on_other_failure(&mut self) {
        self.first_rejection_at = None;
    }

    /// The server acknowledged new data: the episode is over.
    pub(crate) fn on_ack_progress(&mut self) {
        self.rejections = 0;
        self.first_rejection_at = None;
    }

    #[cfg(test)]
    pub(crate) fn rejections(&self) -> u32 {
        self.rejections
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rejection(status: u16) -> Error {
        Error::new(
            ErrorCode::AuthError,
            format!("WebSocket upgrade authentication failed: HTTP status {status}"),
        )
        .with_ws_http_status(status)
    }

    fn at(start: Instant, millis: u64) -> Instant {
        start + Duration::from_millis(millis)
    }

    #[test]
    fn only_an_upgrade_401_or_403_is_an_auth_rejection() {
        assert!(is_upgrade_auth_rejection(&rejection(401)));
        assert!(is_upgrade_auth_rejection(&rejection(403)));
        // A closed provider also reports AuthError, but no server answered.
        assert!(!is_upgrade_auth_rejection(&Error::token_provider_closed(
            "token provider p is closed"
        )));
        assert!(!is_upgrade_auth_rejection(
            &Error::new(
                ErrorCode::SocketError,
                "WebSocket upgrade failed: HTTP status 503"
            )
            .with_ws_http_status(503)
        ));
        // Reclassifying keeps the status, so a retry-budget wrapper still
        // counts as the rejection it wraps.
        let wrapped = rejection(401).reclassified(ErrorCode::AuthError, "budget exhausted");
        assert!(is_upgrade_auth_rejection(&wrapped));
    }

    #[test]
    fn a_rotating_credential_needs_six_rejections() {
        let start = Instant::now();
        let mut ride_out = OrphanAuthRideOut::new("slot", true, Duration::from_secs(60));
        // Five rejections spread over ten minutes, far past the dwell.
        for n in 0..5 {
            assert!(
                ride_out
                    .on_rejection(&rejection(401), at(start, n * 150_000))
                    .is_none(),
                "fewer than six rejections never retire the slot"
            );
        }
        let err = ride_out
            .on_rejection(&rejection(403), at(start, 750_000))
            .expect("retired");
        assert_eq!(err.code(), ErrorCode::AuthError);
        assert!(err.msg().contains("rotating credential 6 times"), "{err}");
        assert!(err.msg().contains("HTTP status 403"), "{err}");
        assert_eq!(err.ws_http_status(), Some(403));
    }

    #[test]
    fn the_rejections_must_persist_for_the_dwell() {
        let start = Instant::now();
        let mut ride_out = OrphanAuthRideOut::new("slot", true, Duration::from_secs(60));
        for n in 0..6 {
            assert!(
                ride_out
                    .on_rejection(&rejection(401), at(start, n))
                    .is_none()
            );
        }
        // The clock started at the first rejection.
        assert!(
            ride_out
                .on_rejection(&rejection(401), at(start, 59_999))
                .is_none()
        );
        let err = ride_out
            .on_rejection(&rejection(401), at(start, 60_000))
            .expect("retired");
        assert!(err.msg().contains("rotating credential 8 times"), "{err}");
        assert!(err.msg().contains("over 60000 ms"), "{err}");
    }

    #[test]
    fn the_dwell_is_capped_at_five_minutes() {
        let start = Instant::now();
        let mut ride_out = OrphanAuthRideOut::new("slot", true, Duration::MAX);
        for _ in 0..5 {
            assert!(ride_out.on_rejection(&rejection(401), start).is_none());
        }
        let just_short = at(start, 299_999);
        assert!(ride_out.on_rejection(&rejection(401), just_short).is_none());
        assert!(
            ride_out
                .on_rejection(&rejection(401), at(start, 300_000))
                .is_some()
        );
    }

    #[test]
    fn a_static_credential_retires_the_slot_at_the_first_rejection() {
        let mut ride_out = OrphanAuthRideOut::new("slot", false, Duration::from_secs(60));
        let err = ride_out
            .on_rejection(&rejection(401), Instant::now())
            .expect("retired");
        assert!(err.msg().contains("static credential"), "{err}");
    }

    #[test]
    fn another_failure_restarts_the_clock_but_keeps_the_count() {
        let start = Instant::now();
        let mut ride_out = OrphanAuthRideOut::new("slot", true, Duration::from_secs(10));
        for n in 0..6 {
            assert!(
                ride_out
                    .on_rejection(&rejection(401), at(start, n))
                    .is_none()
            );
        }
        assert_eq!(ride_out.rejections(), 6);
        // A transport failure between rejections: the next rejection starts a
        // new run, which has not persisted yet.
        ride_out.on_other_failure();
        assert!(
            ride_out
                .on_rejection(&rejection(401), at(start, 60_000))
                .is_none()
        );
        assert_eq!(ride_out.rejections(), 7);
        // Ten seconds into the new run it is retired.
        assert!(
            ride_out
                .on_rejection(&rejection(401), at(start, 70_000))
                .is_some()
        );
    }

    #[test]
    fn rejections_alternating_with_other_failures_reach_the_cap() {
        let start = Instant::now();
        let mut ride_out = OrphanAuthRideOut::new("slot", true, Duration::from_secs(10));
        let mut retired_at = None;
        for n in 1..=OrphanAuthRideOut::MAX_REJECTIONS_PER_EPISODE {
            if ride_out
                .on_rejection(&rejection(401), at(start, u64::from(n) * 60_000))
                .is_some()
            {
                retired_at = Some(n);
                break;
            }
            ride_out.on_other_failure();
        }
        assert_eq!(
            retired_at,
            Some(OrphanAuthRideOut::MAX_REJECTIONS_PER_EPISODE)
        );
    }

    #[test]
    fn ack_progress_ends_the_episode() {
        let start = Instant::now();
        let mut ride_out = OrphanAuthRideOut::new("slot", true, Duration::ZERO);
        for n in 0..5 {
            assert!(
                ride_out
                    .on_rejection(&rejection(401), at(start, n))
                    .is_none()
            );
        }
        ride_out.on_ack_progress();
        assert_eq!(ride_out.rejections(), 0);
        for n in 0..5 {
            assert!(
                ride_out
                    .on_rejection(&rejection(401), at(start, n))
                    .is_none()
            );
        }
        assert!(
            ride_out
                .on_rejection(&rejection(401), at(start, 9))
                .is_some()
        );
    }

    #[test]
    fn an_established_sender_never_gives_up() {
        let mut policy = AuthRejectionPolicy::default();
        let start = Instant::now();
        for n in 0..1_000 {
            assert!(
                policy
                    .on_failed_attempt(&rejection(401 + 2 * (n % 2)), at(start, u64::from(n)))
                    .is_none()
            );
        }
        policy.on_ack_progress();
    }

    #[test]
    fn an_orphan_policy_counts_only_rejections() {
        let start = Instant::now();
        let mut policy =
            AuthRejectionPolicy::Orphan(OrphanAuthRideOut::new("slot", true, Duration::ZERO));
        let transport = Error::new(ErrorCode::SocketError, "connection refused");
        for n in 0..5 {
            assert!(
                policy
                    .on_failed_attempt(&rejection(401), at(start, n))
                    .is_none()
            );
            assert!(policy.on_failed_attempt(&transport, at(start, n)).is_none());
        }
        assert!(
            policy
                .on_failed_attempt(&rejection(401), at(start, 10))
                .is_some()
        );
    }
}
