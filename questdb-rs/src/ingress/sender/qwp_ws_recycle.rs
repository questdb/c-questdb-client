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

//! Shared settings and count-triggered symbol dictionary recycle policy.

use crate::error::{self, Result};
use std::time::{Duration, Instant};

/// Shared with the wire worker. Claiming maintenance and entering reconnect use
/// the same compare/exchange, so a rejected claim cannot become a latent park.
#[cfg(feature = "sync-sender-qwp-ws")]
#[derive(Debug)]
pub(super) struct RecycleLink(std::sync::atomic::AtomicU8);

#[cfg(feature = "sync-sender-qwp-ws")]
const LINK_LIVE: u8 = 0;
#[cfg(feature = "sync-sender-qwp-ws")]
const LINK_RECONNECTING: u8 = 1;
#[cfg(feature = "sync-sender-qwp-ws")]
const LINK_PARKING: u8 = 2;

#[cfg(feature = "sync-sender-qwp-ws")]
impl RecycleLink {
    pub(super) fn new(live: bool) -> Self {
        Self(std::sync::atomic::AtomicU8::new(if live {
            LINK_LIVE
        } else {
            LINK_RECONNECTING
        }))
    }

    pub(super) fn claim(&self) -> bool {
        self.0
            .compare_exchange(
                LINK_LIVE,
                LINK_PARKING,
                std::sync::atomic::Ordering::AcqRel,
                std::sync::atomic::Ordering::Acquire,
            )
            .is_ok()
    }

    pub(super) fn enter_reconnect(&self) -> bool {
        self.0
            .compare_exchange(
                LINK_LIVE,
                LINK_RECONNECTING,
                std::sync::atomic::Ordering::AcqRel,
                std::sync::atomic::Ordering::Acquire,
            )
            .map_or_else(|state| state == LINK_RECONNECTING, |_| true)
    }

    pub(super) fn connected(&self) {
        let _ = self.0.compare_exchange(
            LINK_RECONNECTING,
            LINK_LIVE,
            std::sync::atomic::Ordering::AcqRel,
            std::sync::atomic::Ordering::Acquire,
        );
    }

    pub(super) fn restart(&self) {
        self.0
            .store(LINK_RECONNECTING, std::sync::atomic::Ordering::Release);
    }
}

/// Non-cloneable proof that the old wire worker and its storage work have exited.
/// Dropping a permit does not cancel maintenance or reopen publication. The
/// retained coordinator can issue a replacement; that invalidates earlier proofs.
#[cfg(feature = "sync-sender-qwp-ws")]
#[derive(Debug)]
pub(crate) struct RecyclePermit {
    pub(super) owner: std::sync::Arc<RecycleLink>,
    pub(super) generation: u64,
    pub(super) boundary: Option<u64>,
}

#[cfg(feature = "sync-sender-qwp-ws")]
#[derive(Debug)]
pub(super) struct PendingRecycle {
    pub(super) boundary: Option<u64>,
    pub(super) wait_spent: bool,
    pub(super) quiesced: bool,
    pub(super) installed: bool,
    pub(super) generation: u64,
}

const MAX_THRESHOLD: usize = 1_000_000;
const MAX_WAIT_MILLIS: u64 = 9_223_372_036_854;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct RecycleSettings {
    pub(crate) enabled: bool,
    pub(crate) threshold: usize,
    pub(crate) max_wait: Duration,
}

impl Default for RecycleSettings {
    fn default() -> Self {
        Self {
            enabled: true,
            threshold: 100_000,
            max_wait: Duration::from_millis(2_000),
        }
    }
}

impl RecycleSettings {
    pub(crate) fn validate(self) -> Result<Self> {
        if !(1..=MAX_THRESHOLD).contains(&self.threshold) {
            return Err(error::fmt!(
                ConfigError,
                "\"symbol_dict_reset_threshold\" must be between 1 and {MAX_THRESHOLD}."
            ));
        }
        if self.max_wait > Duration::from_millis(MAX_WAIT_MILLIS)
            || !self.max_wait.subsec_nanos().is_multiple_of(1_000_000)
        {
            return Err(error::fmt!(
                ConfigError,
                "\"symbol_dict_reset_max_wait_millis\" must be an integral number of milliseconds between 0 and {MAX_WAIT_MILLIS}."
            ));
        }
        Ok(self)
    }
}

// Publication integration follows separately; this foundation is intentionally
// not invoked by sender publication paths yet.
#[allow(dead_code)]
pub(crate) struct RecyclePolicy {
    settings: RecycleSettings,
    armed_at: Option<Instant>,
    wait_spent: bool,
    floor: usize,
    epoch: u64,
}

#[allow(dead_code)]
impl RecyclePolicy {
    pub(crate) fn new(settings: RecycleSettings) -> Self {
        Self {
            settings,
            armed_at: None,
            wait_spent: false,
            floor: 0,
            epoch: 0,
        }
    }

    /// Advisory requests bypass the dictionary size gate when enabled.
    pub(crate) fn request_reset(&mut self, now: Instant, _dict_size: usize) {
        if self.settings.enabled {
            self.arm(now);
        }
    }

    pub(crate) fn after_publication(&mut self, now: Instant, dict_size: usize) {
        if self.settings.enabled && dict_size >= self.settings.threshold.max(self.floor) {
            self.arm(now);
        }
    }

    fn arm(&mut self, now: Instant) {
        if self.armed_at.is_none() {
            self.armed_at = Some(now);
            self.wait_spent = false;
        }
    }

    /// An already-drained recycle can proceed immediately while armed. Age
    /// gates only the optional blocking wait returned by `take_wait_budget`.
    pub(crate) fn is_armed(&self) -> bool {
        self.armed_at.is_some()
    }

    pub(crate) fn take_wait_budget(
        &mut self,
        now: Instant,
        live: bool,
        deferred: bool,
    ) -> Option<Duration> {
        let armed_at = self.armed_at?;
        if !live || deferred || self.wait_spent || self.settings.max_wait.is_zero() {
            return None;
        }
        if now.checked_duration_since(armed_at)? < self.settings.max_wait {
            return None;
        }
        self.wait_spent = true;
        Some(self.settings.max_wait)
    }

    pub(crate) fn committed(&mut self, dict_size: usize) {
        self.floor = self
            .floor
            .max(dict_size.saturating_mul(2).min(MAX_THRESHOLD));
        self.armed_at = None;
        self.wait_spent = false;
        self.epoch = self.epoch.saturating_add(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recycle_policy_hysteresis_and_wait_once() {
        let settings = RecycleSettings::default();
        assert_eq!(
            crate::ingress::conf::QwpWsConfig::default().recycle_settings(),
            settings
        );
        let now = Instant::now();
        let mut policy = RecyclePolicy::new(settings);
        policy.after_publication(now, 99_999);
        assert!(!policy.is_armed());
        policy.after_publication(now, 100_000);
        assert!(policy.is_armed()); // Already-drained recycling has no age gate.
        assert_eq!(policy.take_wait_budget(now, true, false), None);
        let later = now.checked_add(settings.max_wait).unwrap();
        policy.after_publication(later, 120_000); // Does not refresh armed age.
        policy.request_reset(later, 1); // Repeated manual requests preserve age too.
        assert_eq!(policy.take_wait_budget(later, false, false), None);
        assert_eq!(policy.take_wait_budget(later, true, true), None);
        assert_eq!(
            policy.take_wait_budget(later, true, false),
            Some(settings.max_wait)
        );
        assert_eq!(policy.take_wait_budget(later, true, false), None);
        policy.committed(100_000);
        assert!(!policy.is_armed());
        assert_eq!((policy.floor, policy.epoch), (200_000, 1));
        policy.after_publication(later, 199_999);
        assert!(!policy.is_armed());
        policy.after_publication(later, 200_000);
        assert!(policy.is_armed());
        assert_eq!(
            policy.take_wait_budget(later.checked_add(settings.max_wait).unwrap(), true, false),
            Some(settings.max_wait)
        );
        policy.committed(200_000);
        assert_eq!((policy.floor, policy.epoch), (400_000, 2));
        policy.after_publication(later, 399_999);
        assert!(!policy.is_armed());
        policy.after_publication(later, 600_000);
        assert!(policy.is_armed());
        policy.committed(600_000);
        assert_eq!((policy.floor, policy.epoch), (1_000_000, 3));
        policy.after_publication(later, 999_999);
        assert!(!policy.is_armed());
        policy.request_reset(later, 1);
        assert!(policy.is_armed());
        policy.committed(1);
        assert_eq!((policy.floor, policy.epoch), (1_000_000, 4));
        policy.after_publication(later, 1_000_000);
        assert!(policy.is_armed());
        policy.committed(usize::MAX);
        assert_eq!(policy.floor, 1_000_000);

        let mut disabled = RecyclePolicy::new(RecycleSettings {
            enabled: false,
            ..settings
        });
        disabled.after_publication(now, usize::MAX);
        disabled.request_reset(now, usize::MAX);
        assert!(!disabled.is_armed());
        assert_eq!(disabled.take_wait_budget(later, true, false), None);

        let mut opportunistic = RecyclePolicy::new(RecycleSettings {
            max_wait: Duration::ZERO,
            ..settings
        });
        opportunistic.request_reset(now, 1);
        assert!(opportunistic.is_armed());
        assert_eq!(opportunistic.take_wait_budget(later, true, false), None);
    }
}
