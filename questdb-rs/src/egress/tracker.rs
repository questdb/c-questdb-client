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

//! Per-client host-health tracker. Ranks the configured endpoint list
//! when picking the next host to try, both on initial connect and on
//! mid-query failover reconnect. Port of the Java reference
//! `QwpHostHealthTracker`; semantics match failover.md §2.
//!
//! The tracker does not carry internal synchronisation: every mutation
//! goes through `&mut self`, so the borrow checker already enforces
//! exclusive access for the lifetime of each call. The Java original
//! uses an internal lock because in that codebase the same tracker is
//! shared across sender (ingress) and query-client (egress) threads;
//! in Rust, sharing across threads would require an explicit
//! `Mutex`/`RwLock` wrapper at the call site, which is the right place
//! for that policy.

/// Lifecycle classification for one host.
///
/// Priority lattice (lowest number wins) per failover.md §2:
///
/// ```text
/// Healthy < Unknown < TransientReject < TransportError < TopologyReject
/// ```
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum HostState {
    /// Never tried this round, or just reset by `begin_round`.
    Unknown,
    /// Last connect to this host succeeded.
    Healthy,
    /// Server returned `421` + `X-QuestDB-Role: PRIMARY_CATCHUP`. Likely to recover.
    TransientReject,
    /// TCP/TLS/handshake error during connect, or mid-stream send/receive
    /// failure (the latter only via `record_mid_stream_failure`).
    TransportError,
    /// Server returned `421` + a topological role (REPLICA / unknown).
    /// Won't recover without topology change.
    TopologyReject,
}

/// Zone classification relative to the client's configured `zone=`. See
/// failover.md §2. When the client zone is unset or `target=primary`,
/// every host's tier collapses to `Same`, degenerating selection to
/// state-only ordering.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum ZoneTier {
    /// Server zone equals client `zone=` (case-insensitive), OR client
    /// `zone=` is unset, OR `target=primary`.
    Same,
    /// Server did not advertise a zone (no `CAP_ZONE`, no
    /// `X-QuestDB-Zone` header, or v1-pinned client).
    Unknown,
    /// Server advertised a different zone.
    Other,
}

/// Per-client bookkeeping for the configured endpoint list.
///
/// Lifecycle:
///
/// - Construct with `new(host_count, client_zone, target_primary)`.
/// - Walk the list via `pick_next()` paired with one of the `record_*`
///   methods; `pick_next` returns `None` when the round is exhausted.
/// - Bound a logical "round" via `begin_round(forget_classifications)`:
///   `false` resets only the attempted bits (within-outage reset);
///   `true` also forgets non-Healthy classifications (between-outages
///   reset), keeping the most-recently-successful same-zone host as a
///   sticky priority pick.
///
/// `pick_next()` returns the highest-priority unattempted host by the
/// lexicographic `(state, zone_tier)` tuple — state outranks zone, so a
/// known-good cross-zone host is picked before an untried local host.
/// Within a tied bucket the lowest array index wins, matching the
/// user-supplied `addr=` order (failover.md §2 selection priority).
pub struct HostHealthTracker {
    states: Vec<HostState>,
    zone_tiers: Vec<ZoneTier>,
    attempted_this_round: Vec<bool>,
    last_success_epoch: Vec<u64>,
    next_success_epoch: u64,
    /// Lowercased, trimmed client zone. `None` collapses every host
    /// tier to `Same` (zone-blind selection).
    configured_zone: Option<String>,
    /// `true` when `target=primary` is in effect. Forces every host's
    /// zone tier to `Same` regardless of `configured_zone`; writers
    /// must be followed across zones (failover.md §2).
    target_primary: bool,
}

impl HostHealthTracker {
    /// `host_count` must be > 0. `client_zone` is the value of the
    /// `zone=` connect-string knob; `None` or empty-after-trim collapses
    /// zone tier to `Same`. `target_primary` is the `target=primary`
    /// flag — see failover.md §2.
    pub fn new(host_count: usize, client_zone: Option<&str>, target_primary: bool) -> Self {
        assert!(host_count > 0, "host_count must be > 0");
        let configured_zone = client_zone
            .map(str::trim)
            .filter(|z| !z.is_empty())
            .map(str::to_ascii_lowercase);
        // When no zone preference is in effect, default every host to
        // `Same` so selection degenerates to state-only ordering.
        // Otherwise start at `Unknown`: the tier flips to `Same` or
        // `Other` the first time a zone is observed via `record_zone`.
        let initial_tier = if configured_zone.is_none() || target_primary {
            ZoneTier::Same
        } else {
            ZoneTier::Unknown
        };
        Self {
            states: vec![HostState::Unknown; host_count],
            zone_tiers: vec![initial_tier; host_count],
            attempted_this_round: vec![false; host_count],
            last_success_epoch: vec![0; host_count],
            next_success_epoch: 0,
            configured_zone,
            target_primary,
        }
    }

    /// Diagnostic accessor — number of configured hosts.
    /// Not consumed in the failover loop today, but useful in tests
    /// and likely-future telemetry hooks.
    #[allow(dead_code)]
    pub fn count(&self) -> usize {
        self.states.len()
    }

    /// Diagnostic accessor — current state classification for one host.
    /// Used in unit tests; held public for future introspection.
    #[allow(dead_code)]
    pub fn state(&self, idx: usize) -> HostState {
        self.states[idx]
    }

    /// Diagnostic accessor — current zone tier for one host.
    /// Used in unit tests; held public for future introspection.
    #[allow(dead_code)]
    pub fn zone_tier(&self, idx: usize) -> ZoneTier {
        self.zone_tiers[idx]
    }

    /// `true` iff every host has been attempted this round.
    /// Not consumed by the walk loop directly (which uses `pick_next ==
    /// None` as the exhaustion signal); kept for tests and future
    /// diagnostics.
    #[allow(dead_code)]
    pub fn is_round_exhausted(&self) -> bool {
        self.attempted_this_round.iter().all(|a| *a)
    }

    /// Returns the highest-priority host not yet attempted this round,
    /// or `None` when the round is exhausted. Iteration order follows
    /// the `(state, zone_tier)` lexicographic priority; within a tied
    /// bucket, the lowest index wins.
    pub fn pick_next(&self) -> Option<usize> {
        // Two-deep cascade rather than a sort: `host_count` is bounded
        // by `MAX_ADDRS` (1024) and the buckets are small, so this is
        // well under a microsecond even at the cap.
        const STATES: [HostState; 5] = [
            HostState::Healthy,
            HostState::Unknown,
            HostState::TransientReject,
            HostState::TransportError,
            HostState::TopologyReject,
        ];
        const ZONES: [ZoneTier; 3] = [ZoneTier::Same, ZoneTier::Unknown, ZoneTier::Other];
        for state in STATES {
            for zone in ZONES {
                for (i, _) in self.states.iter().enumerate() {
                    if !self.attempted_this_round[i]
                        && self.states[i] == state
                        && self.zone_tiers[i] == zone
                    {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    /// Successful connect — mark the host `Healthy`, record the
    /// success epoch for sticky-Healthy tie-breaking, and consume the
    /// round-attempted bit.
    pub fn record_success(&mut self, idx: usize) {
        self.states[idx] = HostState::Healthy;
        self.attempted_this_round[idx] = true;
        self.next_success_epoch += 1;
        self.last_success_epoch[idx] = self.next_success_epoch;
    }

    /// `421` + `X-QuestDB-Role` reject or `SERVER_INFO` target mismatch.
    /// `transient=true` for `PRIMARY_CATCHUP`; every other role byte
    /// (and unrecognised tokens) is topological per failover.md §6.
    pub fn record_role_reject(&mut self, idx: usize, transient: bool) {
        self.states[idx] = if transient {
            HostState::TransientReject
        } else {
            HostState::TopologyReject
        };
        self.attempted_this_round[idx] = true;
    }

    /// TCP/TLS/handshake failure during connect, or the round-time
    /// classification of a `421`-without-role-header response. Does NOT
    /// touch the attempted bit when called from
    /// `record_mid_stream_failure` — see that method's docs.
    pub fn record_transport_error(&mut self, idx: usize) {
        self.states[idx] = HostState::TransportError;
        self.attempted_this_round[idx] = true;
    }

    /// Demote a previously-`Healthy` host on send/receive failure. No-op
    /// when the prior state is anything other than `Healthy` so a
    /// single hiccup does not erase an already-captured topology or
    /// transient reject (per failover.md §2.1).
    ///
    /// Per the spec invariant, this MUST be called **before** the next
    /// `begin_round(forget_classifications=true)` — reversing the order
    /// makes sticky-Healthy preserve the just-failed host as priority
    /// pick, and the first reconnect attempt would re-hit it.
    ///
    /// Does NOT touch the attempted bit: the round lifecycle owns that
    /// flag, and a mid-stream demote is independent of whether the
    /// loop has tried this host in the current round.
    pub fn record_mid_stream_failure(&mut self, idx: usize) {
        if self.states[idx] == HostState::Healthy {
            self.states[idx] = HostState::TransportError;
        }
    }

    /// Record a server-advertised zone for the given host. Called once
    /// after a successful upgrade with `SERVER_INFO.zone_id` (gated by
    /// `CAP_ZONE`), and once with the `X-QuestDB-Zone` header value on
    /// a `421` reject.
    ///
    /// `None` / empty-after-trim is a no-op (preserves the existing
    /// tier, defaulting to `Unknown` if never set). When the client
    /// zone is unset or `target=primary`, every observation collapses
    /// to `Same`. Comparison is case-insensitive.
    pub fn record_zone(&mut self, idx: usize, zone_id: Option<&str>) {
        let raw = match zone_id {
            Some(z) => z,
            None => return,
        };
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return;
        }
        let tier = if self.configured_zone.is_none() || self.target_primary {
            ZoneTier::Same
        } else if let Some(cfg_zone) = self.configured_zone.as_deref()
            && trimmed.eq_ignore_ascii_case(cfg_zone)
        {
            ZoneTier::Same
        } else {
            ZoneTier::Other
        };
        self.zone_tiers[idx] = tier;
    }

    /// Reset the round-attempted bits. With `forget_classifications =
    /// true`, every host except the most-recently-successful
    /// `(Healthy, Same)` entry is reset to `Unknown` — the
    /// sticky-Healthy keeps the last same-zone successful host first in
    /// line on the next round. Cross-zone `Healthy` entries are reset to
    /// `Unknown` rather than preserved (a sticky pin in another zone
    /// would otherwise defeat same-zone preference).
    ///
    /// Per failover.md §2.1, `zone_tier` is NOT cleared by this method
    /// — once observed it persists across rounds.
    pub fn begin_round(&mut self, forget_classifications: bool) {
        let mut sticky_index: Option<usize> = None;
        if forget_classifications {
            let mut best_epoch: u64 = 0;
            for i in 0..self.states.len() {
                if self.states[i] == HostState::Healthy
                    && self.zone_tiers[i] == ZoneTier::Same
                    && self.last_success_epoch[i] > best_epoch
                {
                    best_epoch = self.last_success_epoch[i];
                    sticky_index = Some(i);
                }
            }
        }
        for i in 0..self.states.len() {
            self.attempted_this_round[i] = false;
            if forget_classifications && Some(i) != sticky_index {
                self.states[i] = HostState::Unknown;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(n: usize) -> HostHealthTracker {
        HostHealthTracker::new(n, None, false)
    }

    #[test]
    fn fresh_tracker_picks_lowest_index() {
        let t = t(3);
        assert_eq!(t.pick_next(), Some(0));
    }

    #[test]
    fn attempted_bits_block_repick_within_round() {
        let mut t = t(3);
        t.record_transport_error(0);
        assert_eq!(t.pick_next(), Some(1));
        t.record_transport_error(1);
        assert_eq!(t.pick_next(), Some(2));
        t.record_transport_error(2);
        assert_eq!(t.pick_next(), None);
        assert!(t.is_round_exhausted());
    }

    #[test]
    fn priority_orders_state_before_zone() {
        // 3 hosts: 0 = Healthy/Other, 1 = Unknown/Same, 2 = Unknown/Same.
        // State outranks zone, so 0 wins over 1 even though 0 is in
        // another zone.
        let mut t = HostHealthTracker::new(3, Some("eu-west"), false);
        // Force tiers manually via record_zone.
        t.record_zone(0, Some("us-east")); // Other
        t.record_zone(1, Some("eu-west")); // Same
        t.record_zone(2, Some("eu-west")); // Same
        t.record_success(0); // Healthy/Other
        // Hosts 1, 2: Unknown/Same.
        // begin_round so attempted bits reset.
        t.begin_round(false);
        assert_eq!(t.pick_next(), Some(0), "Healthy/Other beats Unknown/Same");
    }

    #[test]
    fn priority_orders_zone_within_state() {
        let mut t = HostHealthTracker::new(3, Some("eu-west"), false);
        t.record_zone(0, Some("us-east")); // Other, Unknown state
        t.record_zone(1, Some("eu-west")); // Same, Unknown state
        // Host 2: Unknown zone (not advertised), Unknown state.
        // Order should be: 1 (Same) → 2 (Unknown) → 0 (Other).
        assert_eq!(t.pick_next(), Some(1));
        t.record_transport_error(1);
        assert_eq!(t.pick_next(), Some(2));
        t.record_transport_error(2);
        assert_eq!(t.pick_next(), Some(0));
    }

    #[test]
    fn record_role_reject_classifies_transient_vs_topological() {
        let mut t = t(2);
        t.record_role_reject(0, true);
        t.record_role_reject(1, false);
        assert_eq!(t.state(0), HostState::TransientReject);
        assert_eq!(t.state(1), HostState::TopologyReject);
        // TransientReject outranks TopologyReject, so 0 picks first.
        t.begin_round(false);
        assert_eq!(t.pick_next(), Some(0));
    }

    #[test]
    fn record_mid_stream_failure_only_demotes_healthy() {
        let mut t = t(3);
        t.record_success(0);
        t.record_role_reject(1, false);
        t.record_transport_error(2);
        // Pre-mid-stream: 0=Healthy, 1=TopologyReject, 2=TransportError.
        t.record_mid_stream_failure(0); // Healthy → TransportError.
        t.record_mid_stream_failure(1); // No-op (was TopologyReject).
        t.record_mid_stream_failure(2); // No-op (was TransportError).
        assert_eq!(t.state(0), HostState::TransportError);
        assert_eq!(t.state(1), HostState::TopologyReject);
        assert_eq!(t.state(2), HostState::TransportError);
    }

    #[test]
    fn record_mid_stream_failure_does_not_touch_attempted_bit() {
        let mut t = t(2);
        t.record_success(0);
        // 0 is now Healthy and attempted=true. mid_stream_failure on 0:
        // attempted bit must NOT be cleared.
        t.record_mid_stream_failure(0);
        // Without begin_round, pick_next on host 0 still blocked.
        assert_eq!(t.pick_next(), Some(1));
    }

    #[test]
    fn begin_round_false_resets_attempted_only() {
        let mut t = t(3);
        t.record_transport_error(0);
        t.record_role_reject(1, false);
        t.record_success(2);
        t.begin_round(false);
        assert!(!t.is_round_exhausted());
        // Classifications preserved.
        assert_eq!(t.state(0), HostState::TransportError);
        assert_eq!(t.state(1), HostState::TopologyReject);
        assert_eq!(t.state(2), HostState::Healthy);
        // Healthy 2 wins on priority.
        assert_eq!(t.pick_next(), Some(2));
    }

    #[test]
    fn begin_round_true_forgets_non_healthy_keeps_sticky() {
        let mut t = t(3);
        t.record_transport_error(0);
        t.record_role_reject(1, false);
        t.record_success(2);
        t.begin_round(true);
        // 0 and 1 reset to Unknown; 2 stays Healthy (sticky).
        assert_eq!(t.state(0), HostState::Unknown);
        assert_eq!(t.state(1), HostState::Unknown);
        assert_eq!(t.state(2), HostState::Healthy);
        assert_eq!(t.pick_next(), Some(2));
    }

    #[test]
    fn sticky_healthy_keeps_most_recent_success_only() {
        let mut t = t(3);
        t.record_success(0); // epoch 1
        t.record_success(1); // epoch 2
        t.record_success(2); // epoch 3 (most recent)
        t.begin_round(true);
        // Only the latest-epoch Healthy survives; others reset to Unknown.
        assert_eq!(t.state(0), HostState::Unknown);
        assert_eq!(t.state(1), HostState::Unknown);
        assert_eq!(t.state(2), HostState::Healthy);
    }

    #[test]
    fn sticky_healthy_skips_cross_zone() {
        // Host 0 succeeded but is in zone Other; host 1 succeeded
        // earlier and is in zone Same. Sticky-Healthy must prefer
        // host 1, not 0, because pinning a cross-zone Healthy defeats
        // same-zone preference.
        let mut t = HostHealthTracker::new(3, Some("eu-west"), false);
        t.record_zone(0, Some("us-east")); // Other
        t.record_zone(1, Some("eu-west")); // Same
        t.record_success(1); // epoch 1, Same
        t.record_success(0); // epoch 2, Other
        t.begin_round(true);
        assert_eq!(
            t.state(0),
            HostState::Unknown,
            "cross-zone Healthy must reset"
        );
        assert_eq!(
            t.state(1),
            HostState::Healthy,
            "same-zone Healthy stays sticky"
        );
    }

    #[test]
    fn zone_tier_unset_when_zone_id_empty_or_missing() {
        let mut t = HostHealthTracker::new(2, Some("eu-west"), false);
        // Initial tier is Unknown (zone configured, target!=primary).
        assert_eq!(t.zone_tier(0), ZoneTier::Unknown);
        // None and empty are no-ops.
        t.record_zone(0, None);
        t.record_zone(0, Some(""));
        t.record_zone(0, Some("   "));
        assert_eq!(t.zone_tier(0), ZoneTier::Unknown);
        // Non-empty value updates.
        t.record_zone(0, Some("EU-WEST")); // case-insensitive match
        assert_eq!(t.zone_tier(0), ZoneTier::Same);
    }

    #[test]
    fn target_primary_collapses_zones_to_same() {
        let mut t = HostHealthTracker::new(2, Some("eu-west"), true);
        // Even with a configured zone, target_primary=true collapses
        // every observation to Same: writers follow the master across
        // zones (failover.md §2).
        t.record_zone(0, Some("us-east"));
        t.record_zone(1, Some("apac"));
        assert_eq!(t.zone_tier(0), ZoneTier::Same);
        assert_eq!(t.zone_tier(1), ZoneTier::Same);
    }

    #[test]
    fn zone_tier_survives_begin_round_true() {
        let mut t = HostHealthTracker::new(2, Some("eu-west"), false);
        t.record_zone(0, Some("us-east")); // Other
        t.record_zone(1, Some("eu-west")); // Same
        t.record_role_reject(0, false);
        t.record_role_reject(1, false);
        t.begin_round(true);
        // States are forgotten, but zone tiers persist (failover.md §2.1).
        assert_eq!(t.zone_tier(0), ZoneTier::Other);
        assert_eq!(t.zone_tier(1), ZoneTier::Same);
    }

    #[test]
    fn unset_client_zone_collapses_to_same() {
        let mut t = HostHealthTracker::new(2, None, false);
        // Client zone unset → every observation maps to Same.
        t.record_zone(0, Some("us-east"));
        t.record_zone(1, Some("anywhere"));
        assert_eq!(t.zone_tier(0), ZoneTier::Same);
        assert_eq!(t.zone_tier(1), ZoneTier::Same);
    }

    #[test]
    fn empty_client_zone_collapses_to_same() {
        // Empty / whitespace-only client zone is equivalent to unset
        // (the parser at the connect-string layer should reject
        // outright, but the tracker is defensive).
        let mut t = HostHealthTracker::new(2, Some("   "), false);
        t.record_zone(0, Some("us-east"));
        assert_eq!(t.zone_tier(0), ZoneTier::Same);
    }

    #[test]
    fn priority_lattice_full_order() {
        // Construct one host in each state and verify pick order:
        // Healthy < Unknown < TransientReject < TransportError < TopologyReject.
        let mut t = t(5);
        t.record_success(0); // Healthy
        // 1 stays Unknown
        t.record_role_reject(2, true); // TransientReject
        t.record_transport_error(3); // TransportError
        t.record_role_reject(4, false); // TopologyReject
        t.begin_round(false);
        let mut order = Vec::new();
        while let Some(i) = t.pick_next() {
            order.push(i);
            // Consume the bit so the next pick advances. Use a
            // no-classification-change update.
            t.attempted_this_round[i] = true;
        }
        assert_eq!(order, vec![0, 1, 2, 3, 4]);
    }

    #[test]
    fn pick_next_returns_none_when_all_attempted() {
        let mut t = t(2);
        t.record_transport_error(0);
        t.record_transport_error(1);
        assert!(t.is_round_exhausted());
        assert_eq!(t.pick_next(), None);
    }

    #[test]
    fn round_exhausted_then_begin_round_unlocks_picks() {
        let mut t = t(2);
        t.record_transport_error(0);
        t.record_transport_error(1);
        assert_eq!(t.pick_next(), None);
        t.begin_round(false); // forget_classifications=false: attempted only
        assert_eq!(t.pick_next(), Some(0));
    }
}
