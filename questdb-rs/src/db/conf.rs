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

//! [`crate::QuestDb`] pool connect-string parsing (shared by the column-major sender, row-major sender, and reader borrow kinds).
//!
//! Extracts pool-specific keys (`pool_size`, `pool_max`,
//! `pool_idle_timeout_ms`, `pool_reap`), detects explicit
//! disk-backed store-and-forward opt-in (`sf_dir`), enforces a QWP/WebSocket schema, and
//! produces a sanitized conf string that the underlying
//! [`crate::ingress::SenderBuilder`] can consume to build connections.

use std::time::Duration;

use crate::{Result, error};

/// Default number of warm connections opened eagerly at
/// [`crate::QuestDb::connect`].
pub(crate) const DEFAULT_POOL_SIZE: usize = 1;
/// Default hard cap on auto-grow.
pub(crate) const DEFAULT_POOL_MAX: usize = 64;
/// Default idle timeout before the reaper closes an above-`pool_size`
/// connection.
pub(crate) const DEFAULT_POOL_IDLE_TIMEOUT: Duration = Duration::from_secs(60);

/// Hard cap on parsed `pool_size` / `pool_max`. Bounds the eager
/// `Vec::with_capacity` allocation in [`crate::QuestDb::connect`] so a
/// malformed conf string cannot abort the host via allocator OOM.
pub(crate) const MAX_POOL_SIZE: usize = 65_536;
/// Hard cap on parsed `pool_idle_timeout_ms` (one year). Keeps `Duration`
/// arithmetic inside `i64`-microsecond range used downstream.
pub(crate) const MAX_POOL_IDLE_TIMEOUT_MS: u64 = 365 * 24 * 3600 * 1000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PoolReap {
    Auto,
    Manual,
}

#[derive(Debug, Clone)]
pub(crate) struct PoolConfig {
    pub(crate) pool_size: usize,
    pub(crate) pool_max: usize,
    pub(crate) pool_idle_timeout: Duration,
    pub(crate) pool_reap: PoolReap,
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            pool_size: DEFAULT_POOL_SIZE,
            pool_max: DEFAULT_POOL_MAX,
            pool_idle_timeout: DEFAULT_POOL_IDLE_TIMEOUT,
            pool_reap: PoolReap::Auto,
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct ParsedConf {
    pub(crate) pool: PoolConfig,
    /// `sf_dir` was set: store-and-forward senders use disk-backed,
    /// pool-minted slot directories. When false they use in-memory queues.
    pub(crate) sf_disk: bool,
}

/// Validate and extract pool-specific knobs from a QuestDb pool connect
/// string.
///
/// The conf string itself is **not** rewritten — the underlying
/// `SenderBuilder` silently ignores the pool keys, so a single parse over the
/// original conf is enough. This function only sanity-checks the schema,
/// validates store-and-forward opt-in, and returns the [`PoolConfig`] the
/// pool machinery needs.
pub(crate) fn parse(conf: &str) -> Result<ParsedConf> {
    let Some((service, params)) = conf.split_once("::") else {
        return Err(error::fmt!(
            ConfigError,
            "Invalid QuestDb pool config: missing '::' service separator"
        ));
    };

    if !is_qwp_ws_schema(service) {
        return Err(error::fmt!(
            ConfigError,
            "The QuestDb pool requires a QWP/WebSocket connect string \
             (schema must be 'ws' or 'wss', got {:?})",
            service
        ));
    }

    let mut pool = PoolConfig::default();
    let mut sf_dir_specified = false;

    walk_params(params, |key, value| {
        // `sf_dir` selects disk-backed store-and-forward slots;
        // all other `sf_*` / `sender_id` keys are passthrough to the
        // `SenderBuilder`, tuning the in-memory or disk queue — the same as the
        // row-major sender, which accepts them with or without `sf_dir`.
        if key == "sf_dir" {
            sf_dir_specified = true;
        }
        match key {
            "request_durable_ack" => {
                // Syntactic check; the SenderBuilder also parses this
                // for ColumnConn.
                let _ = parse_on_off("request_durable_ack", value)?;
            }
            "qwp_ws_progress" if value != "background" => {
                return Err(error::fmt!(
                    ConfigError,
                    "The QuestDb pool requires \"qwp_ws_progress=background\" (got {:?})",
                    value
                ));
            }
            "pool_size" => {
                let value = parse_pool_usize(key, value)?;
                if value == 0 {
                    return Err(error::fmt!(
                        ConfigError,
                        "\"pool_size\" must be greater than 0"
                    ));
                }
                pool.pool_size = value;
            }
            "pool_max" => {
                let value = parse_pool_usize(key, value)?;
                if value == 0 {
                    return Err(error::fmt!(
                        ConfigError,
                        "\"pool_max\" must be greater than 0"
                    ));
                }
                pool.pool_max = value;
            }
            "pool_idle_timeout_ms" => {
                let millis: u64 = value.parse().map_err(|_| {
                    error::fmt!(
                        ConfigError,
                        "Invalid value for \"pool_idle_timeout_ms\" (expected an unsigned integer): {:?}",
                        value
                    )
                })?;
                if millis > MAX_POOL_IDLE_TIMEOUT_MS {
                    return Err(error::fmt!(
                        ConfigError,
                        "\"pool_idle_timeout_ms\" {} exceeds maximum ({})",
                        millis,
                        MAX_POOL_IDLE_TIMEOUT_MS
                    ));
                }
                pool.pool_idle_timeout = Duration::from_millis(millis);
            }
            "pool_reap" => {
                pool.pool_reap = match value {
                    "auto" => PoolReap::Auto,
                    "manual" => PoolReap::Manual,
                    other => {
                        return Err(error::fmt!(
                            ConfigError,
                            "Invalid value for \"pool_reap\" (expected 'auto' or 'manual'): {:?}",
                            other
                        ));
                    }
                };
            }
            other if other.starts_with("pool_") => {
                return Err(error::fmt!(
                    ConfigError,
                    "Unknown pool config key {:?}",
                    other
                ));
            }
            _ => {
                // Unknown / passthrough — leave the SenderBuilder to handle it.
            }
        }
        Ok(())
    })?;

    if pool.pool_size > pool.pool_max {
        return Err(error::fmt!(
            ConfigError,
            "\"pool_size\" ({}) must not exceed \"pool_max\" ({})",
            pool.pool_size,
            pool.pool_max
        ));
    }

    Ok(ParsedConf {
        pool,
        sf_disk: sf_dir_specified,
    })
}

fn parse_on_off(key: &str, value: &str) -> Result<bool> {
    match value {
        "on" => Ok(true),
        "off" => Ok(false),
        _ => Err(error::fmt!(
            ConfigError,
            "Invalid value for {:?} (expected 'on' or 'off'): {:?}",
            key,
            value
        )),
    }
}

fn is_qwp_ws_schema(service: &str) -> bool {
    service.eq_ignore_ascii_case("ws") || service.eq_ignore_ascii_case("wss")
}

fn parse_pool_usize(key: &str, value: &str) -> Result<usize> {
    let parsed: usize = value.parse().map_err(|_| {
        error::fmt!(
            ConfigError,
            "Invalid value for {:?} (expected an unsigned integer): {:?}",
            key,
            value
        )
    })?;
    if parsed > MAX_POOL_SIZE {
        return Err(error::fmt!(
            ConfigError,
            "{:?} ({}) exceeds maximum ({})",
            key,
            parsed,
            MAX_POOL_SIZE
        ));
    }
    Ok(parsed)
}

/// Walk a parsed conf-string `params` section, invoking `visit(key, value)`
/// for each `key=value;` pair.
///
/// Mirrors the value-parsing rules of [`crate::ingress::scan_qwp_ws_addr_params`]:
/// a doubled `;;` is treated as a literal semicolon inside a value.
fn walk_params<F>(params: &str, mut visit: F) -> Result<()>
where
    F: FnMut(&str, &str) -> Result<()>,
{
    let mut pos = 0usize;
    while pos < params.len() {
        let Some(eq_rel) = params[pos..].find('=') else {
            return Err(error::fmt!(
                ConfigError,
                "Invalid QuestDb pool config: parameter without '=' at position {}",
                pos
            ));
        };
        let key = &params[pos..pos + eq_rel];
        pos = pos + eq_rel + 1;

        let mut value = String::new();
        while pos < params.len() {
            let rest = &params[pos..];
            let mut chars = rest.char_indices();
            let (_, ch) = chars.next().expect("pos is within params");
            if ch == ';' {
                let next_pos = pos + ch.len_utf8();
                if params[next_pos..].starts_with(';') {
                    value.push(';');
                    pos = next_pos + 1;
                    continue;
                }
                pos = next_pos;
                break;
            }
            value.push(ch);
            pos += ch.len_utf8();
        }

        visit(key, value.as_str())?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ErrorCode;

    fn parse_ok(conf: &str) -> ParsedConf {
        parse(conf).unwrap_or_else(|e| panic!("expected ok, got {e}"))
    }

    fn parse_err(conf: &str) -> crate::Error {
        match parse(conf) {
            Ok(_) => panic!("expected error for {conf:?}"),
            Err(e) => e,
        }
    }

    #[test]
    fn defaults() {
        let p = parse_ok("ws::addr=localhost:9000;");
        assert_eq!(p.pool.pool_size, DEFAULT_POOL_SIZE);
        assert_eq!(p.pool.pool_max, DEFAULT_POOL_MAX);
        assert_eq!(p.pool.pool_idle_timeout, DEFAULT_POOL_IDLE_TIMEOUT);
        assert_eq!(p.pool.pool_reap, PoolReap::Auto);
        assert!(!p.sf_disk);
    }

    #[test]
    fn parses_pool_knobs() {
        let p = parse_ok(
            "ws::addr=localhost:9000;pool_size=4;pool_max=8;pool_idle_timeout_ms=10000;pool_reap=manual;",
        );
        assert_eq!(p.pool.pool_size, 4);
        assert_eq!(p.pool.pool_max, 8);
        assert_eq!(p.pool.pool_idle_timeout, Duration::from_secs(10));
        assert_eq!(p.pool.pool_reap, PoolReap::Manual);
    }

    #[test]
    fn refuses_non_qwp_ws_schema() {
        let err = parse_err("http::addr=localhost:9000;");
        assert_eq!(err.code(), ErrorCode::ConfigError);
        assert!(err.msg().contains("QWP/WebSocket"));
    }

    #[test]
    fn sf_dir_selects_disk_store_and_forward_without_changing_pool_max() {
        let p = parse_ok("ws::addr=localhost:9000;sf_dir=/tmp/qdb-sf;");
        assert!(p.sf_disk);
        assert_eq!(p.pool.pool_size, 1);
        assert_eq!(p.pool.pool_max, DEFAULT_POOL_MAX);
    }

    #[test]
    fn sf_dir_accepts_multi_slot_pool() {
        let p = parse_ok(
            "ws::addr=localhost:9000;sf_dir=/tmp/qdb-sf;pool_size=4;pool_max=8;sender_id=abc;",
        );
        assert!(p.sf_disk);
        assert_eq!(p.pool.pool_size, 4);
        assert_eq!(p.pool.pool_max, 8);
    }

    #[test]
    fn accepts_sf_keys_without_sf_dir() {
        // In-memory store-and-forward is always on, so SF tuning keys are
        // accepted without `sf_dir` (passthrough to the SenderBuilder), matching
        // the row-major sender. They select in-memory SF: `sf_disk` stays
        // false and the pool keeps the normal pool cap.
        for key in [
            "sender_id",
            "sf_max_bytes",
            "sf_max_total_bytes",
            "sf_durability",
            "sf_append_deadline_millis",
        ] {
            let conf = format!("ws::addr=localhost:9000;{key}=whatever;");
            let p = parse_ok(&conf);
            assert!(!p.sf_disk, "{key} must not imply disk-backed SF");
            assert_eq!(p.pool.pool_max, DEFAULT_POOL_MAX, "key {key}");
        }
    }

    #[test]
    fn refuses_pool_size_zero() {
        let err = parse_err("ws::addr=localhost:9000;pool_size=0;");
        assert_eq!(err.code(), ErrorCode::ConfigError);
        assert!(err.msg().contains("pool_size"));
    }

    #[test]
    fn refuses_pool_size_above_pool_max() {
        let err = parse_err("ws::addr=localhost:9000;pool_size=10;pool_max=5;");
        assert_eq!(err.code(), ErrorCode::ConfigError);
        assert!(err.msg().contains("pool_size") && err.msg().contains("pool_max"));
    }

    #[test]
    fn invalid_pool_reap_value() {
        let err = parse_err("ws::addr=localhost:9000;pool_reap=sometimes;");
        assert_eq!(err.code(), ErrorCode::ConfigError);
        assert!(err.msg().contains("pool_reap"));
    }

    #[test]
    fn ignores_unknown_keys() {
        // Unknown keys are passed through to the underlying SenderBuilder,
        // which silently ignores its own unknowns. The pool config layer
        // must not error on them either.
        let _ = parse_ok("ws::addr=localhost:9000;auth_timeout=5000;some_future_key=value;");
    }

    #[test]
    fn parses_request_durable_ack() {
        // Syntactically valid values pass the pool config pre-check.
        // The actual `durable_ack_opt_in` flag is sourced from the
        // SenderBuilder inside `ColumnConn::connect`.
        let _ = parse_ok("ws::addr=localhost:9000;");
        let _ = parse_ok("ws::addr=localhost:9000;request_durable_ack=on;");
        let _ = parse_ok("ws::addr=localhost:9000;request_durable_ack=off;");
    }

    #[test]
    fn refuses_invalid_request_durable_ack_value() {
        let err = parse_err("ws::addr=localhost:9000;request_durable_ack=true;");
        assert_eq!(err.code(), ErrorCode::ConfigError);
        assert!(err.msg().contains("request_durable_ack"));
    }

    #[test]
    fn refuses_manual_progress_mode() {
        let err = parse_err("ws::addr=localhost:9000;qwp_ws_progress=manual;");
        assert_eq!(err.code(), ErrorCode::ConfigError);
        assert!(err.msg().contains("qwp_ws_progress"));
    }

    #[test]
    fn accepts_explicit_background_progress_mode() {
        let _ = parse_ok("ws::addr=localhost:9000;qwp_ws_progress=background;");
    }

    #[test]
    fn doubled_semicolon_in_value() {
        // `;;` inside a value should be parsed as a literal `;`, not as a
        // record separator. Our walker mirrors `scan_qwp_ws_addr_params` so a
        // value containing `;;` does not bleed into the next key.
        let _ = parse_ok("ws::addr=localhost:9000;password=a;;b;pool_size=2;");
    }
}
