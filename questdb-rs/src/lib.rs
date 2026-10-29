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
#![doc = include_str!("../README.md")]

mod error;

#[cfg(any(feature = "sync-sender-tcp", feature = "sync-sender-qwp-udp"))]
mod gai;

// Shared RFC 6455 WebSocket plumbing. Compiled whenever either side
// needs it (ingress QWP/WS sender or egress QWP/WS reader). Each side
// keeps its own transport-specific state machine on top of these
// primitives.
#[cfg(any(feature = "_sender-qwp-ws", feature = "_egress"))]
mod ws;

// Display-safe rendering of untrusted text, shared by the OIDC prompt and
// token-provider error redaction.
#[cfg(any(
    feature = "_oidc",
    feature = "_sender-http",
    feature = "_sender-qwp-ws",
    feature = "_egress"
))]
mod display_text;

// Rotating Bearer-token providers shared by the ILP/HTTP sender, the QWP/WS
// ingress sender, and the egress reader: the `BearerTokenProvider` interface,
// and the proactively refreshing `RefreshingTokenProvider` cache.
#[cfg(any(
    feature = "_sender-http",
    feature = "_sender-qwp-ws",
    feature = "_egress"
))]
pub mod token_provider;
#[cfg(any(
    feature = "_sender-http",
    feature = "_sender-qwp-ws",
    feature = "_egress"
))]
#[doc(hidden)]
pub use token_provider::{
    TokenProviderIsolation, token_pull_must_not_block, with_nonblocking_token_pull,
};

// JKS / PKCS#12 trust-store loader for `tls_roots_password`. Pulled
// in only for the QWP transports — matches the Java reference's
// `KeyStore.getInstance(...)` surface there. Other ILP transports
// keep using rustls' native PEM input.
#[cfg(feature = "_keystore-roots")]
mod keystore_roots;

pub mod ingress;

// Transport-neutral Arrow field-metadata keys, shared by the ingress encoder
// and the egress adapter. Homed here so a sender-only `arrow-ingress` build
// can use them without compiling the egress reader.
#[cfg(feature = "_arrow")]
pub mod arrow_metadata;

// Transport-neutral arrow<->polars_arrow FFI bridges, shared by both polars
// directions.
#[cfg(feature = "_polars")]
#[doc(hidden)]
pub(crate) mod polars_ffi;

#[cfg(feature = "_egress")]
pub mod egress;

#[cfg(feature = "_oidc")]
pub mod oidc;

pub use error::*;

/// True if `s` is safe to send verbatim as a wire-bound Bearer credential:
/// non-blank and printable-ASCII only. A control / non-ASCII byte (a decoded CR/LF
/// is a header-injection vector) or a blank value must never reach an
/// `Authorization: Bearer` header. Single gate shared by the OIDC token checks, the
/// ILP/HTTP token-provider, and the QWP/WS + egress token-provider.
#[cfg(any(
    feature = "_oidc",
    feature = "_sender-http",
    feature = "_sender-qwp-ws",
    feature = "_egress"
))]
pub(crate) fn is_printable_ascii_token(s: &str) -> bool {
    !s.trim().is_empty() && s.bytes().all(|b| (0x20..=0x7e).contains(&b))
}

/// Connect-string keys the dynamic-credential specification reserves for
/// selecting a token provider (design/qwp-token-provider-spec.md §7.1).
const RESERVED_TOKEN_PROVIDER_KEYS: &[&str] = &[
    "token_provider",
    "azure_resource",
    "azure_client_id",
    "azure_credential",
];

/// The sender method that attaches a token provider in this build, named by the
/// reserved-key error: the protocol-neutral one needs both Bearer transports.
#[cfg(all(feature = "_sender-http", feature = "_sender-qwp-ws"))]
const SENDER_TOKEN_PROVIDER_API: Option<&str> = Some("SenderBuilder::bearer_token_provider");
#[cfg(all(feature = "_sender-http", not(feature = "_sender-qwp-ws")))]
const SENDER_TOKEN_PROVIDER_API: Option<&str> = Some("SenderBuilder::http_token_provider");
#[cfg(all(feature = "_sender-qwp-ws", not(feature = "_sender-http")))]
const SENDER_TOKEN_PROVIDER_API: Option<&str> = Some("SenderBuilder::qwp_ws_token_provider");
#[cfg(not(any(feature = "_sender-http", feature = "_sender-qwp-ws")))]
const SENDER_TOKEN_PROVIDER_API: Option<&str> = None;

/// The reader method that attaches a token provider, when this build has one.
#[cfg(feature = "_egress")]
const READER_TOKEN_PROVIDER_API: Option<&str> = Some("ReaderConfig::token_provider");
#[cfg(not(feature = "_egress"))]
const READER_TOKEN_PROVIDER_API: Option<&str> = None;

/// Where a Rust caller of this build attaches a token provider, for the
/// reserved-key error. It names only methods the enabled features compile in:
/// pointing an ILP/HTTP-only build at `bearer_token_provider` sent the caller
/// looking for a method that does not exist there.
fn rust_token_provider_hint() -> String {
    let apis: Vec<String> = [SENDER_TOKEN_PROVIDER_API, READER_TOKEN_PROVIDER_API]
        .into_iter()
        .flatten()
        .map(|api| format!("`{api}`"))
        .collect();
    if apis.is_empty() {
        return "Rust: this build has no ILP/HTTP, QWP/WebSocket or reader feature, so \
                nothing in it accepts a token provider."
            .to_string();
    }
    format!(
        "Rust {}. A `RefreshingTokenProvider` can fetch tokens however you like, Azure \
         Identity included.",
        apis.join(" or ")
    )
}

/// The error for a reserved token-provider key, or `None` for any other key.
///
/// This client selects no token provider from a connect string, so it rejects
/// these keys on every schema with a pointer to the in-code API (§7.2): it must
/// never connect without the credential the string asked for.
pub(crate) fn reserved_token_provider_key_error(key: &str) -> Option<Error> {
    RESERVED_TOKEN_PROVIDER_KEYS.contains(&key).then(|| {
        error::fmt!(
            ConfigError,
            "\"{key}\" selects a connect-string token provider, which this client does not \
             support (supported token_provider values: none). Attach a token provider in code \
             instead: Python `bearer_token_provider=`; C/C++ `line_sender_opts_token_provider`, \
             `questdb_db_connect_options.token_provider` or \
             `qwp_reader_from_conf_with_token_provider`; {}",
            rust_token_provider_hint()
        )
    })
}

#[cfg(test)]
mod reserved_token_provider_key_tests {
    use super::reserved_token_provider_key_error;

    #[test]
    fn the_error_names_only_apis_this_build_compiles_in() {
        let err = reserved_token_provider_key_error("token_provider").unwrap();
        let msg = err.msg();
        for (api, compiled_in) in [
            (
                "SenderBuilder::bearer_token_provider",
                cfg!(all(feature = "_sender-http", feature = "_sender-qwp-ws")),
            ),
            (
                "SenderBuilder::http_token_provider",
                cfg!(all(
                    feature = "_sender-http",
                    not(feature = "_sender-qwp-ws")
                )),
            ),
            (
                "SenderBuilder::qwp_ws_token_provider",
                cfg!(all(
                    feature = "_sender-qwp-ws",
                    not(feature = "_sender-http")
                )),
            ),
            ("ReaderConfig::token_provider", cfg!(feature = "_egress")),
        ] {
            assert_eq!(msg.contains(api), compiled_in, "{api}: {msg}");
        }
        assert!(
            reserved_token_provider_key_error("token").is_none(),
            "an ordinary key is not reserved"
        );
    }
}

// --- Primary entry point -------------------------------------------------
//
// `QuestDb` is the connection/pool handle for a QuestDB instance. It spans
// both directions — it hands out unified ingestion senders (write) and query
// readers (read) — so it lives in its own top-level `db` module,
// a peer of `ingress` and `egress` rather than a child of either. Those
// modules remain the home of the specialised, direction-specific types
// (`Chunk`, `AckLevel`, `ColumnView`, `Cursor`, `Bind`, …); the common entry
// path is `use questdb::QuestDb`.
#[cfg(feature = "sync-sender-qwp-ws")]
mod db;

#[cfg(feature = "sync-sender-qwp-ws")]
pub use db::{BorrowedSender, ConnectHandlers, QuestDb};
// Unstable per-pool connection-count snapshot for soak / leak harnesses.
// `#[doc(hidden)]` at the definition site; re-exported so `QuestDb`'s
// `dbg_pool_counts` return type is nameable.
#[cfg(feature = "sync-sender-qwp-ws")]
pub use db::{DbgPoolCount, DbgPoolCounts};
// Internal transport behind `QuestDb::flush_arrow_batch` /
// `QuestDb::flush_polars_dataframe`. Not part of the public API: hidden from
// the docs and has no documented constructor. Kept reachable only so the
// crate's own ingestion entry points can name it.
#[cfg(feature = "sync-sender-qwp-ws")]
#[doc(hidden)]
pub use db::BorrowedDirectColumnSender;

#[cfg(all(feature = "sync-sender-qwp-ws", feature = "_egress"))]
pub use db::BorrowedReader;

// FFI escape-hatch surface. Hidden and not semver-stable: it exists so the
// `questdb-rs-ffi` C-ABI crate can borrow owned (lifetime-free) pool handles
// that C / Python cannot express as Rust lifetimes. Normal Rust users borrow
// the lifetime-bound handles re-exported above. The `ffi-support` feature
// implies `sync-sender-qwp-ws`, so the module is always available when enabled.
#[cfg(feature = "ffi-support")]
#[doc(hidden)]
pub use db::ffi_support;

#[cfg(all(test, any(feature = "_sender-qwp-udp", feature = "_sender-qwp-ws")))]
mod alloc_counter {
    use std::alloc::{GlobalAlloc, Layout, System};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    pub static COUNTING: AtomicBool = AtomicBool::new(false);
    pub static ALLOC_COUNT: AtomicUsize = AtomicUsize::new(0);

    pub struct CountingAllocator;

    unsafe impl GlobalAlloc for CountingAllocator {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            if COUNTING.load(Ordering::Relaxed) {
                ALLOC_COUNT.fetch_add(1, Ordering::Relaxed);
            }
            unsafe { System.alloc(layout) }
        }

        unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
            unsafe { System.dealloc(ptr, layout) }
        }

        unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
            if COUNTING.load(Ordering::Relaxed) {
                ALLOC_COUNT.fetch_add(1, Ordering::Relaxed);
            }
            unsafe { System.realloc(ptr, layout, new_size) }
        }
    }

    /// Begin counting allocations made through the global allocator.
    ///
    /// The counter and the enable flag are process-global, so *any* allocation
    /// on *any* thread between [`start_counting`] and [`stop_counting`] is
    /// included. Tests that assert on the result must therefore run
    /// single-threaded: mark them `#[ignore]` and run with `--test-threads=1`
    /// (see the existing `qwp_zero_alloc_*` tests for the convention).
    pub fn start_counting() -> usize {
        ALLOC_COUNT.store(0, Ordering::SeqCst);
        COUNTING.store(true, Ordering::SeqCst);
        0
    }

    /// Stop counting and return the number of allocations observed since
    /// [`start_counting`]. Same single-thread constraint as `start_counting`.
    pub fn stop_counting() -> usize {
        COUNTING.store(false, Ordering::SeqCst);
        ALLOC_COUNT.load(Ordering::SeqCst)
    }
}

#[cfg(all(test, any(feature = "_sender-qwp-udp", feature = "_sender-qwp-ws")))]
#[global_allocator]
static GLOBAL: alloc_counter::CountingAllocator = alloc_counter::CountingAllocator;

#[cfg(test)]
mod tests;
