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

//! Cross-restart persistence for the [`OidcDeviceAuth`](crate::oidc::OidcDeviceAuth)
//! token state.
//!
//! By default token state is in-memory only, so a restarted process re-runs the
//! interactive device flow. Passing a [`TokenStore`] persists it, so a restart
//! resumes from the saved refresh token (one silent token-endpoint round-trip)
//! instead of re-prompting.
//!
//! The default [`FileTokenStore`] writes one plaintext JSON file per identity,
//! protected at rest by file permissions (`0600` file in a `0700` directory)
//! rather than encryption — the same approach `gcloud`, `aws` and `gh` take. For
//! at-rest encryption, back a custom [`TokenStore`] with an OS keychain or a
//! secrets manager instead.
//!
//! # Security
//!
//! **Persistence writes a long-lived refresh token to disk in plaintext**,
//! protected only by file permissions — anyone who can read the file holds a
//! credential until the IdP expires or revokes it. This is why persistence is
//! opt-in.
//!
//! The on-disk file is treated as untrusted input: on load it is size-bounded,
//! parsed defensively (a corrupt / oversized / garbage file is ignored, not
//! fatal), its fingerprint re-checked against the live config (a token minted for
//! one identity is never served for another), and the served token re-validated
//! for control / non-ASCII characters — the same rejection the device flow
//! applies to IdP responses.
//!
//! The on-disk format (file name, JSON schema, atomic-write and lock-file
//! protocols) is a **frozen cross-language contract** shared with the QuestDB
//! Java and Python clients, so a file written by one can be read by another.

use std::cell::RefCell;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime};

use serde_json::Value;

/// The environment variable that overrides the default token-store directory.
/// Shared with the other QuestDB clients.
pub const TOKEN_STORE_DIR_ENV: &str = "QUESTDB_CLIENT_OIDC_TOKEN_STORE_DIR";

const SCHEMA_VERSION: i64 = 1;
const CANONICAL_PREFIX: &str = "questdb-oidc-token-v1";

/// Cap on a token-store file. An id token with many group claims is a few KiB;
/// 1 MiB is ample while refusing to persist or read an oversized file.
const MAX_FILE_BYTES: u64 = 1 << 20;

/// How long to spin trying to acquire the per-identity lock file before returning
/// a retryable error. A refresh must never run without the lock: rotating refresh
/// tokens can be invalidated when two processes submit the same parent token.
const DEFAULT_LOCK_ACQUIRE_BUDGET: Duration = Duration::from_secs(3);
/// A configured acquire budget above this is clamped down so a bad configuration
/// cannot block indefinitely or overflow `Instant::now() + budget`.
const MAX_LOCK_ACQUIRE_BUDGET: Duration = Duration::from_secs(300);
const LOCK_POLL_SLICE: Duration = Duration::from_millis(50);

/// A lock older than this is reported as stale in the acquisition error. Stale
/// locks are deliberately not stolen automatically: there is no portable atomic
/// "remove this path only if it is still this inode" operation, so a check then
/// rename/unlink can displace a newly acquired live lock.
const DEFAULT_LOCK_STALE: Duration = Duration::from_secs(600);
/// A configured staleness window below this is clamped up — see
/// [`FileTokenStore::with_lock_timings`].
const MIN_LOCK_STALE: Duration = Duration::from_secs(300);

/// The result of a [`TokenStore`] operation. Lazy-load and fresh-sign-in
/// persistence is best-effort. Coordination and pre-refresh load/clear failures
/// are surfaced as retryable token-acquisition errors so a refresh never runs
/// concurrently or reuses an ambiguously rotated parent.
pub type TokenStoreResult<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

// ---------------------------------------------------------------------------
// PersistedToken
// ---------------------------------------------------------------------------

/// The token state persisted for one identity — a carrier mirroring the
/// in-memory token fields, with an absolute expiry that survives a restart.
///
/// The secret fields are excluded from [`Debug`] so a credential can't leak into
/// a log or a panic message.
#[derive(Clone, PartialEq)]
pub struct PersistedToken {
    access_token: Option<String>,
    id_token: Option<String>,
    refresh_token: Option<String>,
    /// Absolute expiry as epoch seconds (fractional); `0.0` == unknown.
    expires_at: f64,
    /// The (clamped) lifetime `expires_at` was derived from, in seconds.
    token_ttl: f64,
}

impl PersistedToken {
    /// Construct a persisted token. `expires_at` is absolute epoch seconds;
    /// `token_ttl` is the lifetime it was derived from.
    pub fn new(
        access_token: Option<String>,
        id_token: Option<String>,
        refresh_token: Option<String>,
        expires_at: f64,
        token_ttl: f64,
    ) -> Self {
        PersistedToken {
            access_token,
            id_token,
            refresh_token,
            expires_at,
            token_ttl,
        }
    }

    /// The persisted OAuth `access_token`, when present.
    pub fn access_token(&self) -> Option<&str> {
        self.access_token.as_deref()
    }

    /// The persisted OIDC `id_token`, when present.
    pub fn id_token(&self) -> Option<&str> {
        self.id_token.as_deref()
    }

    /// The persisted `refresh_token`, when present.
    pub fn refresh_token(&self) -> Option<&str> {
        self.refresh_token.as_deref()
    }

    /// The absolute expiry as epoch seconds (`0.0` == unknown).
    pub fn expires_at(&self) -> f64 {
        self.expires_at
    }

    /// The lifetime `expires_at` was derived from, in seconds.
    pub fn token_ttl(&self) -> f64 {
        self.token_ttl
    }
}

impl fmt::Debug for PersistedToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PersistedToken")
            .field(
                "access_token",
                &self.access_token.as_ref().map(|_| "<redacted>"),
            )
            .field("id_token", &self.id_token.as_ref().map(|_| "<redacted>"))
            .field(
                "refresh_token",
                &self.refresh_token.as_ref().map(|_| "<redacted>"),
            )
            .field("expires_at", &self.expires_at)
            .field("token_ttl", &self.token_ttl)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// TokenStoreKey
// ---------------------------------------------------------------------------

/// The non-secret identity a persisted token belongs to.
///
/// A [`TokenStore`] keys its entries by this so a token minted for one server /
/// identity provider / scope / audience is never served to a process configured
/// for another. The endpoint and scope fields must be passed already normalised —
/// exactly as [`OidcDeviceAuth`](crate::oidc::OidcDeviceAuth) builds them (via
/// [`from_config`](Self::from_config)) — so a directly-constructed key matches the
/// same identity the auth object computes.
///
/// [`hash`](Self::hash) is a stable lowercase-hex SHA-256 over a canonical,
/// NUL-separated rendering of the fields, identical across QuestDB client
/// implementations, so processes (and languages) sharing one identity address the
/// same persisted entry. `issuer` participates in the on-load identity re-check
/// but **not** in [`hash`](Self::hash): it is excluded from the file name so the
/// cross-language addressing contract stays byte-identical, while a session pinned
/// to a different issuer still never adopts another's token.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TokenStoreKey {
    client_id: String,
    token_endpoint: String,
    device_authorization_endpoint: String,
    scope: String,
    audience: Option<String>,
    groups_in_token: bool,
    issuer: Option<String>,
}

impl TokenStoreKey {
    /// Build a key from raw identity fields, canonicalising the endpoints and
    /// order-normalising the scope so the same identity hashes the same way in
    /// every process and language client.
    pub fn from_config(
        client_id: impl Into<String>,
        token_endpoint: &str,
        device_authorization_endpoint: &str,
        scope: &str,
        audience: Option<&str>,
        groups_in_token: bool,
        issuer: Option<&str>,
    ) -> Self {
        TokenStoreKey {
            client_id: client_id.into(),
            token_endpoint: canonical_endpoint(token_endpoint),
            device_authorization_endpoint: canonical_endpoint(device_authorization_endpoint),
            scope: normalize_scope(scope),
            audience: audience.map(str::to_string),
            groups_in_token,
            issuer: issuer.map(str::to_string),
        }
    }

    /// The OIDC public-client id.
    pub fn client_id(&self) -> &str {
        &self.client_id
    }

    /// The canonicalised IdP token endpoint.
    pub fn token_endpoint(&self) -> &str {
        &self.token_endpoint
    }

    /// The canonicalised IdP device-authorization endpoint.
    pub fn device_authorization_endpoint(&self) -> &str {
        &self.device_authorization_endpoint
    }

    /// The order-normalised, space-separated scope.
    pub fn scope(&self) -> &str {
        &self.scope
    }

    /// The optional OAuth `audience`.
    pub fn audience(&self) -> Option<&str> {
        self.audience.as_deref()
    }

    /// Whether the server expects groups encoded in the token.
    pub fn groups_in_token(&self) -> bool {
        self.groups_in_token
    }

    /// The optional out-of-band issuer pin.
    pub fn issuer(&self) -> Option<&str> {
        self.issuer.as_deref()
    }

    /// A stable lowercase-hex SHA-256 of the canonical identity string, usable as
    /// an opaque file name / cache key. Identical across QuestDB clients.
    pub fn hash(&self) -> String {
        // NUL-separate the fields so no field value can be confused with a
        // separator (a client id / url / scope / audience never contains a NUL).
        // The prefix tags the domain and schema version. `issuer` is deliberately
        // NOT folded in (the file name is a frozen cross-language contract);
        // issuer isolation is enforced on load via the in-file fingerprint.
        let canonical = [
            CANONICAL_PREFIX,
            &self.client_id,
            &self.token_endpoint,
            &self.device_authorization_endpoint,
            &self.scope,
            self.audience.as_deref().unwrap_or(""),
            if self.groups_in_token { "1" } else { "0" },
        ]
        .join("\0");
        sha256_hex(canonical.as_bytes())
    }
}

// ---------------------------------------------------------------------------
// TokenStore trait
// ---------------------------------------------------------------------------

/// Persists the token state of an [`OidcDeviceAuth`](crate::oidc::OidcDeviceAuth)
/// so a restarted process resumes from a saved refresh token instead of running
/// the interactive device flow again.
///
/// The default implementation is [`FileTokenStore`]. Supply your own to back
/// persistence with an OS keychain, a secrets manager, or a vault — for example
/// to encrypt the refresh token at rest, which the file store does not do.
///
/// Calls are made while `OidcDeviceAuth` holds its own instance lock, so an
/// implementation need not be thread-safe against concurrent calls from one
/// instance; it does, however, share its backing storage with other processes
/// (and other language clients), so it must keep a concurrent reader from
/// observing a half-written entry. A store reports failure by returning `Err`.
/// Lazy-load and fresh-sign-in persistence failures are best-effort. During a
/// coordinated refresh, load/clear failures are retryable and abort the attempt:
/// the client must not submit a refresh token it cannot first make unavailable to
/// peers.
///
/// **Security — [`load`](Self::load) MUST re-verify identity.** `OidcDeviceAuth`
/// does not re-check the returned token against `key`; it trusts `load` to only
/// ever return an entry stored under the *same* identity. A store addressed by
/// [`TokenStoreKey::hash`] must therefore also record the identity fields in the
/// payload and re-compare them on load (as [`FileTokenStore`] does), so a hash
/// collision or a copied entry cannot serve one identity's token to another.
pub trait TokenStore: Send + Sync {
    /// Load the persisted token for this identity, or `None` if there is none
    /// usable (no entry, one that does not match `key`, or one that cannot be read
    /// as a valid token). A `None` return makes `OidcDeviceAuth` fall back to a
    /// refresh or an interactive sign-in.
    fn load(&self, key: &TokenStoreKey) -> TokenStoreResult<Option<PersistedToken>>;

    /// Persist (atomically replace) the token for this identity.
    fn save(&self, key: &TokenStoreKey, token: &PersistedToken) -> TokenStoreResult<()>;

    /// Durably remove any persisted entry for this identity. A no-op when nothing
    /// is stored. After this returns successfully, a later [`load`](Self::load)
    /// must not return the removed refresh-token parent.
    fn clear(&self, key: &TokenStoreKey) -> TokenStoreResult<()>;

    /// Run `action` while holding a cross-process lock scoped to `key`, so a
    /// refresh by another process sharing this identity is observed rather than
    /// raced, and return its result.
    ///
    /// Every store must provide real coordination for all processes sharing its
    /// backing state. The implementation must either invoke `action` exactly
    /// once, synchronously, with the lock held for the whole call, or return
    /// `Err` without invoking it. Running the action without ownership can reuse
    /// and revoke a rotating refresh-token family.
    ///
    /// `action` re-enters this store through [`load`](Self::load),
    /// [`save`](Self::save), or [`clear`](Self::clear). The coordination lock
    /// therefore **must be independent of every mutex or transaction guard those
    /// methods acquire**. Do not hold the store's data-state mutex while invoking
    /// `action`: a non-reentrant mutex would self-deadlock.
    ///
    /// A store used by only one process may coordinate with a separate
    /// in-process mutex, as below, but that limitation belongs in the store's own
    /// explicit contract; there is deliberately no unlocked default.
    ///
    /// ```
    /// use std::collections::HashMap;
    /// use std::sync::Mutex;
    /// use questdb::oidc::{PersistedToken, TokenStore, TokenStoreKey, TokenStoreResult};
    ///
    /// #[derive(Default)]
    /// struct SingleProcessStore {
    ///     entries: Mutex<HashMap<String, PersistedToken>>,
    ///     // Deliberately separate from `entries`: the action calls back into
    ///     // load/save/clear, which lock `entries` themselves.
    ///     refresh_coordination: Mutex<()>,
    /// }
    ///
    /// impl TokenStore for SingleProcessStore {
    ///     fn load(&self, key: &TokenStoreKey)
    ///         -> TokenStoreResult<Option<PersistedToken>>
    ///     {
    ///         Ok(self.entries.lock().unwrap().get(&key.hash()).cloned())
    ///     }
    ///
    ///     fn save(&self, key: &TokenStoreKey, token: &PersistedToken)
    ///         -> TokenStoreResult<()>
    ///     {
    ///         self.entries.lock().unwrap().insert(key.hash(), token.clone());
    ///         Ok(())
    ///     }
    ///
    ///     fn clear(&self, key: &TokenStoreKey) -> TokenStoreResult<()> {
    ///         self.entries.lock().unwrap().remove(&key.hash());
    ///         Ok(())
    ///     }
    ///
    ///     fn in_lock(
    ///         &self,
    ///         _key: &TokenStoreKey,
    ///         action: &mut dyn FnMut() -> TokenStoreResult<()>,
    ///     ) -> TokenStoreResult<()> {
    ///         let _coordination = self.refresh_coordination.lock().unwrap();
    ///         action()
    ///     }
    /// }
    ///
    /// let store = SingleProcessStore::default();
    /// let key = TokenStoreKey::from_config(
    ///     "questdb",
    ///     "https://idp.example.com/token",
    ///     "https://idp.example.com/device",
    ///     "openid",
    ///     None,
    ///     false,
    ///     None,
    /// );
    /// store.in_lock(&key, &mut || {
    ///     let _current = store.load(&key)?;
    ///     store.clear(&key)
    /// }).unwrap();
    /// ```
    fn in_lock(
        &self,
        key: &TokenStoreKey,
        action: &mut dyn FnMut() -> TokenStoreResult<()>,
    ) -> TokenStoreResult<()>;
}

// ---------------------------------------------------------------------------
// FileTokenStore
// ---------------------------------------------------------------------------

/// The default [`TokenStore`]: one plaintext JSON file per identity.
///
/// The refresh token is protected at rest by file permissions (`0600` file,
/// `0700` directory) rather than encryption — matching `gcloud`, `aws` and `gh`.
/// For encryption at rest, supply a [`TokenStore`] backed by an OS keychain or a
/// secrets manager instead.
///
/// The default location is `${HOME}/.questdb/oidc-tokens/`, overridable with the
/// `QUESTDB_CLIENT_OIDC_TOKEN_STORE_DIR` environment variable. The file name is
/// `<TokenStoreKey::hash()>.json`, so several identities coexist and the name
/// leaks neither the endpoint nor the client id.
///
/// [`save`](FileTokenStore::save) writes a sibling temp file then atomically
/// renames it over the target, so a crash or an overlapping reader — in any
/// process or language — sees the whole old or whole new file, never a torn
/// credential. Every save participates in the same per-identity lock used by
/// [`in_lock`](TokenStore::in_lock), including re-entrant saves made by its
/// action. A successful save removes crash-orphaned plaintext temps only after
/// their age exceeds the configured staleness window. The lock uses an
/// `O_CREAT|O_EXCL` file and never runs an action without owning it or
/// automatically steals a stale pathname: either operation could let two
/// processes submit the same rotating refresh token. A stale lock is reported as
/// a retryable error rather than being reclaimed automatically.
///
/// # Recovering an abandoned lock
///
/// If a lock holder is killed, aborts, or loses power, its lock can remain after
/// the process is gone. The exact path is
/// `<store-directory>/<TokenStoreKey::hash()>.lock`; at the default location that
/// is `${HOME}/.questdb/oidc-tokens/<hash>.lock`, or
/// `$QUESTDB_CLIENT_OIDC_TOKEN_STORE_DIR/<hash>.lock` when the environment
/// override is set. [`FileTokenStore::at`] uses its supplied directory. A lock
/// acquisition error also prints the exact path that blocked it.
///
/// When available, the lock contents identify its creator as
/// `<pid>@<hostname> <creation-time-in-Unix-epoch-nanoseconds>`. Before removing
/// a lock reported as stale, inspect those contents and verify on the named host
/// that the PID no longer identifies the original process. If the PID still
/// exists, compare its executable and start time with the lock's timestamp or
/// modification time to account for PID reuse; treat a matching client process as
/// a live holder and do not remove the lock. If the hostname is unavailable or
/// the store directory is shared across hosts or language clients, verify every
/// candidate host and ensure that no Rust, Java, or Python client using the same
/// identity is still inside a token-store operation.
///
/// Only after establishing that the holder is gone should an operator remove that
/// one `.lock` file; do not remove the sibling `.json` token file. If the holder
/// cannot be ruled out, leave the lock in place. Never automate recovery with a
/// bare unlink or check-then-rename: it can displace a live successor and allow
/// concurrent reuse of a rotating refresh token. Any automatic recovery protocol
/// must be race-safe and coordinated with the Java and Python clients that share
/// this on-disk contract.
#[derive(Debug, Clone)]
pub struct FileTokenStore {
    directory: PathBuf,
    lock_acquire_budget: Duration,
    lock_stale: Duration,
}

impl FileTokenStore {
    /// A store rooted at the given directory.
    pub fn at(directory: impl Into<PathBuf>) -> Self {
        FileTokenStore {
            directory: directory.into(),
            lock_acquire_budget: DEFAULT_LOCK_ACQUIRE_BUDGET,
            lock_stale: DEFAULT_LOCK_STALE,
        }
    }

    /// A store at `$QUESTDB_CLIENT_OIDC_TOKEN_STORE_DIR` if that variable is set,
    /// otherwise at `${HOME}/.questdb/oidc-tokens/`.
    ///
    /// Errors if the home directory can't be resolved and no override is set
    /// (e.g. a distroless container with no `HOME`) — set the environment variable
    /// to an absolute path, or use [`at`](Self::at) explicitly.
    pub fn at_default_location() -> std::io::Result<Self> {
        if let Some(dir) = std::env::var_os(TOKEN_STORE_DIR_ENV).filter(|v| !v.is_empty()) {
            return Ok(Self::at(PathBuf::from(dir)));
        }
        let home = home_dir().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!(
                    "could not resolve the home directory for the default OIDC \
                     token-store location; set the {TOKEN_STORE_DIR_ENV} environment \
                     variable to an absolute path, or construct FileTokenStore::at(dir)."
                ),
            )
        })?;
        Ok(Self::at(home.join(".questdb").join("oidc-tokens")))
    }

    /// Override the cross-process lock timings. `stale` controls when a lock is
    /// identified as abandoned in the acquisition error and when a crash-orphaned
    /// token temp file becomes eligible for cleanup. It never causes a lock to be
    /// automatically unlinked or renamed. A tighter value is clamped up to the
    /// 5-minute floor. `acquire_budget` is clamped down to 5 minutes (an unclamped
    /// value would overflow the deadline arithmetic).
    pub fn with_lock_timings(mut self, acquire_budget: Duration, stale: Duration) -> Self {
        self.lock_acquire_budget = acquire_budget.min(MAX_LOCK_ACQUIRE_BUDGET);
        self.lock_stale = stale.max(MIN_LOCK_STALE);
        self
    }

    fn token_file(&self, key: &TokenStoreKey) -> PathBuf {
        self.directory.join(format!("{}.json", key.hash()))
    }

    fn lock_file(&self, key: &TokenStoreKey) -> PathBuf {
        self.directory.join(format!("{}.lock", key.hash()))
    }

    /// Create the store directory `0700` (no group/world access) and, on a
    /// pre-existing real directory, re-assert owner-only perms. Refuses a symlink
    /// at the leaf so the plaintext token files can't be redirected outside the
    /// owner-only directory.
    fn ensure_directory(&self) -> std::io::Result<()> {
        // lstat the leaf: a symlink planted at the store path would have us write
        // (and chmod) the link's target, outside any directory we own. Only the
        // final component is checked, so a symlinked parent (the whole store moved
        // via the env var) still works.
        match fs::symlink_metadata(&self.directory) {
            Ok(meta) if meta.file_type().is_symlink() => {
                return Err(symlink_leaf_error());
            }
            Ok(_) => {
                // Pre-existing real directory: re-assert owner-only perms.
                restrict_to_owner(&self.directory);
                return Ok(());
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        // Create the parent chain, then the leaf itself NON-recursively, so a
        // symlink planted at the leaf in the window since the lstat above makes the
        // create fail with `AlreadyExists` rather than being silently accepted by a
        // recursive create — closing the stat→create TOCTOU on the sensitive final
        // component (a recursive `create_dir_all` treats an existing symlink-to-dir
        // as success and would write token files through it).
        if let Some(parent) = self.directory.parent()
            && !parent.as_os_str().is_empty()
        {
            create_dir_all_private(parent)?;
        }
        match create_dir_private(&self.directory) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                // Lost the create race: accept only a real directory, never a
                // symlink planted in the gap.
                if fs::symlink_metadata(&self.directory)?
                    .file_type()
                    .is_symlink()
                {
                    return Err(symlink_leaf_error());
                }
            }
            Err(e) => return Err(e),
        }
        restrict_to_owner(&self.directory);
        Ok(())
    }

    fn parse_and_verify(&self, key: &TokenStoreKey, data: &[u8]) -> Option<PersistedToken> {
        let obj = serde_json::from_slice::<Value>(data).ok()?;
        let obj = obj.as_object()?;
        // Schema and fingerprint must match the live identity; a mismatch is a
        // hash collision or a file copied from a different identity, so ignore it
        // rather than serve the wrong identity's token.
        if obj.get("v").and_then(Value::as_i64) != Some(SCHEMA_VERSION) {
            return None;
        }
        let str_field = |k: &str| obj.get(k).and_then(Value::as_str);
        if str_field("client_id") != Some(key.client_id.as_str())
            || str_field("token_endpoint") != Some(key.token_endpoint.as_str())
            || str_field("device_authorization_endpoint")
                != Some(key.device_authorization_endpoint.as_str())
            || str_field("scope") != Some(key.scope.as_str())
            || !opt_str_matches(key.audience.as_deref(), obj.get("audience"))
            || !opt_str_matches(key.issuer.as_deref(), obj.get("issuer"))
            || obj.get("groups_in_token").and_then(Value::as_bool) != Some(key.groups_in_token)
        {
            return None;
        }
        Some(PersistedToken {
            access_token: nonempty_str(obj.get("access_token")),
            id_token: nonempty_str(obj.get("id_token")),
            refresh_token: nonempty_str(obj.get("refresh_token")),
            expires_at: millis_to_seconds(obj.get("expires_at_millis")),
            token_ttl: millis_to_seconds(obj.get("token_ttl_millis")),
        })
    }

    fn serialize(&self, key: &TokenStoreKey, token: &PersistedToken) -> Vec<u8> {
        // A null value (an absent audience/issuer, or a token kind the grant did
        // not return) is OMITTED, never written as JSON null — the only encoding
        // under which a present value round-trips verbatim and an absent one reads
        // back as null.
        let mut map = serde_json::Map::new();
        map.insert("v".into(), Value::from(SCHEMA_VERSION));
        map.insert("client_id".into(), Value::from(key.client_id.clone()));
        map.insert(
            "token_endpoint".into(),
            Value::from(key.token_endpoint.clone()),
        );
        map.insert(
            "device_authorization_endpoint".into(),
            Value::from(key.device_authorization_endpoint.clone()),
        );
        map.insert("scope".into(), Value::from(key.scope.clone()));
        if let Some(audience) = &key.audience {
            map.insert("audience".into(), Value::from(audience.clone()));
        }
        if let Some(issuer) = &key.issuer {
            map.insert("issuer".into(), Value::from(issuer.clone()));
        }
        map.insert("groups_in_token".into(), Value::from(key.groups_in_token));
        if let Some(t) = &token.access_token {
            map.insert("access_token".into(), Value::from(t.clone()));
        }
        if let Some(t) = &token.id_token {
            map.insert("id_token".into(), Value::from(t.clone()));
        }
        if let Some(t) = &token.refresh_token {
            map.insert("refresh_token".into(), Value::from(t.clone()));
        }
        map.insert(
            "expires_at_millis".into(),
            Value::from(seconds_to_millis(token.expires_at)),
        );
        map.insert(
            "token_ttl_millis".into(),
            Value::from(seconds_to_millis(token.token_ttl)),
        );
        // serde_json escapes `"`, `\` and control chars, so an opaque token string
        // round-trips safely.
        serde_json::to_vec(&Value::Object(map)).unwrap_or_default()
    }

    // -- lock-file protocol -------------------------------------------------

    fn acquire_lock(&self, lock: &Path) -> TokenStoreResult<File> {
        // `lock_acquire_budget` is clamped in `with_lock_timings`, so this add
        // cannot overflow.
        let deadline = Instant::now() + self.lock_acquire_budget;
        loop {
            match create_lock_file(lock) {
                Ok(file) => return Ok(file),
                Err(e)
                    if e.kind() == std::io::ErrorKind::AlreadyExists
                        || is_transient_create_contention(&e) =>
                {
                    if Instant::now() >= deadline {
                        let detail = if self.is_stale(lock) {
                            "the lock appears stale; verify that no holder is active, then remove it manually"
                        } else {
                            "another process still holds the lock"
                        };
                        return Err(Box::new(std::io::Error::new(
                            std::io::ErrorKind::WouldBlock,
                            format!(
                                "could not acquire the OIDC token-store lock {lock:?} within {:?}: {detail}",
                                self.lock_acquire_budget
                            ),
                        )));
                    }
                    std::thread::sleep(LOCK_POLL_SLICE);
                }
                Err(e) => return Err(Box::new(e)),
            }
        }
    }

    fn is_stale(&self, lock: &Path) -> bool {
        // lstat (symlink_metadata): judge a symlink by its OWN mtime; for the
        // regular lock/temp files we create, lstat == stat.
        let Ok(meta) = fs::symlink_metadata(lock) else {
            return false; // can't determine age → report ordinary contention
        };
        let Ok(mtime) = meta.modified() else {
            return false;
        };
        match SystemTime::now().duration_since(mtime) {
            // A future-dated mtime (our clock reads behind the lock's) is
            // untrustworthy; treat as fresh rather than break a possibly-live lock.
            Ok(elapsed) => elapsed > self.lock_stale,
            Err(_) => false,
        }
    }

    /// Run under this identity's filesystem lock. `TokenStore::in_lock` actions
    /// synchronously re-enter `save` and `clear`, so ownership is tracked for the
    /// current thread to avoid trying to acquire our own non-reentrant lock.
    fn with_lock<T>(
        &self,
        key: &TokenStoreKey,
        action: impl FnOnce() -> TokenStoreResult<T>,
    ) -> TokenStoreResult<T> {
        let lock = self.lock_file(key);
        if current_thread_holds(&lock) {
            return action();
        }
        self.ensure_directory()?;
        let file = self.acquire_lock(&lock)?;
        // Drop the thread marker before releasing the filesystem lock. Both are
        // RAII guards, so unwinding through user code preserves that order too.
        let _held = HeldLock {
            lock: lock.clone(),
            file,
        };
        let _scope = HeldLockScope::enter(lock);
        action()
    }

    /// Remove only crash-orphaned temps old enough to be unambiguously stale.
    /// The caller must hold this identity's coordination lock so a cooperating
    /// save cannot still be writing any candidate.
    fn sweep_stale_orphan_temps(&self, key: &TokenStoreKey) -> bool {
        debug_assert!(current_thread_holds(&self.lock_file(key)));
        let hash = key.hash();
        let Ok(entries) = fs::read_dir(&self.directory) else {
            return false;
        };
        let mut removed = false;
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name.starts_with(&hash) && name.ends_with(".tmp") && self.is_stale(&entry.path()) {
                removed |= fs::remove_file(entry.path()).is_ok();
            }
        }
        removed
    }

    fn save_under_lock(&self, key: &TokenStoreKey, content: &[u8]) -> TokenStoreResult<()> {
        debug_assert!(current_thread_holds(&self.lock_file(key)));
        let target = self.token_file(key);
        let tmp = temp_path(&self.directory, &key.hash());
        // create_new + 0600 (POSIX): no world-readable window before the rename.
        let mut opts = OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let write_result = (|| -> std::io::Result<()> {
            let mut f = opts.open(&tmp)?;
            f.write_all(content)?;
            f.flush()?;
            f.sync_all()?; // force to disk before the rename
            fs::rename(&tmp, &target)?; // atomic on POSIX and Windows
            Ok(())
        })();
        if write_result.is_err() {
            let _ = fs::remove_file(&tmp); // clean up the temp on failure
        }
        write_result?;
        // A successful save is a recovery point for plaintext temps left by a
        // crashed predecessor. Fresh temps are retained until their age proves
        // they are not from a live cross-language writer.
        self.sweep_stale_orphan_temps(key);
        let _ = fsync_directory(&self.directory); // best-effort: persist changes
        Ok(())
    }

    fn clear_under_lock(&self, key: &TokenStoreKey) -> TokenStoreResult<()> {
        debug_assert!(current_thread_holds(&self.lock_file(key)));
        let removed = match fs::remove_file(self.token_file(key)) {
            Ok(()) => true,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
            Err(e) => return Err(Box::new(e)),
        };
        let removed_orphans = self.sweep_stale_orphan_temps(key);
        if removed || removed_orphans {
            fsync_directory(&self.directory)?; // make the refresh-parent tombstone durable
        }
        Ok(())
    }
}

impl TokenStore for FileTokenStore {
    fn load(&self, key: &TokenStoreKey) -> TokenStoreResult<Option<PersistedToken>> {
        let path = self.token_file(key);
        let file = match open_regular_bounded(&path)? {
            Some(f) => f,
            None => return Ok(None), // missing / non-regular / empty / oversized
        };
        // Read at most MAX_FILE_BYTES + 1 so an oversized file (grown after the
        // metadata check) is rejected rather than read whole.
        let mut data = Vec::new();
        file.take(MAX_FILE_BYTES + 1)
            .read_to_end(&mut data)
            .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { Box::new(e) })?;
        if data.len() as u64 > MAX_FILE_BYTES {
            return Ok(None);
        }
        Ok(self.parse_and_verify(key, &data))
    }

    fn save(&self, key: &TokenStoreKey, token: &PersistedToken) -> TokenStoreResult<()> {
        let content = self.serialize(key, token);
        if content.len() as u64 > MAX_FILE_BYTES {
            return Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "serialized OIDC token-store entry is {} bytes, exceeding the {MAX_FILE_BYTES}-byte limit",
                    content.len()
                ),
            )));
        }
        self.with_lock(key, || self.save_under_lock(key, &content))
    }

    fn clear(&self, key: &TokenStoreKey) -> TokenStoreResult<()> {
        self.with_lock(key, || self.clear_under_lock(key))
    }

    fn in_lock(
        &self,
        key: &TokenStoreKey,
        action: &mut dyn FnMut() -> TokenStoreResult<()>,
    ) -> TokenStoreResult<()> {
        self.with_lock(key, action)
    }
}

// ---------------------------------------------------------------------------
// Free helpers
// ---------------------------------------------------------------------------

/// Canonicalise an endpoint URL for the cross-language store-key hash:
/// `scheme://host:port/path?query` with scheme and host lower-cased, the port
/// always explicit (443/80 default), and an IPv6 host bracketed. The complete
/// path and query are retained because both are routing-significant parts of an
/// OAuth endpoint's identity.
fn canonical_endpoint(url: &str) -> String {
    let Ok(uri) = url.parse::<ureq::http::Uri>() else {
        return url.to_string();
    };
    let scheme = uri.scheme_str().unwrap_or("").to_ascii_lowercase();
    let mut host = uri.host().unwrap_or("").to_ascii_lowercase();
    // Bracket an IPv6 literal so the host:port boundary is unambiguous and matches
    // the bracketed authority form the other clients render.
    if host.contains(':') && !host.starts_with('[') {
        host = format!("[{host}]");
    }
    let default_port = match scheme.as_str() {
        "https" => Some(443),
        "http" => Some(80),
        _ => None,
    };
    let port = uri.port_u16().or(default_port);
    // Preserve the byte-exact request target. In particular, `/token` and
    // `/token/` can be different resources, and OAuth explicitly permits a token
    // endpoint to carry a routing-significant query component.
    let path_and_query = uri
        .path_and_query()
        .map(|value| value.as_str())
        .unwrap_or_else(|| uri.path());
    match port {
        Some(port) => format!("{scheme}://{host}:{port}{path_and_query}"),
        None => format!("{scheme}://{host}{path_and_query}"),
    }
}

/// Order-normalise a space-separated scope (sort the token set) so two spellings
/// of the same scope set are one identity.
fn normalize_scope(scope: &str) -> String {
    let mut tokens: Vec<&str> = scope.split_whitespace().collect();
    tokens.sort_unstable();
    tokens.join(" ")
}

/// A persisted JSON field as a non-empty string, else `None` (a non-string —
/// from a hand-edited or hostile file — reads as absent rather than landing in a
/// token field as a raw object).
fn nonempty_str(value: Option<&Value>) -> Option<String> {
    match value {
        Some(Value::String(s)) if !s.is_empty() => Some(s.clone()),
        _ => None,
    }
}

/// True if an optional key field matches an on-disk field: the file omits a null
/// value, so an absent field matches a `None` key; a present value must be an
/// exact string match, and a non-string file value never matches.
fn opt_str_matches(key_value: Option<&str>, file_value: Option<&Value>) -> bool {
    match key_value {
        None => file_value.is_none() || matches!(file_value, Some(Value::Null)),
        Some(k) => file_value.and_then(Value::as_str) == Some(k),
    }
}

/// Epoch/duration seconds as an on-disk `*_millis` integer; a non-finite value
/// maps to `0` (which reads back as expired).
fn seconds_to_millis(seconds: f64) -> i64 {
    if !seconds.is_finite() {
        return 0;
    }
    let millis = (seconds * 1000.0).round();
    if millis < i64::MIN as f64 || millis > i64::MAX as f64 {
        return 0;
    }
    millis as i64
}

/// An on-disk `*_millis` field as epoch/duration seconds; a non-numeric or
/// non-finite value (a hostile file) reads as `0.0`, marking the entry expired so
/// it falls through to a refresh rather than being served.
fn millis_to_seconds(value: Option<&Value>) -> f64 {
    let n = match value {
        Some(Value::Number(n)) => n,
        _ => return 0.0,
    };
    let millis = n.as_i64().map(|i| i as f64).or_else(|| n.as_f64());
    match millis {
        Some(m) if m.is_finite() => m / 1000.0,
        _ => 0.0,
    }
}

/// A unique sibling temp path under `dir` for an atomic write.
fn temp_path(dir: &Path, hash: &str) -> PathBuf {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    dir.join(format!("{hash}.{}.{n}.{nanos}.tmp", std::process::id()))
}

fn create_lock_file(lock: &Path) -> std::io::Result<File> {
    // The create_new (O_CREAT|O_EXCL) IS the acquisition; write the holder bytes
    // through this same handle. Holder bytes are diagnostic-only (staleness is
    // judged by mtime). The handle is returned so release can verify that the path
    // still names the exact file we acquired.
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(lock)?;
    let _ = f.write_all(holder_bytes().as_bytes());
    Ok(f)
}

/// A failed `create_new` acquisition that reflects momentary contention rather than
/// a settled "someone else holds it" (`AlreadyExists`), so the contender must keep
/// polling until the deadline instead of surfacing the error.
///
/// On Windows a lock file that its departing holder has just unlinked lingers in a
/// "delete pending" state until the holder's last open handle closes. During that
/// window a concurrent `create_new` on the same path fails with `ERROR_ACCESS_DENIED`
/// (`PermissionDenied`) instead of `AlreadyExists`, and the name frees up a moment
/// later once the release completes. On Unix an unlink takes effect immediately and a
/// `create_new` `PermissionDenied` always signals a genuine directory-permission
/// problem, so it is surfaced rather than retried.
#[cfg(windows)]
fn is_transient_create_contention(e: &std::io::Error) -> bool {
    e.kind() == std::io::ErrorKind::PermissionDenied
}

#[cfg(not(windows))]
fn is_transient_create_contention(_e: &std::io::Error) -> bool {
    false
}

/// Owns one successfully acquired lock for exactly the lifetime of the critical
/// section. In particular, unwinding through a user-provided `in_lock` action
/// still runs the ownership-checked release.
struct HeldLock {
    lock: PathBuf,
    file: File,
}

impl Drop for HeldLock {
    fn drop(&mut self) {
        release_lock(&self.lock, &self.file);
    }
}

std::thread_local! {
    /// Filesystem locks owned by this thread. `in_lock` actions are synchronous,
    /// so this is a precise re-entrancy proof rather than a process-wide guess
    /// based on the mere presence of a lock pathname.
    static HELD_LOCKS: RefCell<Vec<PathBuf>> = const { RefCell::new(Vec::new()) };
}

fn current_thread_holds(lock: &Path) -> bool {
    HELD_LOCKS.with(|held| held.borrow().iter().any(|candidate| candidate == lock))
}

/// Marks the dynamic scope in which this thread owns a filesystem lock.
struct HeldLockScope {
    lock: PathBuf,
}

impl HeldLockScope {
    fn enter(lock: PathBuf) -> Self {
        HELD_LOCKS.with(|held| {
            let mut held = held.borrow_mut();
            debug_assert!(!held.contains(&lock));
            held.push(lock.clone());
        });
        Self { lock }
    }
}

impl Drop for HeldLockScope {
    fn drop(&mut self) {
        HELD_LOCKS.with(|held| {
            let mut held = held.borrow_mut();
            let position = held
                .iter()
                .rposition(|candidate| candidate == &self.lock)
                .expect("held OIDC token-store lock marker disappeared");
            held.remove(position);
        });
    }
}

/// Release a held lock by unlinking it — but only when the path still resolves to
/// the exact file we created. Another language client or operator may have removed
/// and recreated the pathname while this action was running; unlinking by path
/// alone would then delete the successor's live lock and admit a second holder.
/// Comparing filesystem identity avoids deleting a successor already present
/// when release begins. This implementation never replaces a held lock itself;
/// that is also why stale locks are reported instead of stolen automatically.
#[cfg(unix)]
fn release_lock(lock: &Path, held: &File) {
    use std::os::unix::fs::MetadataExt;
    let ours = held.metadata().ok();
    let at_path = fs::symlink_metadata(lock).ok();
    if let (Some(ours), Some(at_path)) = (ours, at_path)
        && ours.dev() == at_path.dev()
        && ours.ino() == at_path.ino()
    {
        let _ = fs::remove_file(lock);
    }
}

#[cfg(windows)]
fn release_lock(lock: &Path, held: &File) {
    let at_path = File::open(lock).ok();
    if at_path.as_ref().is_some_and(|at_path| {
        windows_file_identity(held)
            .zip(windows_file_identity(at_path))
            .is_some_and(|(ours, current)| ours == current)
    }) {
        let _ = fs::remove_file(lock);
    }
}

#[cfg(windows)]
fn windows_file_identity(file: &File) -> Option<(u32, u64)> {
    use std::mem::MaybeUninit;
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle,
    };

    let mut info = MaybeUninit::<BY_HANDLE_FILE_INFORMATION>::uninit();
    // SAFETY: `file` keeps the OS handle valid for the call, and `info` points to
    // writable storage of the exact structure the Windows API initialises.
    let ok = unsafe { GetFileInformationByHandle(file.as_raw_handle(), info.as_mut_ptr()) };
    if ok == 0 {
        return None;
    }
    // SAFETY: a non-zero return means Windows initialised the whole structure.
    let info = unsafe { info.assume_init() };
    let index = (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow);
    Some((info.dwVolumeSerialNumber, index))
}

#[cfg(not(any(unix, windows)))]
fn release_lock(_lock: &Path, _held: &File) {
    // The crate's supported desktop/server targets are Unix and Windows. On an
    // unknown std target, leaking the lock is safer than path-only deletion,
    // which could remove a successor's lock and admit concurrent refreshes.
}

fn holder_bytes() -> String {
    let nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("{}@{} {nanos}", std::process::id(), hostname())
}

/// Open a file for reading only if it is a regular file within the size bound;
/// `None` for a missing / non-regular / empty / oversized entry (per the load
/// contract), `Err` only for a genuine I/O error.
fn open_regular_bounded(path: &Path) -> TokenStoreResult<Option<File>> {
    // Open first (with O_NONBLOCK on unix so a FIFO swapped in doesn't hang the
    // thread), then fstat the OPENED handle — closing the stat→open TOCTOU.
    let mut opts = OpenOptions::new();
    opts.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(libc::O_NONBLOCK);
    }
    let file = match opts.open(path) {
        Ok(f) => f,
        Err(e)
            if matches!(
                e.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::InvalidInput
            ) =>
        {
            return Ok(None);
        }
        Err(e) => return Err(Box::new(e)),
    };
    let meta = file.metadata().map_err(Box::new)?;
    if !meta.is_file() || meta.len() == 0 || meta.len() > MAX_FILE_BYTES {
        return Ok(None);
    }
    Ok(Some(file))
}

/// SHA-256 hex digest using the crate's configured crypto provider.
#[cfg(feature = "ring-crypto")]
fn sha256_hex(input: &[u8]) -> String {
    to_hex(ring::digest::digest(&ring::digest::SHA256, input).as_ref())
}

#[cfg(all(feature = "aws-lc-crypto", not(feature = "ring-crypto")))]
fn sha256_hex(input: &[u8]) -> String {
    to_hex(aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, input).as_ref())
}

fn to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(char::from_digit((b >> 4) as u32, 16).unwrap());
        out.push(char::from_digit((b & 0x0f) as u32, 16).unwrap());
    }
    out
}

/// The user's home directory (`HOME` on unix, `USERPROFILE` on Windows), only if
/// absolute — a relative value would create a surprise `~`-like dir under the cwd.
fn home_dir() -> Option<PathBuf> {
    #[cfg(unix)]
    let raw = std::env::var_os("HOME");
    #[cfg(windows)]
    let raw = std::env::var_os("USERPROFILE");
    #[cfg(not(any(unix, windows)))]
    let raw: Option<std::ffi::OsString> = None;
    let path = PathBuf::from(raw?);
    if path.is_absolute() { Some(path) } else { None }
}

fn hostname() -> String {
    std::env::var("HOSTNAME")
        .ok()
        .filter(|h| !h.is_empty())
        .unwrap_or_else(|| "localhost".to_string())
}

#[cfg(unix)]
fn create_dir_all_private(dir: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
}

#[cfg(not(unix))]
fn create_dir_all_private(dir: &Path) -> std::io::Result<()> {
    warn_no_posix_perms_once();
    fs::create_dir_all(dir)
}

/// Create a single directory (non-recursive) with owner-only perms. Non-recursive
/// so an existing symlink planted at `dir` fails with `AlreadyExists` instead of
/// being followed — the parent chain must already exist.
#[cfg(unix)]
fn create_dir_private(dir: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    fs::DirBuilder::new().mode(0o700).create(dir)
}

#[cfg(not(unix))]
fn create_dir_private(dir: &Path) -> std::io::Result<()> {
    warn_no_posix_perms_once();
    fs::create_dir(dir)
}

/// The error returned when the store leaf is (or races to become) a symlink.
fn symlink_leaf_error() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        "the OIDC token store path is a symbolic link; refusing to use it because \
         the plaintext token files could be redirected outside the owner-only \
         directory",
    )
}

#[cfg(unix)]
fn restrict_to_owner(dir: &Path) {
    use std::os::unix::fs::PermissionsExt;
    // Best-effort: a directory not ours to chmod keeps its perms; each file's own
    // 0600 mode still protects its content.
    let _ = fs::set_permissions(dir, fs::Permissions::from_mode(0o700));
}

#[cfg(not(unix))]
fn restrict_to_owner(_dir: &Path) {
    warn_no_posix_perms_once();
}

#[cfg(unix)]
fn fsync_directory(dir: &Path) -> std::io::Result<()> {
    File::open(dir)?.sync_all()
}

#[cfg(not(unix))]
fn fsync_directory(_dir: &Path) -> std::io::Result<()> {
    Ok(())
}

#[cfg(not(unix))]
fn warn_no_posix_perms_once() {
    static WARNED: AtomicBool = AtomicBool::new(false);
    if !WARNED.swap(true, Ordering::Relaxed) {
        log::warn!(
            "questdb oidc: the token store could not enforce owner-only (0600/0700) \
             permissions on this filesystem; the persisted refresh token is protected \
             only by the directory's default ACL. Back the store with an OS keychain \
             for at-rest encryption."
        );
    }
}

// Referenced only on non-unix; silence the unused warning on unix.
#[cfg(unix)]
#[allow(dead_code)]
fn warn_no_posix_perms_once() {
    let _ = AtomicBool::new(false);
}

#[cfg(test)]
mod tests;
