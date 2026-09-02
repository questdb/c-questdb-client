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
use std::collections::HashMap;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, TryLockError};
use std::time::{Duration, Instant, SystemTime};

use serde_json::Value;
use zeroize::{Zeroize, Zeroizing};

/// The environment variable that overrides the default token-store directory.
/// Uses Java's exact configuration key so every client selects the same store.
pub const TOKEN_STORE_DIR_ENV: &str = "questdb.client.oidc.token.store.dir";

const SCHEMA_VERSION: i64 = 1;
const CANONICAL_PREFIX: &str = "questdb-oidc-token-v1";

/// Cap on a token-store file. An id token with many group claims is a few KiB;
/// 1 MiB is ample while refusing to persist or read an oversized file.
const MAX_FILE_BYTES: u64 = 1 << 20;
const MAX_LOCK_FILE_BYTES: u64 = 1 << 12;

const DIRECTORY_LOCK_FILE_NAME: &str = ".store.lock";
const UNTRUSTED_SENTINEL_NAME: &str = ".untrusted";
const DIRECTORY_LOCK_HEARTBEAT: Duration = Duration::from_millis(500);
const DIRECTORY_LOCK_STALE: Duration = Duration::from_secs(2);
const DIRECTORY_LOCK_EMPTY_GRACE: Duration = Duration::from_secs(2);
const EMPTY_LOCK_GRACE: Duration = Duration::from_secs(5);

/// How long to spin trying to acquire a lock file. The directory lock is
/// required; the per-identity refresh lock degrades to atomic replacement after
/// this budget, matching the Java reference implementation.
const DEFAULT_LOCK_ACQUIRE_BUDGET: Duration = Duration::from_secs(3);
/// Java caps the configurable budget at 30 seconds; use the same ceiling so the
/// two clients have the same producer-path bound.
const MAX_LOCK_ACQUIRE_BUDGET: Duration = Duration::from_secs(30);
const LOCK_POLL_SLICE: Duration = Duration::from_millis(50);

/// A lock older than this is considered abandoned and reclaimed through the
/// Java-compatible capture-then-verify protocol.
const DEFAULT_LOCK_STALE: Duration = Duration::from_secs(600);
/// A configured staleness window below this is clamped up — see
/// [`FileTokenStore::with_lock_timings`].
const MIN_LOCK_STALE: Duration = Duration::from_secs(300);

/// The result of a [`TokenStore`] operation. Lazy-load and fresh-sign-in
/// persistence is best-effort. Coordination and pre-refresh load/clear failures
/// are surfaced as retryable token-acquisition errors so a refresh never runs
/// concurrently or reuses an ambiguously rotated parent.
pub type TokenStoreResult<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

fn cancelled_error() -> Box<dyn std::error::Error + Send + Sync> {
    Box::new(std::io::Error::new(
        std::io::ErrorKind::Interrupted,
        "OIDC authentication was closed while waiting for the token store",
    ))
}

fn never_cancelled() -> bool {
    false
}

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

impl Drop for PersistedToken {
    fn drop(&mut self) {
        // Scrub the persisted secrets from the heap when this carrier is dropped
        // (after a save, or after a load hands the token on to the cache). Each
        // `Option<String>::zeroize()` overwrites the string buffer.
        self.access_token.zeroize();
        self.id_token.zeroize();
        self.refresh_token.zeroize();
    }
}

// ---------------------------------------------------------------------------
// TokenStoreKey
// ---------------------------------------------------------------------------

/// The non-secret identity a persisted token belongs to.
///
/// A [`TokenStore`] keys its entries by this so a token minted for one server /
/// identity provider / scope / audience is never served to a process configured
/// for another. [`from_config`](Self::from_config) canonicalises the endpoints
/// exactly as [`OidcDeviceAuth`](crate::oidc::OidcDeviceAuth) does; it preserves
/// the configured scope because the frozen Java-compatible identity treats its
/// spelling and order as significant.
///
/// [`hash`](Self::hash) is a stable lowercase-hex SHA-256 over a canonical,
/// NUL-separated rendering of the fields, identical across QuestDB client
/// implementations, so processes (and languages) sharing one identity address the
/// same persisted entry. `issuer` is retained as configuration metadata for API
/// compatibility but is deliberately not part of the frozen store identity: the
/// Java reference contract identifies a credential by its concrete token/device
/// endpoints and the other fields below.
#[derive(Clone, Debug)]
pub struct TokenStoreKey {
    client_id: String,
    token_endpoint: String,
    device_authorization_endpoint: String,
    scope: String,
    audience: Option<String>,
    groups_in_token: bool,
    issuer: Option<String>,
}

impl PartialEq for TokenStoreKey {
    fn eq(&self, other: &Self) -> bool {
        self.client_id == other.client_id
            && self.token_endpoint == other.token_endpoint
            && self.device_authorization_endpoint == other.device_authorization_endpoint
            && self.scope == other.scope
            && self.audience == other.audience
            && self.groups_in_token == other.groups_in_token
    }
}

impl Eq for TokenStoreKey {}

impl TokenStoreKey {
    /// Build a key from raw identity fields, canonicalising the endpoints while
    /// preserving the configured scope byte-for-byte. Scope order is significant
    /// in the frozen Java-compatible persistence contract.
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
            scope: scope.to_string(),
            audience: audience
                .filter(|value| !value.is_empty())
                .map(str::to_string),
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

    /// The configured scope, preserved byte-for-byte for Java compatibility.
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
        // not folded in: concrete endpoints, not the optional trust pin used to
        // discover/validate them, are part of the Java-compatible identity.
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
/// refresh, load/clear failures are retryable and abort the attempt; failure to
/// acquire a best-effort cross-process refresh lock may instead degrade to the
/// store's atomic replacement layer.
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

    /// Cancellable form of [`load`](Self::load). Custom stores may override
    /// this to abandon an interruptible backend wait promptly when `cancelled`
    /// becomes true. The default preserves source compatibility and checks the
    /// signal before and after the ordinary operation.
    fn load_cancellable(
        &self,
        key: &TokenStoreKey,
        cancelled: &dyn Fn() -> bool,
    ) -> TokenStoreResult<Option<PersistedToken>> {
        if cancelled() {
            return Err(cancelled_error());
        }
        let result = self.load(key);
        if cancelled() {
            return Err(cancelled_error());
        }
        result
    }

    /// Cancellable form of [`save`](Self::save). See
    /// [`load_cancellable`](Self::load_cancellable).
    fn save_cancellable(
        &self,
        key: &TokenStoreKey,
        token: &PersistedToken,
        cancelled: &dyn Fn() -> bool,
    ) -> TokenStoreResult<()> {
        if cancelled() {
            return Err(cancelled_error());
        }
        let result = self.save(key, token);
        if cancelled() {
            return Err(cancelled_error());
        }
        result
    }

    /// Cancellable form of [`clear`](Self::clear). See
    /// [`load_cancellable`](Self::load_cancellable).
    fn clear_cancellable(
        &self,
        key: &TokenStoreKey,
        cancelled: &dyn Fn() -> bool,
    ) -> TokenStoreResult<()> {
        if cancelled() {
            return Err(cancelled_error());
        }
        let result = self.clear(key);
        if cancelled() {
            return Err(cancelled_error());
        }
        result
    }

    /// Run `action` while holding a cross-process lock scoped to `key`, so a
    /// refresh by another process sharing this identity is observed rather than
    /// raced, and return its result.
    ///
    /// Stores should coordinate all processes sharing their backing state. The
    /// file implementation follows the frozen Java contract: it waits for a
    /// bounded time, then invokes `action` under its in-process lock without the
    /// cross-process lock, relying on atomic replacement rather than stalling a
    /// sign-in indefinitely. That fallback can cause one extra sign-in with an
    /// IdP that rotates and reuse-detects refresh tokens.
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

    /// Cancellable form of [`in_lock`](Self::in_lock). The bundled
    /// [`FileTokenStore`] observes the signal while waiting for both its
    /// in-process and filesystem locks. Custom stores that can interrupt their
    /// coordination wait should override this method; the default checks only
    /// before and after the existing `in_lock` call.
    fn in_lock_cancellable(
        &self,
        key: &TokenStoreKey,
        cancelled: &dyn Fn() -> bool,
        action: &mut dyn FnMut() -> TokenStoreResult<()>,
    ) -> TokenStoreResult<()> {
        if cancelled() {
            return Err(cancelled_error());
        }
        let result = self.in_lock(key, action);
        if cancelled() {
            return Err(cancelled_error());
        }
        result
    }
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
/// `questdb.client.oidc.token.store.dir` environment variable. The file name is
/// `<TokenStoreKey::hash()>.json`, so several identities coexist and the name
/// leaks neither the endpoint nor the client id.
///
/// [`save`](FileTokenStore::save) writes a sibling temp file then atomically
/// renames it over the target, so a crash or an overlapping reader — in any
/// process or language — sees the whole old or whole new file, never a torn
/// credential. Every load and save also takes Java's required `.store.lock`,
/// which serializes directory trust recovery and prevents a recovery sweep from
/// deleting a peer's completed save. A group/other-writable directory is marked
/// `.untrusted`, tightened, and swept before its contents can be trusted.
///
/// Per-identity refresh locks use `O_CREAT|O_EXCL`, bounded owner stamps,
/// owner-verified release, and the shared capture-then-verify stale-lock recovery
/// protocol. If one cannot be acquired within the configured budget, refresh
/// continues using the atomic-file layer; a required directory-lock failure is
/// returned.
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

    /// A store at the directory named by the
    /// `questdb.client.oidc.token.store.dir` environment variable when set,
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
    /// treated as abandoned and reclaimed and when a crash-orphaned token temp
    /// file becomes eligible for cleanup. A tighter value is clamped up to the
    /// 5-minute floor. `acquire_budget` is clamped down to 30 seconds.
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

    /// Ensure the store directory exists, but do not tighten a pre-existing
    /// directory yet. Its old permission verdict must be observed while holding
    /// `.store.lock`, otherwise two clients can race recovery and one can sweep a
    /// token the other has just saved.
    fn create_directory(&self) -> std::io::Result<()> {
        // lstat the leaf: a symlink planted at the store path would have us write
        // (and chmod) the link's target, outside any directory we own. Only the
        // final component is checked, so a symlinked parent (the whole store moved
        // via the env var) still works.
        match fs::symlink_metadata(&self.directory) {
            Ok(meta) if meta.file_type().is_symlink() => {
                return Err(symlink_leaf_error());
            }
            Ok(meta) if meta.is_dir() => return Ok(()),
            Ok(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "the OIDC token store path is not a directory",
                ));
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
        Ok(())
    }

    fn parse_and_verify(&self, key: &TokenStoreKey, data: &[u8]) -> Option<PersistedToken> {
        let mut root = serde_json::from_slice::<Value>(data).ok()?;
        // Extract under an immutable borrow; the returned PersistedToken owns its
        // own copies (zeroized by its own Drop).
        let result = (|| {
            let obj = root.as_object()?;
            // The shared schema is one flat object. Reject arrays and nested
            // objects even in unknown fields so Java and Rust agree on which
            // documents are usable.
            if obj
                .values()
                .any(|value| value.is_array() || value.is_object())
            {
                return None;
            }
            // Schema and fingerprint must match the live identity; a mismatch is a
            // hash collision or a file copied from a different identity, so ignore
            // it rather than serve the wrong identity's token.
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
        })();
        // On every path (including a validation miss) scrub the secret strings
        // the parser cloned out of `data` before the JSON tree is dropped.
        if let Some(obj) = root.as_object_mut() {
            for field in ["access_token", "id_token", "refresh_token"] {
                if let Some(Value::String(secret)) = obj.get_mut(field) {
                    secret.zeroize();
                }
            }
        }
        result
    }

    fn serialize(&self, key: &TokenStoreKey, token: &PersistedToken) -> Zeroizing<Vec<u8>> {
        // A null value (an absent audience, or a token kind the grant did
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
        // round-trips safely. Wrap the write buffer in `Zeroizing` so the
        // plaintext bytes are scrubbed once the caller has written them. Serialize
        // `&map` (not a moved `Value::Object(map)`, byte-identical output) so the
        // map survives the call and its cloned secret strings can be scrubbed too.
        let bytes = Zeroizing::new(serde_json::to_vec(&map).unwrap_or_default());
        for field in ["access_token", "id_token", "refresh_token"] {
            if let Some(Value::String(secret)) = map.get_mut(field) {
                secret.zeroize();
            }
        }
        bytes
    }

    // -- lock-file protocol -------------------------------------------------

    fn acquire_lock(
        &self,
        lock: &Path,
        required: bool,
        stale_after: Duration,
        empty_grace: Duration,
        cancelled: &dyn Fn() -> bool,
    ) -> TokenStoreResult<Option<HeldLock>> {
        // `lock_acquire_budget` is clamped in `with_lock_timings`, so this add
        // cannot overflow.
        let deadline = Instant::now() + self.lock_acquire_budget;
        let stamp = holder_bytes()?;
        loop {
            if cancelled() {
                return Err(cancelled_error());
            }
            match create_lock_file(lock, &stamp) {
                Ok(()) => {
                    return Ok(Some(HeldLock {
                        lock: lock.to_path_buf(),
                        stamp,
                    }));
                }
                Err(e)
                    if e.kind() == std::io::ErrorKind::AlreadyExists
                        || is_transient_create_contention(&e) =>
                {
                    // Java uses this same capture-then-verify reclaim protocol.
                    // It handles a killed peer without a path-only delete that
                    // could displace a freshly-created successor lock.
                    let _ = steal_if_stale(lock, stale_after, empty_grace);
                    if Instant::now() >= deadline {
                        if required {
                            return Err(Box::new(std::io::Error::new(
                                std::io::ErrorKind::WouldBlock,
                                format!(
                                    "could not acquire the required OIDC token-store lock {lock:?} within {:?}",
                                    self.lock_acquire_budget
                                ),
                            )));
                        }
                        log::warn!(
                            "questdb oidc: could not acquire the token-store lock {:?}; running this refresh without cross-process coordination",
                            lock
                        );
                        return Ok(None);
                    }
                    std::thread::sleep(LOCK_POLL_SLICE);
                }
                Err(e) if required => return Err(Box::new(e)),
                Err(e) => {
                    log::warn!(
                        "questdb oidc: could not acquire the token-store lock {:?}; running this refresh without cross-process coordination: {}",
                        lock,
                        e
                    );
                    return Ok(None);
                }
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

    fn directory_lock_file(&self) -> PathBuf {
        self.directory.join(DIRECTORY_LOCK_FILE_NAME)
    }

    fn untrusted_sentinel(&self) -> PathBuf {
        self.directory.join(UNTRUSTED_SENTINEL_NAME)
    }

    fn with_directory_lock<T>(
        &self,
        cancelled: &dyn Fn() -> bool,
        action: impl FnOnce(bool) -> TokenStoreResult<T>,
    ) -> TokenStoreResult<T> {
        if cancelled() {
            return Err(cancelled_error());
        }
        self.create_directory()?;
        let lock = self.directory_lock_file();
        let process_lock = process_lock_for(&lock);
        let _process_guard = lock_process_cancellable(&process_lock, cancelled)?;
        let short_lease = directory_is_owner_only(&self.directory)
            && path_is_definitely_absent(&self.untrusted_sentinel());
        let stale_after = if short_lease {
            DIRECTORY_LOCK_STALE
        } else {
            self.lock_stale
        };
        let empty_grace = if short_lease {
            DIRECTORY_LOCK_EMPTY_GRACE
        } else {
            EMPTY_LOCK_GRACE
        };
        let held = self
            .acquire_lock(&lock, true, stale_after, empty_grace, cancelled)?
            .expect("a required lock never degrades");
        let scope = HeldLockScope::enter(lock.clone());

        let trusted = prepare_directory_trust(&self.directory, &self.untrusted_sentinel())?;
        if !lock_is_owned(&lock, &held.stamp) {
            if !trusted {
                let _ = mark_untrusted(&self.untrusted_sentinel());
            }
            drop(scope);
            drop(held);
            return Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "lost ownership of the OIDC token-store directory lock while tightening permissions",
            )));
        }

        let heartbeat = DirectoryLockHeartbeat::start(lock, held.stamp.clone());
        if !trusted {
            discard_untrusted_directory_contents(&self.directory, &self.untrusted_sentinel());
        }
        let result = if cancelled() {
            Err(cancelled_error())
        } else {
            action(trusted)
        };
        drop(heartbeat);
        drop(scope);
        drop(held);
        result
    }

    fn prepare_directory(&self, cancelled: &dyn Fn() -> bool) -> TokenStoreResult<()> {
        self.with_directory_lock(cancelled, |_| Ok(()))
    }

    /// Run under this identity's process and filesystem locks. The filesystem
    /// lock follows Java's best-effort Layer 2 contract: after the bounded wait,
    /// the action still runs under the in-process lock and atomic-file Layer 1.
    fn with_lock<T>(
        &self,
        key: &TokenStoreKey,
        cancelled: &dyn Fn() -> bool,
        action: impl FnOnce() -> TokenStoreResult<T>,
    ) -> TokenStoreResult<T> {
        if cancelled() {
            return Err(cancelled_error());
        }
        let lock = self.lock_file(key);
        if current_thread_holds(&lock) {
            if cancelled() {
                return Err(cancelled_error());
            }
            return action();
        }
        let process_lock = process_lock_for(&lock);
        let _process_guard = lock_process_cancellable(&process_lock, cancelled)?;
        let _scope = HeldLockScope::enter(lock.clone());
        self.prepare_directory(cancelled)?;
        let held = self.acquire_lock(&lock, false, self.lock_stale, EMPTY_LOCK_GRACE, cancelled)?;
        let result = if cancelled() {
            Err(cancelled_error())
        } else {
            action()
        };
        drop(held);
        result
    }

    /// Remove only crash-orphaned temps old enough to be unambiguously stale.
    /// The caller holds the directory lock, so a cooperating save cannot still
    /// be writing any candidate. Never touch `.lock.*.tmp` steal captures.
    fn sweep_orphan_temps(&self, key: &TokenStoreKey, stale_only: bool) -> bool {
        debug_assert!(current_thread_holds(&self.directory_lock_file()));
        let hash = key.hash();
        let Ok(entries) = fs::read_dir(&self.directory) else {
            return false;
        };
        let mut removed = false;
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name.starts_with(&hash)
                && name.ends_with(".tmp")
                && !name.contains(".lock.")
                && (!stale_only || self.is_stale(&entry.path()))
            {
                removed |= fs::remove_file(entry.path()).is_ok();
            }
        }
        removed
    }

    fn save_under_lock(&self, key: &TokenStoreKey, content: &[u8]) -> TokenStoreResult<()> {
        debug_assert!(current_thread_holds(&self.directory_lock_file()));
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
        self.sweep_orphan_temps(key, true);
        let _ = fsync_directory(&self.directory); // best-effort: persist changes
        Ok(())
    }

    fn clear_under_lock(&self, key: &TokenStoreKey) -> TokenStoreResult<()> {
        debug_assert!(current_thread_holds(&self.directory_lock_file()));
        let removed = match fs::remove_file(self.token_file(key)) {
            Ok(()) => true,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
            Err(e) => return Err(Box::new(e)),
        };
        let removed_orphans = self.sweep_orphan_temps(key, false);
        if removed || removed_orphans {
            fsync_directory(&self.directory)?; // make the refresh-parent tombstone durable
        }
        Ok(())
    }
}

impl TokenStore for FileTokenStore {
    fn load(&self, key: &TokenStoreKey) -> TokenStoreResult<Option<PersistedToken>> {
        self.load_cancellable(key, &never_cancelled)
    }

    fn load_cancellable(
        &self,
        key: &TokenStoreKey,
        cancelled: &dyn Fn() -> bool,
    ) -> TokenStoreResult<Option<PersistedToken>> {
        self.with_directory_lock(cancelled, |trusted| {
            if !trusted {
                return Ok(None);
            }
            let path = self.token_file(key);
            let file = match open_regular_bounded(&path)? {
                Some(f) => f,
                None => return Ok(None), // missing / non-regular / empty / oversized
            };
            // Read at most MAX_FILE_BYTES + 1 so an oversized file (grown after
            // the metadata check) is rejected rather than read whole.
            let mut data = Zeroizing::new(Vec::new());
            file.take(MAX_FILE_BYTES + 1)
                .read_to_end(&mut data)
                .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { Box::new(e) })?;
            if data.len() as u64 > MAX_FILE_BYTES {
                return Ok(None);
            }
            Ok(self.parse_and_verify(key, &data))
        })
    }

    fn save(&self, key: &TokenStoreKey, token: &PersistedToken) -> TokenStoreResult<()> {
        self.save_cancellable(key, token, &never_cancelled)
    }

    fn save_cancellable(
        &self,
        key: &TokenStoreKey,
        token: &PersistedToken,
        cancelled: &dyn Fn() -> bool,
    ) -> TokenStoreResult<()> {
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
        self.with_directory_lock(cancelled, |_| {
            self.sweep_orphan_temps(key, true);
            self.save_under_lock(key, &content)
        })
    }

    fn clear(&self, key: &TokenStoreKey) -> TokenStoreResult<()> {
        self.clear_cancellable(key, &never_cancelled)
    }

    fn clear_cancellable(
        &self,
        key: &TokenStoreKey,
        cancelled: &dyn Fn() -> bool,
    ) -> TokenStoreResult<()> {
        if cancelled() {
            return Err(cancelled_error());
        }
        if !self.directory.is_dir() {
            return Ok(());
        }
        self.with_lock(key, cancelled, || {
            self.with_directory_lock(cancelled, |_| self.clear_under_lock(key))
        })
    }

    fn in_lock(
        &self,
        key: &TokenStoreKey,
        action: &mut dyn FnMut() -> TokenStoreResult<()>,
    ) -> TokenStoreResult<()> {
        self.in_lock_cancellable(key, &never_cancelled, action)
    }

    fn in_lock_cancellable(
        &self,
        key: &TokenStoreKey,
        cancelled: &dyn Fn() -> bool,
        action: &mut dyn FnMut() -> TokenStoreResult<()>,
    ) -> TokenStoreResult<()> {
        self.with_lock(key, cancelled, action)
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

/// An on-disk `*_millis` field as epoch/duration seconds. The frozen format
/// permits plain JSON integers only; floats and exponent notation are rejected
/// by returning `0.0`, marking the entry expired.
fn millis_to_seconds(value: Option<&Value>) -> f64 {
    value
        .and_then(Value::as_i64)
        .map(|millis| millis as f64 / 1000.0)
        .unwrap_or(0.0)
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

fn create_lock_file(lock: &Path, stamp: &str) -> std::io::Result<()> {
    // The exclusive create is the acquisition. The file necessarily exists
    // empty for a tiny create-to-stamp window; the shared empty-lock grace is
    // what protects a creator paused in that window.
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(lock)?;
    f.write_all(stamp.as_bytes())
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
    stamp: String,
}

impl Drop for HeldLock {
    fn drop(&mut self) {
        release_lock(&self.lock, &self.stamp);
    }
}

/// In-process serialization keyed by the same lock pathname used between
/// processes. The filesystem protocol is not re-entrant and Rust callers can
/// otherwise contend with another thread in the same process unnecessarily.
fn process_lock_for(lock: &Path) -> Arc<Mutex<()>> {
    static LOCKS: OnceLock<Mutex<HashMap<PathBuf, Arc<Mutex<()>>>>> = OnceLock::new();
    let locks = LOCKS.get_or_init(|| Mutex::new(HashMap::new()));
    let mut locks = locks.lock().unwrap_or_else(|e| e.into_inner());
    locks
        .entry(lock.to_path_buf())
        .or_insert_with(|| Arc::new(Mutex::new(())))
        .clone()
}

fn lock_process_cancellable<'a>(
    lock: &'a Mutex<()>,
    cancelled: &dyn Fn() -> bool,
) -> TokenStoreResult<MutexGuard<'a, ()>> {
    loop {
        if cancelled() {
            return Err(cancelled_error());
        }
        match lock.try_lock() {
            Ok(guard) => return Ok(guard),
            Err(TryLockError::Poisoned(error)) => return Ok(error.into_inner()),
            Err(TryLockError::WouldBlock) => std::thread::sleep(LOCK_POLL_SLICE),
        }
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

/// Delete the canonical lock only while it still carries our exact owner stamp.
/// Java makes the same byte-for-byte check, so neither implementation can delete
/// a successor created after a stale-lock handover.
fn release_lock(lock: &Path, stamp: &str) {
    if lock_is_owned(lock, stamp) {
        let _ = fs::remove_file(lock);
    }
}

fn holder_bytes() -> std::io::Result<String> {
    let mut nonce = [0_u8; 16];
    fill_random_lock_nonce(&mut nonce)?;
    let nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    Ok(format!(
        "{nanos} {} {}@{}",
        to_hex(&nonce),
        std::process::id(),
        hostname()
    ))
}

#[cfg(feature = "ring-crypto")]
fn fill_random_lock_nonce(nonce: &mut [u8]) -> std::io::Result<()> {
    use ring::rand::SecureRandom;
    ring::rand::SystemRandom::new()
        .fill(nonce)
        .map_err(|_| std::io::Error::other("could not generate an OIDC lock owner nonce"))
}

#[cfg(all(feature = "aws-lc-crypto", not(feature = "ring-crypto")))]
fn fill_random_lock_nonce(nonce: &mut [u8]) -> std::io::Result<()> {
    use aws_lc_rs::rand::SecureRandom;
    aws_lc_rs::rand::SystemRandom::new()
        .fill(nonce)
        .map_err(|_| std::io::Error::other("could not generate an OIDC lock owner nonce"))
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum LockStamp {
    /// `None` means an empty or oversized file, which uses the short grace.
    Readable(Option<Vec<u8>>),
    Unreadable,
}

#[derive(Clone, Debug)]
struct LockSnapshot {
    stamp: LockStamp,
    modified_millis: u128,
}

fn system_time_millis(time: SystemTime) -> Option<u128> {
    time.duration_since(SystemTime::UNIX_EPOCH)
        .ok()
        .map(|duration| duration.as_millis())
}

/// Read a lock owner stamp without ever allocating or reading more than 4 KiB.
fn read_lock_stamp(lock: &Path) -> std::io::Result<Option<Vec<u8>>> {
    let mut opts = OpenOptions::new();
    opts.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(libc::O_NONBLOCK);
    }
    let file = opts.open(lock)?;
    let meta = file.metadata()?;
    if !meta.is_file() || meta.len() == 0 || meta.len() > MAX_LOCK_FILE_BYTES {
        return Ok(None);
    }
    let mut bytes = Vec::with_capacity(meta.len() as usize);
    file.take(MAX_LOCK_FILE_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.is_empty() || bytes.len() as u64 > MAX_LOCK_FILE_BYTES {
        return Ok(None);
    }
    Ok(Some(bytes))
}

fn lock_snapshot(lock: &Path) -> std::io::Result<Option<LockSnapshot>> {
    let meta = match fs::symlink_metadata(lock) {
        Ok(meta) => meta,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    if !meta.is_file() || meta.file_type().is_symlink() {
        return Ok(None);
    }
    let modified_millis = meta
        .modified()
        .ok()
        .and_then(system_time_millis)
        .ok_or_else(|| std::io::Error::other("OIDC token-store lock has no usable mtime"))?;
    let stamp = match read_lock_stamp(lock) {
        Ok(stamp) => LockStamp::Readable(stamp),
        Err(_) => LockStamp::Unreadable,
    };
    Ok(Some(LockSnapshot {
        stamp,
        modified_millis,
    }))
}

fn lock_is_owned(lock: &Path, stamp: &str) -> bool {
    read_lock_stamp(lock)
        .ok()
        .flatten()
        .is_some_and(|bytes| bytes == stamp.as_bytes())
}

fn capture_path(lock: &Path) -> PathBuf {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let counter = COUNTER.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    let name = lock
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("lock");
    lock.with_file_name(format!(
        "{name}.{}.{}.{}.tmp",
        std::process::id(),
        counter,
        nanos
    ))
}

fn delete_capture(captured: &Path) {
    if fs::remove_file(captured).is_err() {
        let _ = fs::remove_dir(captured);
    }
}

/// Restore a captured peer lock without replacing a third party that claimed the
/// canonical name. Hard-linking is the cross-language no-replace primitive; a
/// plain rename is only a fallback for filesystems that do not support links.
fn restore_captured_lock(lock: &Path, captured: &Path) {
    match fs::hard_link(captured, lock) {
        Ok(()) => delete_capture(captured),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => delete_capture(captured),
        Err(_) => {
            if fs::rename(captured, lock).is_err() {
                delete_capture(captured);
            }
        }
    }
}

fn displace_lock_squatter(lock: &Path) {
    let captured = capture_path(lock);
    if fs::rename(lock, &captured).is_err() {
        return;
    }
    match fs::symlink_metadata(&captured) {
        Ok(meta) if meta.is_file() && !meta.file_type().is_symlink() => {
            restore_captured_lock(lock, &captured)
        }
        _ => delete_capture(&captured),
    }
}

/// Reclaim a stale Java, Python, or Rust lock with capture-then-verify. The stamp
/// and mtime observed before the atomic capture must match afterwards; otherwise
/// the captured peer replacement is restored rather than discarded.
fn steal_if_stale(lock: &Path, stale_after: Duration, empty_grace: Duration) -> bool {
    let meta = match fs::symlink_metadata(lock) {
        Ok(meta) => meta,
        Err(_) => return false,
    };
    if !meta.is_file() || meta.file_type().is_symlink() {
        displace_lock_squatter(lock);
        return !lock.exists();
    }
    let before = match lock_snapshot(lock) {
        Ok(Some(snapshot)) => snapshot,
        _ => return false,
    };
    let threshold = match before.stamp {
        LockStamp::Readable(None) => empty_grace,
        _ => stale_after,
    };
    let now_millis = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or(0);
    if now_millis.saturating_sub(before.modified_millis) <= threshold.as_millis() {
        return false;
    }

    let captured = capture_path(lock);
    if fs::rename(lock, &captured).is_err() {
        return false;
    }
    let after = lock_snapshot(&captured).ok().flatten();
    if after.as_ref().is_some_and(|after| {
        after.modified_millis == before.modified_millis && after.stamp == before.stamp
    }) {
        delete_capture(&captured);
        true
    } else {
        restore_captured_lock(lock, &captured);
        false
    }
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

fn path_is_definitely_absent(path: &Path) -> bool {
    fs::symlink_metadata(path).is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound)
}

/// The short directory-lock lease is safe once no other user can write the
/// directory. Read/execute bits alone do not make its 0600 token files
/// attacker-writable, which is also Java's trust boundary.
#[cfg(unix)]
fn directory_is_owner_only(dir: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    fs::symlink_metadata(dir)
        .map(|meta| meta.permissions().mode() & 0o022 == 0)
        .unwrap_or(false)
}

#[cfg(not(unix))]
fn directory_is_owner_only(_dir: &Path) -> bool {
    true
}

fn create_empty_private(path: &Path) -> std::io::Result<()> {
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts.open(path).map(|_| ())
}

/// Publish distrust before chmod makes a previously writable directory appear
/// safe to another process. A non-regular squatter at the reserved name is
/// displaced when possible; any surviving shape still counts as untrusted.
fn mark_untrusted(sentinel: &Path) -> std::io::Result<()> {
    match create_empty_private(sentinel) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let usable = fs::symlink_metadata(sentinel)
                .map(|meta| meta.is_file() && !meta.file_type().is_symlink())
                .unwrap_or(false);
            if usable {
                return Ok(());
            }
            if fs::remove_file(sentinel).is_err() {
                let _ = fs::remove_dir(sentinel);
            }
            create_empty_private(sentinel)
        }
        Err(error) => Err(error),
    }
}

#[cfg(unix)]
fn prepare_directory_trust(dir: &Path, sentinel: &Path) -> std::io::Result<bool> {
    use std::os::unix::fs::PermissionsExt;
    let meta = fs::symlink_metadata(dir)?;
    let mode = meta.permissions().mode();
    let was_other_writable = mode & 0o022 != 0;
    if was_other_writable {
        // Best effort, matching Java: this caller retains the untrusted verdict
        // even if publishing it for a concurrent caller fails.
        let _ = mark_untrusted(sentinel);
    }
    if mode & 0o077 != 0 {
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
    }
    Ok(!was_other_writable && path_is_definitely_absent(sentinel))
}

#[cfg(not(unix))]
fn prepare_directory_trust(_dir: &Path, sentinel: &Path) -> std::io::Result<bool> {
    warn_no_posix_perms_once();
    Ok(path_is_definitely_absent(sentinel))
}

fn has_store_hash_prefix(name: &str) -> bool {
    name.len() >= 64
        && name
            .as_bytes()
            .iter()
            .take(64)
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
}

/// Sweep only names this token store could have written. A captured lock name
/// contains `.lock.` and must survive because another client may be deciding
/// whether to restore it.
fn discard_untrusted_directory_contents(dir: &Path, sentinel: &Path) {
    let mut swept_clean = true;
    match fs::read_dir(dir) {
        Ok(entries) => {
            for entry in entries {
                let Ok(entry) = entry else {
                    swept_clean = false;
                    continue;
                };
                let name = entry.file_name();
                let name = name.to_string_lossy();
                if !has_store_hash_prefix(&name) {
                    continue;
                }
                let is_entry = name.len() == 69 && name.ends_with(".json");
                let is_write_temp = name.ends_with(".tmp") && !name.contains(".lock.");
                if (is_entry || is_write_temp) && fs::remove_file(entry.path()).is_err() {
                    swept_clean = false;
                }
            }
        }
        Err(_) => swept_clean = false,
    }
    if swept_clean && fs::remove_file(sentinel).is_err() && !path_is_definitely_absent(sentinel) {
        // Preserve the marker if it cannot be lifted. A later load must remain
        // fail-closed and retry the sweep rather than trust partial recovery.
        let _ = mark_untrusted(sentinel);
    }
}

struct DirectoryLockHeartbeat {
    closed: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl DirectoryLockHeartbeat {
    fn start(lock: PathBuf, stamp: String) -> Self {
        let closed = Arc::new(AtomicBool::new(false));
        let thread_closed = Arc::clone(&closed);
        let thread = std::thread::Builder::new()
            .name("questdb-oidc-store-lock-heartbeat".into())
            .spawn(move || {
                while !thread_closed.load(Ordering::Acquire) {
                    std::thread::park_timeout(DIRECTORY_LOCK_HEARTBEAT);
                    if thread_closed.load(Ordering::Acquire) || !lock_is_owned(&lock, &stamp) {
                        return;
                    }
                    let Ok(file) = OpenOptions::new().write(true).open(&lock) else {
                        return;
                    };
                    if file.set_modified(SystemTime::now()).is_err() {
                        return;
                    }
                }
            })
            .ok();
        Self { closed, thread }
    }
}

impl Drop for DirectoryLockHeartbeat {
    fn drop(&mut self) {
        self.closed.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            thread.thread().unpark();
            let _ = thread.join();
        }
    }
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
