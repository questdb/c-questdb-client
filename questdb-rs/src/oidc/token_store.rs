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
/// 1 MiB is ample while refusing to read an unbounded (hostile) file into memory.
const MAX_FILE_BYTES: u64 = 1 << 20;

/// How long to spin trying to acquire the per-identity lock file before giving up
/// and running without it (degrading to the atomic-replace integrity layer).
const DEFAULT_LOCK_ACQUIRE_BUDGET: Duration = Duration::from_secs(3);
const LOCK_POLL_SLICE: Duration = Duration::from_millis(50);

/// A lock older than this is treated as abandoned (a crashed holder) and stolen.
/// Must dominate the worst-case time a live holder can hold it: up to ~4×HTTP
/// timeout (capped 120s) for the refresh I/O plus a generous connection-stall
/// allowance. 10 minutes clears that with headroom.
const DEFAULT_LOCK_STALE: Duration = Duration::from_secs(600);
/// A configured staleness window below this is rejected — see [`FileTokenStore::with_lock_timings`].
const MIN_LOCK_STALE: Duration = Duration::from_secs(300);

/// The result of a [`TokenStore`] operation. Persistence is best-effort: the
/// [`OidcDeviceAuth`](crate::oidc::OidcDeviceAuth) treats an `Err` as non-fatal,
/// warning and continuing with the in-memory token.
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
/// observing a half-written entry. A store reports failure by returning `Err`;
/// `OidcDeviceAuth` treats persistence as best-effort and a failure as non-fatal.
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

    /// Remove any persisted entry for this identity. A no-op when nothing is
    /// stored.
    fn clear(&self, key: &TokenStoreKey) -> TokenStoreResult<()>;

    /// Run `action` while holding a cross-process lock scoped to `key`, so a
    /// refresh by another process sharing this identity is observed rather than
    /// raced, and return its result.
    ///
    /// The default runs `action` with no locking, which is correct for a single
    /// process or a non-rotating refresh token; [`FileTokenStore`] overrides it
    /// with a lock-file protocol. **Most stores should NOT override this.**
    /// `action` MUST be invoked exactly once, synchronously, on the calling
    /// thread, with the lock held for the whole call; an implementation that
    /// cannot acquire the lock should run `action` anyway (degrade) rather than
    /// fail a sign-in.
    fn in_lock(
        &self,
        key: &TokenStoreKey,
        action: &mut dyn FnMut() -> TokenStoreResult<()>,
    ) -> TokenStoreResult<()> {
        let _ = key;
        action()
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
/// `QUESTDB_CLIENT_OIDC_TOKEN_STORE_DIR` environment variable. The file name is
/// `<TokenStoreKey::hash()>.json`, so several identities coexist and the name
/// leaks neither the endpoint nor the client id.
///
/// [`save`](FileTokenStore::save) writes a sibling temp file then atomically
/// renames it over the target, so a crash or an overlapping reader — in any
/// process or language — sees the whole old or whole new file, never a torn
/// credential. [`in_lock`](TokenStore::in_lock) serialises the
/// read-refresh-write of a token refresh across processes with an
/// `O_CREAT|O_EXCL` lock file, stealing a stale lock left by a crashed holder and
/// degrading to running without the lock rather than stall a sign-in.
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

    /// Override the cross-process lock timings. `stale` must exceed 5 minutes (it
    /// must dominate the worst-case time a live holder can hold the lock, so a
    /// tighter window could steal a live lock). A tighter `stale` is clamped up to
    /// the 5-minute floor.
    pub fn with_lock_timings(mut self, acquire_budget: Duration, stale: Duration) -> Self {
        self.lock_acquire_budget = acquire_budget;
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
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "the OIDC token store path is a symbolic link; refusing to use it \
                     because the plaintext token files could be redirected outside the \
                     owner-only directory",
                ));
            }
            Ok(_) => {
                // Pre-existing real directory: re-assert owner-only perms.
                restrict_to_owner(&self.directory);
                return Ok(());
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        create_dir_all_private(&self.directory)?;
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

    fn acquire_lock(&self, lock: &Path) -> bool {
        let deadline = Instant::now() + self.lock_acquire_budget;
        loop {
            match create_lock_file(lock) {
                Ok(()) => return true,
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    if self.is_stale(lock) {
                        steal_stale_lock(lock, self.lock_stale);
                    }
                    if Instant::now() >= deadline {
                        return false; // give up; run without the lock
                    }
                    std::thread::sleep(LOCK_POLL_SLICE);
                }
                Err(_) => return false, // unexpected IO; degrade to no lock
            }
        }
    }

    fn is_stale(&self, lock: &Path) -> bool {
        // lstat (symlink_metadata): judge a symlink by its OWN mtime; for a
        // regular-file lock (what we create) lstat == stat.
        let Ok(meta) = fs::symlink_metadata(lock) else {
            return false; // can't determine age → don't steal
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
        self.ensure_directory()?;
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
            f.write_all(&content)?;
            f.flush()?;
            f.sync_all()?; // force to disk before the rename
            fs::rename(&tmp, &target)?; // atomic on POSIX and Windows
            Ok(())
        })();
        if write_result.is_err() {
            let _ = fs::remove_file(&tmp); // clean up the temp on failure
        }
        write_result?;
        fsync_directory(&self.directory); // best-effort: persist the rename
        Ok(())
    }

    fn clear(&self, key: &TokenStoreKey) -> TokenStoreResult<()> {
        match fs::remove_file(self.token_file(key)) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(Box::new(e)),
        }
        // Sweep any orphaned sibling temp files holding a now-forgotten credential
        // (a hard crash between the temp write and the rename). Best-effort.
        sweep_orphan_temps(&self.directory, &key.hash());
        Ok(())
    }

    fn in_lock(
        &self,
        key: &TokenStoreKey,
        action: &mut dyn FnMut() -> TokenStoreResult<()>,
    ) -> TokenStoreResult<()> {
        let lock = self.lock_file(key);
        // Prepare the directory and acquire; on any failure, run without the lock
        // (the atomic write still keeps every reader consistent).
        let held = self.ensure_directory().is_ok() && self.acquire_lock(&lock);
        let result = action();
        if held {
            // Best-effort release; a leftover lock goes stale and the next
            // acquirer steals it.
            let _ = fs::remove_file(&lock);
        }
        result
    }
}

// ---------------------------------------------------------------------------
// Free helpers
// ---------------------------------------------------------------------------

/// Canonicalise an endpoint URL for the cross-language store-key hash:
/// `scheme://host:port/path` with scheme and host lower-cased, the port always
/// explicit (443/80 default), an IPv6 host bracketed, and a trailing slash
/// stripped from the path. For the common case (no trailing slash) this is
/// byte-for-byte unchanged.
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
    // Strip a trailing slash so `.../token` and `.../token/` are ONE identity.
    let path = uri.path().trim_end_matches('/');
    match port {
        Some(port) => format!("{scheme}://{host}:{port}{path}"),
        None => format!("{scheme}://{host}{path}"),
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

fn create_lock_file(lock: &Path) -> std::io::Result<()> {
    // The create_new (O_CREAT|O_EXCL) IS the acquisition; write the holder bytes
    // through this same handle so a concurrent steal can't truncate a peer's
    // fresh lock. Holder bytes are debug-only (staleness is judged by mtime).
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(lock)?;
    let _ = f.write_all(holder_bytes().as_bytes());
    Ok(())
}

fn steal_stale_lock(lock: &Path, lock_stale: Duration) {
    // Break a stale lock ATOMICALLY: rename it aside to a private path (only one
    // racer can rename a given file away). Re-judge staleness on the moved-aside
    // file; if a peer recreated a fresh lock in the gap we moved a live lock by
    // mistake — restore it. A single break is the common outcome and a live lock
    // is never blindly deleted; integrity is guarded by the atomic write
    // regardless.
    let private = lock.with_extension(format!(
        "stale.{}.{}",
        std::process::id(),
        thread_id_stamp()
    ));
    if fs::rename(lock, &private).is_err() {
        return; // lost the steal race; the lock is already gone — retry create
    }
    let stale = match fs::symlink_metadata(&private).and_then(|m| m.modified()) {
        Ok(mtime) => SystemTime::now()
            .duration_since(mtime)
            .map(|e| e > lock_stale)
            .unwrap_or(false),
        Err(_) => false,
    };
    if stale {
        // Genuinely abandoned: drop it so the next create wins.
        let _ = fs::remove_file(&private);
    } else {
        // A still-live lock we moved by mistake (a peer recreated it in the gap):
        // put it back. If the slot was retaken meanwhile, drop our redundant copy.
        if fs::rename(&private, lock).is_err() {
            let _ = fs::remove_file(&private);
        }
    }
}

fn holder_bytes() -> String {
    let nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("{}@{} {nanos}", std::process::id(), hostname())
}

fn thread_id_stamp() -> String {
    // A per-acquisition stamp for the private steal path; the exact value doesn't
    // matter, only that concurrent stealers pick different paths.
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    COUNTER.fetch_add(1, Ordering::Relaxed).to_string()
}

/// Sweep any leftover `<hash>*.tmp` files for one identity (a plaintext token an
/// aborted `save` left behind). Best-effort.
fn sweep_orphan_temps(dir: &Path, hash: &str) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.starts_with(hash) && name.ends_with(".tmp") {
            let _ = fs::remove_file(entry.path());
        }
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
fn fsync_directory(dir: &Path) {
    if let Ok(f) = File::open(dir) {
        let _ = f.sync_all();
    }
}

#[cfg(not(unix))]
fn fsync_directory(_dir: &Path) {}

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
