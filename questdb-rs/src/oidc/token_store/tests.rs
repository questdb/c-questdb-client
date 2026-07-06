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

use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use tempfile::TempDir;

use super::*;

const EP_T: &str = "https://idp.example.com/token";
const EP_D: &str = "https://idp.example.com/device";

fn test_key() -> TokenStoreKey {
    TokenStoreKey::from_config("questdb", EP_T, EP_D, "openid", None, false, None)
}

fn test_token() -> PersistedToken {
    PersistedToken::new(
        Some("AT-1".to_string()),
        None,
        Some("RT-1".to_string()),
        1_700_000_000.0,
        300.0,
    )
}

// -- cross-language contract (frozen) ---------------------------------------

#[test]
fn hash_matches_frozen_cross_language_value() {
    // Pinned to the byte-exact canonical string the Java/Python clients hash, so
    // a drift in the prefix, field order, NUL separation, endpoint canonicalisation
    // or groups encoding — any of which would break cross-language file sharing —
    // fails here.
    let key = TokenStoreKey::from_config("questdb", EP_T, EP_D, "openid", None, false, None);
    assert_eq!(
        key.hash(),
        "bb24451046d9646892338e3cd193581c782267fe1a7a444a57277a2d2a1c5fd8"
    );
    let key2 = TokenStoreKey::from_config(
        "questdb",
        EP_T,
        EP_D,
        "openid",
        Some("api://billing"),
        true,
        None,
    );
    assert_eq!(
        key2.hash(),
        "bcdc81e286ebb78ff6845418e0b00f3a903322a69e28fb3da758c049c9df76ae"
    );
}

#[test]
fn canonical_endpoint_normalizes() {
    // Default port made explicit; scheme/host lower-cased; trailing slash stripped.
    assert_eq!(
        canonical_endpoint("https://idp.example.com/token"),
        "https://idp.example.com:443/token"
    );
    assert_eq!(
        canonical_endpoint("https://IDP.Example.COM:443/token/"),
        "https://idp.example.com:443/token"
    );
    assert_eq!(
        canonical_endpoint("http://localhost:9000/dev"),
        "http://localhost:9000/dev"
    );
    // An IPv6 host stays bracketed so the host:port boundary is unambiguous.
    assert_eq!(
        canonical_endpoint("https://[::1]:8443/t"),
        "https://[::1]:8443/t"
    );
}

#[test]
fn scope_is_order_normalized() {
    let a = TokenStoreKey::from_config("c", EP_T, EP_D, "openid offline_access", None, false, None);
    let b = TokenStoreKey::from_config("c", EP_T, EP_D, "offline_access openid", None, false, None);
    assert_eq!(a.hash(), b.hash());
    assert_eq!(a.scope(), "offline_access openid");
}

#[test]
fn issuer_excluded_from_hash_but_isolated_on_load() {
    let dir = TempDir::new().unwrap();
    let store = FileTokenStore::at(dir.path());
    let pinned = TokenStoreKey::from_config(
        "questdb",
        EP_T,
        EP_D,
        "openid",
        None,
        false,
        Some("https://idp"),
    );
    let unpinned = TokenStoreKey::from_config("questdb", EP_T, EP_D, "openid", None, false, None);
    // Same file name (issuer is not folded into the hash)...
    assert_eq!(pinned.hash(), unpinned.hash());
    store.save(&pinned, &test_token()).unwrap();
    // ...but the un-pinned session rejects the issuer-pinned entry (and vice versa).
    assert!(store.load(&unpinned).unwrap().is_none());
    assert!(store.load(&pinned).unwrap().is_some());
}

// -- round trip + defensive load --------------------------------------------

#[test]
fn round_trip_save_load() {
    let dir = TempDir::new().unwrap();
    let store = FileTokenStore::at(dir.path());
    let key = test_key();
    let token = PersistedToken::new(
        Some("AT".to_string()),
        Some("ID".to_string()),
        Some("RT".to_string()),
        1_700_000_000.5,
        300.0,
    );
    store.save(&key, &token).unwrap();
    let loaded = store.load(&key).unwrap().unwrap();
    assert_eq!(loaded.access_token(), Some("AT"));
    assert_eq!(loaded.id_token(), Some("ID"));
    assert_eq!(loaded.refresh_token(), Some("RT"));
    // Millisecond precision round-trips (0.5s -> 500ms -> 0.5s).
    assert!((loaded.expires_at() - 1_700_000_000.5).abs() < 0.001);
    assert!((loaded.token_ttl() - 300.0).abs() < 0.001);
}

#[test]
fn null_fields_omitted_and_read_back_as_none() {
    let dir = TempDir::new().unwrap();
    let store = FileTokenStore::at(dir.path());
    let key = test_key();
    // No id_token, no refresh_token.
    let token = PersistedToken::new(Some("AT".to_string()), None, None, 1_700_000_000.0, 300.0);
    store.save(&key, &token).unwrap();
    let raw = std::fs::read_to_string(store.token_file(&key)).unwrap();
    assert!(
        !raw.contains("id_token"),
        "null field must be omitted: {raw}"
    );
    assert!(!raw.contains("refresh_token"), "null omitted: {raw}");
    assert!(!raw.contains("null"), "no literal JSON null: {raw}");
    let loaded = store.load(&key).unwrap().unwrap();
    assert_eq!(loaded.id_token(), None);
    assert_eq!(loaded.refresh_token(), None);
}

#[test]
fn missing_file_returns_none() {
    let dir = TempDir::new().unwrap();
    let store = FileTokenStore::at(dir.path());
    assert!(store.load(&test_key()).unwrap().is_none());
}

#[test]
fn fingerprint_mismatch_returns_none() {
    let dir = TempDir::new().unwrap();
    let store = FileTokenStore::at(dir.path());
    let key_a = TokenStoreKey::from_config("client-a", EP_T, EP_D, "openid", None, false, None);
    let key_b = TokenStoreKey::from_config("client-b", EP_T, EP_D, "openid", None, false, None);
    store.save(&key_a, &test_token()).unwrap();
    // Simulate a copied/renamed file: place key_a's content at key_b's path. The
    // in-file fingerprint (client-a) mismatches key_b (client-b) -> ignored.
    let content = std::fs::read(store.token_file(&key_a)).unwrap();
    std::fs::write(store.token_file(&key_b), &content).unwrap();
    assert!(store.load(&key_b).unwrap().is_none());
}

#[test]
fn oversized_file_ignored() {
    let dir = TempDir::new().unwrap();
    let store = FileTokenStore::at(dir.path());
    let key = test_key();
    let big = vec![b'x'; (MAX_FILE_BYTES + 10) as usize];
    std::fs::write(store.token_file(&key), &big).unwrap();
    assert!(store.load(&key).unwrap().is_none());
}

#[test]
fn corrupt_wrong_version_and_non_object_ignored() {
    let dir = TempDir::new().unwrap();
    let store = FileTokenStore::at(dir.path());
    let key = test_key();
    let path = store.token_file(&key);
    for bad in [
        &b"not json at all"[..],
        br#"{"v":2,"client_id":"questdb"}"#,
        b"[]",
        b"\"a string\"",
        b"",
    ] {
        std::fs::write(&path, bad).unwrap();
        assert!(
            store.load(&key).unwrap().is_none(),
            "should ignore: {:?}",
            String::from_utf8_lossy(bad)
        );
    }
}

// -- atomicity + permissions ------------------------------------------------

#[test]
fn save_leaves_no_temp_file() {
    let dir = TempDir::new().unwrap();
    let store = FileTokenStore::at(dir.path());
    store.save(&test_key(), &test_token()).unwrap();
    let leftover: Vec<_> = std::fs::read_dir(dir.path())
        .unwrap()
        .flatten()
        .filter(|e| e.file_name().to_string_lossy().ends_with(".tmp"))
        .collect();
    assert!(leftover.is_empty(), "leftover temp file(s): {leftover:?}");
}

#[cfg(unix)]
#[test]
fn file_and_dir_are_owner_only() {
    use std::os::unix::fs::PermissionsExt;
    let base = TempDir::new().unwrap();
    // A not-yet-existing subdir, so the store creates it 0700 itself.
    let dir = base.path().join("oidc-tokens");
    let store = FileTokenStore::at(&dir);
    let key = test_key();
    store.save(&key, &test_token()).unwrap();
    let dmode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
    assert_eq!(dmode, 0o700, "directory must be 0700");
    let fmode = std::fs::metadata(store.token_file(&key))
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(fmode, 0o600, "token file must be 0600");
}

#[cfg(unix)]
#[test]
fn refuses_a_symlinked_store_directory() {
    let base = TempDir::new().unwrap();
    let real = base.path().join("real");
    std::fs::create_dir(&real).unwrap();
    let link = base.path().join("link");
    std::os::unix::fs::symlink(&real, &link).unwrap();
    let store = FileTokenStore::at(&link);
    // save must refuse to operate through the symlinked leaf (a redirect risk).
    assert!(store.save(&test_key(), &test_token()).is_err());
}

#[test]
fn clear_removes_file_and_is_idempotent() {
    let dir = TempDir::new().unwrap();
    let store = FileTokenStore::at(dir.path());
    let key = test_key();
    store.save(&key, &test_token()).unwrap();
    assert!(store.load(&key).unwrap().is_some());
    store.clear(&key).unwrap();
    assert!(store.load(&key).unwrap().is_none());
    store.clear(&key).unwrap(); // no-op on an already-absent file
}

// -- cross-process lock (Layer 2) -------------------------------------------

#[test]
fn in_lock_runs_action_and_releases() {
    let dir = TempDir::new().unwrap();
    let store = FileTokenStore::at(dir.path());
    let key = test_key();
    let ran = Arc::new(AtomicBool::new(false));
    let r = Arc::clone(&ran);
    store
        .in_lock(&key, &mut || {
            r.store(true, Ordering::SeqCst);
            Ok(())
        })
        .unwrap();
    assert!(ran.load(Ordering::SeqCst));
    // The lock file is released (deleted) after in_lock returns.
    assert!(!store.lock_file(&key).exists(), "lock not released");
}

#[test]
fn in_lock_serialises_concurrent_holders() {
    let dir = TempDir::new().unwrap();
    let key = test_key();
    let active = Arc::new(std::sync::Mutex::new(false));
    let overlap = Arc::new(AtomicBool::new(false));

    let spawn = |dir: PathBuf,
                 key: TokenStoreKey,
                 active: Arc<std::sync::Mutex<bool>>,
                 overlap: Arc<AtomicBool>| {
        std::thread::spawn(move || {
            let store = FileTokenStore::at(dir);
            store
                .in_lock(&key, &mut || {
                    {
                        let mut a = active.lock().unwrap();
                        if *a {
                            overlap.store(true, Ordering::SeqCst);
                        }
                        *a = true;
                    }
                    std::thread::sleep(Duration::from_millis(150));
                    *active.lock().unwrap() = false;
                    Ok(())
                })
                .unwrap();
        })
    };
    let t1 = spawn(
        dir.path().to_path_buf(),
        key.clone(),
        Arc::clone(&active),
        Arc::clone(&overlap),
    );
    let t2 = spawn(
        dir.path().to_path_buf(),
        key.clone(),
        Arc::clone(&active),
        Arc::clone(&overlap),
    );
    t1.join().unwrap();
    t2.join().unwrap();
    // The 3s acquire budget comfortably covers the 150ms hold, so the loser waits
    // for the winner rather than degrading — the two critical sections never overlap.
    assert!(
        !overlap.load(Ordering::SeqCst),
        "lock did not serialise the two holders"
    );
}

#[test]
fn stale_lock_is_stolen() {
    let dir = TempDir::new().unwrap();
    let key = test_key();
    let store = FileTokenStore::at(dir.path())
        .with_lock_timings(Duration::from_millis(500), Duration::from_secs(300));
    // Plant a lock and backdate its mtime well past the staleness window.
    let lock = store.lock_file(&key);
    std::fs::write(&lock, b"crashed-holder").unwrap();
    let f = OpenOptions::new().write(true).open(&lock).unwrap();
    f.set_modified(SystemTime::now() - Duration::from_secs(400))
        .unwrap();
    drop(f);
    // in_lock steals the abandoned lock and runs the action within the budget.
    let ran = Arc::new(AtomicBool::new(false));
    let r = Arc::clone(&ran);
    store
        .in_lock(&key, &mut || {
            r.store(true, Ordering::SeqCst);
            Ok(())
        })
        .unwrap();
    assert!(ran.load(Ordering::SeqCst), "did not steal the stale lock");
}

#[test]
fn with_lock_timings_enforces_stale_floor() {
    let store = FileTokenStore::at("/tmp/x")
        .with_lock_timings(Duration::from_secs(1), Duration::from_secs(1));
    // A sub-floor staleness window is clamped up to the 5-minute minimum.
    assert_eq!(store.lock_stale, MIN_LOCK_STALE);
}
