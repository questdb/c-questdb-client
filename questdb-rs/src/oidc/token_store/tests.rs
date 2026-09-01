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
    // fails here. Cross-language fixtures for the same contract:
    // Python (the null-audience digest below):
    // https://github.com/questdb/py-questdb-client/blob/b8348d940f1657b2e4bdcfe615a4050d37ecdd1b/test/test_auth.py#L5897-L5904
    // Java (companion audience/groups vectors):
    // https://github.com/questdb/java-questdb-client/blob/7a95bb3a29ee1ccecf982378cb9da87a6e3590cd/core/src/test/java/io/questdb/client/test/cutlass/auth/FileTokenStoreTest.java#L516-L539
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
    // Default port made explicit and scheme/host lower-cased, while the complete
    // routing-significant path and query stay byte-exact.
    assert_eq!(
        canonical_endpoint("https://idp.example.com/token"),
        "https://idp.example.com:443/token"
    );
    assert_eq!(
        canonical_endpoint("https://IDP.Example.COM:443/token/"),
        "https://idp.example.com:443/token/"
    );
    assert_eq!(
        canonical_endpoint("https://IDP.Example.COM/token?tenant=A%2FB&mode=strict"),
        "https://idp.example.com:443/token?tenant=A%2FB&mode=strict"
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
fn endpoint_path_and_query_isolate_store_entries() {
    let key = |token_endpoint: &str, device_endpoint: &str| {
        TokenStoreKey::from_config(
            "questdb",
            token_endpoint,
            device_endpoint,
            "openid",
            None,
            false,
            None,
        )
    };

    let tenant_a = key(
        "https://idp.example.com/token?tenant=A",
        "https://idp.example.com/device",
    );
    let tenant_b = key(
        "https://idp.example.com/token?tenant=B",
        "https://idp.example.com/device",
    );
    let device_tenant_b = key(
        "https://idp.example.com/token?tenant=A",
        "https://idp.example.com/device?tenant=B",
    );
    let trailing_slash = key(
        "https://idp.example.com/token/",
        "https://idp.example.com/device",
    );

    assert_ne!(tenant_a.hash(), tenant_b.hash());
    assert_ne!(tenant_a.hash(), device_tenant_b.hash());
    assert_ne!(tenant_a.hash(), trailing_slash.hash());

    let dir = TempDir::new().unwrap();
    let store = FileTokenStore::at(dir.path());
    store.save(&tenant_a, &test_token()).unwrap();
    assert!(store.load(&tenant_a).unwrap().is_some());
    assert!(store.load(&tenant_b).unwrap().is_none());
    assert!(store.load(&device_tenant_b).unwrap().is_none());
    assert!(store.load(&trailing_slash).unwrap().is_none());
}

#[test]
fn scope_order_matches_java_frozen_identity() {
    let a = TokenStoreKey::from_config("c", EP_T, EP_D, "openid offline_access", None, false, None);
    let b = TokenStoreKey::from_config("c", EP_T, EP_D, "offline_access openid", None, false, None);
    assert_ne!(a.hash(), b.hash());
    assert_eq!(a.scope(), "openid offline_access");
}

#[test]
fn issuer_is_not_part_of_java_store_identity() {
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
    // The issuer pin validates how the concrete endpoints were obtained; Java's
    // frozen store identity contains the endpoints themselves, not that pin.
    assert_eq!(pinned.hash(), unpinned.hash());
    assert_eq!(pinned, unpinned);
    store.save(&pinned, &test_token()).unwrap();
    assert!(store.load(&unpinned).unwrap().is_some());
    assert!(store.load(&pinned).unwrap().is_some());
    let raw = std::fs::read_to_string(store.token_file(&pinned)).unwrap();
    assert!(!raw.contains("\"issuer\""));
}

#[test]
fn java_multiscope_file_is_read_with_an_issuer_pin() {
    let dir = TempDir::new().unwrap();
    let store = FileTokenStore::at(dir.path());
    let key = TokenStoreKey::from_config(
        "questdb",
        EP_T,
        EP_D,
        "openid offline_access",
        None,
        false,
        Some("https://idp.example.com"),
    );
    // Generated by Java TokenStoreKey for this exact identity.
    assert_eq!(
        key.hash(),
        "bce5fd34cd8f688c99035d435a9891b4e99f520615f31cf39f791280ca9132ab"
    );
    let java_json = br#"{"v":1,"client_id":"questdb","token_endpoint":"https://idp.example.com:443/token","device_authorization_endpoint":"https://idp.example.com:443/device","scope":"openid offline_access","groups_in_token":false,"access_token":"AT-JAVA","refresh_token":"RT-JAVA","expires_at_millis":1730000000000,"token_ttl_millis":300000}"#;
    std::fs::write(store.token_file(&key), java_json).unwrap();
    let loaded = store.load(&key).unwrap().unwrap();
    assert_eq!(loaded.access_token(), Some("AT-JAVA"));
    assert_eq!(loaded.refresh_token(), Some("RT-JAVA"));
}

#[test]
fn empty_and_absent_audience_share_java_identity() {
    let empty = TokenStoreKey::from_config("questdb", EP_T, EP_D, "openid", Some(""), false, None);
    let absent = TokenStoreKey::from_config("questdb", EP_T, EP_D, "openid", None, false, None);
    assert_eq!(empty, absent);
    assert_eq!(empty.hash(), absent.hash());
    assert_eq!(empty.audience(), None);
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
fn oversized_save_is_rejected_without_replacing_existing_token() {
    let dir = TempDir::new().unwrap();
    let store = FileTokenStore::at(dir.path());
    let key = test_key();
    let existing = test_token();
    store.save(&key, &existing).unwrap();

    let oversized = PersistedToken::new(
        Some("x".repeat(MAX_FILE_BYTES as usize)),
        None,
        Some("RT-2".to_string()),
        1_700_000_300.0,
        300.0,
    );
    let error = store.save(&key, &oversized).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("exceeding the 1048576-byte limit"),
        "unexpected error: {error}"
    );

    assert_eq!(store.load(&key).unwrap(), Some(existing));
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

#[test]
fn nested_or_array_values_are_rejected() {
    let dir = TempDir::new().unwrap();
    let store = FileTokenStore::at(dir.path());
    let key = test_key();
    store.save(&key, &test_token()).unwrap();
    let path = store.token_file(&key);
    let original: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    for extra in [serde_json::json!([]), serde_json::json!({"nested": true})] {
        let mut candidate = original.clone();
        candidate["extra"] = extra;
        std::fs::write(&path, serde_json::to_vec(&candidate).unwrap()).unwrap();
        assert!(store.load(&key).unwrap().is_none());
    }
}

#[test]
fn refresh_only_entries_are_rejected_on_save_and_load() {
    let dir = TempDir::new().unwrap();
    let store = FileTokenStore::at(dir.path());
    let key = test_key();
    let refresh_only = PersistedToken::new(
        None,
        None,
        Some("RT-PLANTED".to_string()),
        1_700_000_000.0,
        300.0,
    );
    assert!(store.save(&key, &refresh_only).is_err());

    let json = serde_json::json!({
        "v": 1,
        "client_id": "questdb",
        "token_endpoint": "https://idp.example.com:443/token",
        "device_authorization_endpoint": "https://idp.example.com:443/device",
        "scope": "openid",
        "groups_in_token": false,
        "refresh_token": "RT-PLANTED",
        "expires_at_millis": 1_700_000_000_000_i64,
        "token_ttl_millis": 300_000,
    });
    std::fs::write(store.token_file(&key), serde_json::to_vec(&json).unwrap()).unwrap();
    assert!(store.load(&key).unwrap().is_none());
}

#[test]
fn garbage_millis_field_reads_back_as_expired() {
    let dir = TempDir::new().unwrap();
    let store = FileTokenStore::at(dir.path());
    let key = test_key();
    // Start from a valid entry so the identity fingerprint still matches, then
    // corrupt only the numeric millis fields with non-numeric junk (a hand-edited
    // or hostile file). `millis_to_seconds` maps them to 0.0, so the entry loads
    // but reads back as expired and is never served as a live token.
    store.save(&key, &test_token()).unwrap();
    let path = store.token_file(&key);
    let mut obj: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    obj["expires_at_millis"] = serde_json::Value::from("garbage");
    obj["token_ttl_millis"] = serde_json::Value::from("nope");
    std::fs::write(&path, serde_json::to_vec(&obj).unwrap()).unwrap();

    let loaded = store.load(&key).unwrap().unwrap();
    assert_eq!(loaded.access_token(), Some("AT-1"));
    assert_eq!(
        loaded.expires_at(),
        0.0,
        "a non-numeric expires_at_millis must read as expired"
    );
    assert_eq!(loaded.token_ttl(), 0.0);
}

#[test]
fn non_integer_millis_fields_read_back_as_expired() {
    let dir = TempDir::new().unwrap();
    let store = FileTokenStore::at(dir.path());
    let key = test_key();
    store.save(&key, &test_token()).unwrap();
    let path = store.token_file(&key);
    let mut obj: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    obj["expires_at_millis"] = serde_json::json!(1.7e12);
    obj["token_ttl_millis"] = serde_json::json!(300000.5);
    std::fs::write(&path, serde_json::to_vec(&obj).unwrap()).unwrap();

    let loaded = store.load(&key).unwrap().unwrap();
    assert_eq!(loaded.expires_at(), 0.0);
    assert_eq!(loaded.token_ttl(), 0.0);
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

#[cfg(unix)]
#[test]
fn non_regular_token_file_is_ignored_not_hung() {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    let dir = TempDir::new().unwrap();
    let store = FileTokenStore::at(dir.path());
    let key = test_key();
    let path = store.token_file(&key);
    let c_path = CString::new(path.as_os_str().as_bytes()).unwrap();
    // A FIFO swapped in at the token path: open(O_RDONLY) WITHOUT O_NONBLOCK would
    // block forever waiting for a writer. `open_regular_bounded` opens with
    // O_NONBLOCK and rejects a non-regular file, so this is treated as absent
    // rather than hanging the caller's thread.
    assert_eq!(
        unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) },
        0,
        "mkfifo failed"
    );
    assert!(store.load(&key).unwrap().is_none());
}

#[cfg(unix)]
#[test]
fn preexisting_loose_permissions_directory_is_retightened() {
    use std::os::unix::fs::PermissionsExt;
    let dir = TempDir::new().unwrap();
    // A pre-existing, world-accessible store directory...
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o777)).unwrap();
    let store = FileTokenStore::at(dir.path());
    store.save(&test_key(), &test_token()).unwrap();
    // ...is re-asserted to owner-only (0700) by ensure_directory, so a token file
    // is never left under a group/world-readable directory.
    let mode = std::fs::metadata(dir.path()).unwrap().permissions().mode() & 0o777;
    assert_eq!(
        mode, 0o700,
        "a pre-existing loose-perms dir must be tightened"
    );
}

#[test]
fn creates_missing_parent_chain() {
    // The parent chain is created recursively and the leaf non-recursively; a
    // brand-new nested store path must still work.
    let base = TempDir::new().unwrap();
    let dir = base.path().join("a").join("b").join("oidc-tokens");
    let store = FileTokenStore::at(&dir);
    store.save(&test_key(), &test_token()).unwrap();
    assert!(store.load(&test_key()).unwrap().is_some());
}

#[test]
fn with_lock_timings_clamps_acquire_budget() {
    // An unclamped near-`Duration::MAX` budget would overflow `Instant::now() +
    // budget`; it is clamped down to the 5-minute ceiling.
    let store =
        FileTokenStore::at("/tmp/x").with_lock_timings(Duration::MAX, Duration::from_secs(600));
    assert_eq!(store.lock_acquire_budget, MAX_LOCK_ACQUIRE_BUDGET);
}

#[cfg(unix)]
#[test]
fn release_lock_removes_our_own_lock() {
    let dir = TempDir::new().unwrap();
    let lock = dir.path().join("y.lock");
    let ours = create_lock_file(&lock).unwrap();
    release_lock(&lock, &ours);
    assert!(!lock.exists(), "release must remove a lock we still own");
}

#[cfg(unix)]
#[test]
fn release_lock_leaves_a_successor_lock() {
    // If our lock is stolen and a peer recreates it (a different inode), releasing
    // our now-orphaned handle must NOT delete the peer's live lock — deleting by
    // path alone would break mutual exclusion.
    let dir = TempDir::new().unwrap();
    let lock = dir.path().join("z.lock");
    let ours = create_lock_file(&lock).unwrap();
    std::fs::remove_file(&lock).unwrap(); // steal: our inode is now orphaned
    let _peer = create_lock_file(&lock).unwrap(); // peer's fresh inode at the path
    release_lock(&lock, &ours);
    assert!(
        lock.exists(),
        "release deleted the peer's successor lock (by-path unlink)"
    );
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

#[test]
fn clear_removes_stale_orphan_temp_without_a_token_file() {
    let dir = TempDir::new().unwrap();
    let store = FileTokenStore::at(dir.path());
    let key = test_key();
    let orphan = temp_path(dir.path(), &key.hash());
    std::fs::write(&orphan, b"orphaned refresh credential").unwrap();
    let file = OpenOptions::new().write(true).open(&orphan).unwrap();
    file.set_modified(SystemTime::now() - DEFAULT_LOCK_STALE - Duration::from_secs(1))
        .unwrap();
    drop(file);
    assert!(!store.token_file(&key).exists());

    // This is the path where only the orphan deletion changes the directory;
    // clear must detect it so the subsequent directory fsync is not skipped.
    store.clear(&key).unwrap();
    assert!(!orphan.exists());
}

#[test]
fn save_sweeps_only_proven_stale_orphan_temps() {
    let dir = TempDir::new().unwrap();
    let store = FileTokenStore::at(dir.path());
    let key = test_key();
    let stale = temp_path(dir.path(), &key.hash());
    let fresh = temp_path(dir.path(), &key.hash());
    std::fs::write(&stale, b"stale refresh credential").unwrap();
    std::fs::write(&fresh, b"possibly live refresh credential").unwrap();
    let file = OpenOptions::new().write(true).open(&stale).unwrap();
    file.set_modified(SystemTime::now() - DEFAULT_LOCK_STALE - Duration::from_secs(1))
        .unwrap();
    drop(file);

    store.save(&key, &test_token()).unwrap();

    assert!(!stale.exists(), "stale plaintext temp was not recovered");
    assert!(
        fresh.exists(),
        "save removed a temp that was not proven stale"
    );
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
fn save_reuses_a_lock_already_held_by_the_current_action() {
    let dir = TempDir::new().unwrap();
    let store =
        FileTokenStore::at(dir.path()).with_lock_timings(Duration::ZERO, DEFAULT_LOCK_STALE);
    let key = test_key();

    store
        .in_lock(&key, &mut || store.save(&key, &test_token()))
        .unwrap();

    assert!(store.load(&key).unwrap().is_some());
    assert!(!store.lock_file(&key).exists(), "lock was not released");
}

#[test]
fn standalone_save_never_bypasses_a_peer_lock() {
    let dir = TempDir::new().unwrap();
    let store =
        FileTokenStore::at(dir.path()).with_lock_timings(Duration::ZERO, DEFAULT_LOCK_STALE);
    let key = test_key();
    let lock = store.lock_file(&key);
    let _peer = create_lock_file(&lock).unwrap();
    let stale = temp_path(dir.path(), &key.hash());
    std::fs::write(&stale, b"stale refresh credential").unwrap();
    let file = OpenOptions::new().write(true).open(&stale).unwrap();
    file.set_modified(SystemTime::now() - DEFAULT_LOCK_STALE - Duration::from_secs(1))
        .unwrap();
    drop(file);

    let error = store.save(&key, &test_token()).unwrap_err();

    assert_eq!(
        error
            .downcast_ref::<std::io::Error>()
            .map(std::io::Error::kind),
        Some(std::io::ErrorKind::WouldBlock)
    );
    assert!(!store.token_file(&key).exists());
    assert!(stale.exists(), "save swept a temp without owning the lock");
    assert!(lock.exists(), "save removed the peer's live lock");
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
    // for the winner and the two critical sections never overlap.
    assert!(
        !overlap.load(Ordering::SeqCst),
        "lock did not serialise the two holders"
    );
}

#[test]
fn in_lock_never_runs_action_after_acquire_timeout() {
    let dir = TempDir::new().unwrap();
    let key = test_key();
    let store =
        FileTokenStore::at(dir.path()).with_lock_timings(Duration::ZERO, Duration::from_secs(600));
    let lock = store.lock_file(&key);
    let _peer = create_lock_file(&lock).unwrap();

    let ran = Arc::new(AtomicBool::new(false));
    let r = Arc::clone(&ran);
    let err = store
        .in_lock(&key, &mut || {
            r.store(true, Ordering::SeqCst);
            Ok(())
        })
        .unwrap_err();

    assert!(!ran.load(Ordering::SeqCst), "action ran without the lock");
    assert_eq!(
        err.downcast_ref::<std::io::Error>()
            .map(std::io::Error::kind),
        Some(std::io::ErrorKind::WouldBlock)
    );
    assert!(lock.exists(), "contender removed the peer's live lock");
}

#[test]
fn stale_lock_is_reported_but_never_stolen() {
    let dir = TempDir::new().unwrap();
    let key = test_key();
    let store =
        FileTokenStore::at(dir.path()).with_lock_timings(Duration::ZERO, Duration::from_secs(300));
    // Plant a lock and backdate its mtime well past the staleness window.
    let lock = store.lock_file(&key);
    std::fs::write(&lock, b"crashed-holder").unwrap();
    let f = OpenOptions::new().write(true).open(&lock).unwrap();
    f.set_modified(SystemTime::now() - Duration::from_secs(400))
        .unwrap();
    drop(f);

    let ran = Arc::new(AtomicBool::new(false));
    let r = Arc::clone(&ran);
    let err = store
        .in_lock(&key, &mut || {
            r.store(true, Ordering::SeqCst);
            Ok(())
        })
        .unwrap_err();

    assert!(!ran.load(Ordering::SeqCst), "action ran without the lock");
    assert!(
        err.to_string().contains("appears stale"),
        "unexpected error: {err}"
    );
    assert!(
        lock.exists(),
        "automatic stale recovery removed an unowned lock"
    );
}

#[test]
fn in_lock_releases_during_unwind() {
    let dir = TempDir::new().unwrap();
    let store = FileTokenStore::at(dir.path());
    let key = test_key();
    let lock = store.lock_file(&key);

    let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = store.in_lock(&key, &mut || -> TokenStoreResult<()> {
            panic!("test panic inside token-store action")
        });
    }));

    assert!(unwind.is_err());
    assert!(!lock.exists(), "unwinding left the owned lock behind");
    store.in_lock(&key, &mut || Ok(())).unwrap();
}

#[test]
fn with_lock_timings_enforces_stale_floor() {
    let store = FileTokenStore::at("/tmp/x")
        .with_lock_timings(Duration::from_secs(1), Duration::from_secs(1));
    // A sub-floor staleness window is clamped up to the 5-minute minimum.
    assert_eq!(store.lock_stale, MIN_LOCK_STALE);
}
