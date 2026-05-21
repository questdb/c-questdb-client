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

//! Java KeyStore (JKS) / PKCS#12 truststore loader for `tls_roots` +
//! `tls_roots_password` parity with the Java client.
//!
//! Used by the QWP transports (egress reader + qwp-ws ingress sender)
//! to load the same trust-store shape the Java reference accepts —
//! `KeyStore.getInstance("JKS")` on the Java side, with the password
//! unlocking the file. ILP/TCP and ILP/HTTP keep their PEM-only
//! posture; rustls reads unencrypted PEM directly without a password.
//!
//! Format detection is by file magic: `0xFEEDFEED` -> JKS,
//! ASN.1 SEQUENCE (`0x30`) -> PKCS#12. Anything else is rejected with
//! a diagnostic naming both expected magics.
//!
//! Only **trusted certificate entries** are extracted. Any private-key
//! entries the file might also contain are ignored: this is a *trust
//! store*, not a client-identity store. (Java's reference path
//! likewise feeds the loaded `KeyStore` straight to
//! `TrustManagerFactory`.) DER bytes flow through to
//! `rustls::RootCertStore::add_parsable_certificates`, mirroring the
//! PEM path.

use std::fs;
use std::path::{Path, PathBuf};

use rustls_pki_types::CertificateDer;

/// Outcome of [`load_truststore_certs`]: DER-encoded trusted root
/// certificates, ready for `RootCertStore::add_parsable_certificates`.
pub(crate) type LoadedCerts = Vec<CertificateDer<'static>>;

/// Error returned by the loader. The transport-specific wrappers
/// (ingress, egress) convert this into their own error types — the
/// loader stays format-aware but transport-agnostic.
#[derive(Debug)]
pub(crate) struct KeystoreError {
    pub path: PathBuf,
    pub kind: KeystoreErrorKind,
}

#[derive(Debug)]
pub(crate) enum KeystoreErrorKind {
    /// Failed to open or read the file (path missing, permission, etc).
    Io(std::io::Error),
    /// First bytes are neither `0xFEEDFEED` (JKS) nor `0x30` (PKCS#12).
    UnknownFormat,
    /// JKS magic matched but parsing failed (bad password, truncated
    /// file, unsupported entry version, etc).
    JksParse(String),
    /// PKCS#12 magic matched but parsing failed.
    Pkcs12Parse(String),
    /// The keystore parsed cleanly but had no trusted-certificate
    /// entries — i.e. it's a key store, not a trust store. A
    /// no-cert trust store is functionally identical to no `tls_roots`
    /// at all, so callers get a config-shaped error rather than a
    /// silent empty `RootCertStore`.
    NoTrustedCerts,
}

impl std::fmt::Display for KeystoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.kind {
            KeystoreErrorKind::Io(e) => {
                write!(f, "Could not open tls_roots {:?}: {}", self.path, e)
            }
            KeystoreErrorKind::UnknownFormat => write!(
                f,
                "tls_roots {:?} is not a recognised keystore (expected JKS magic 0xFEEDFEED \
                 or PKCS#12 ASN.1 SEQUENCE prefix 0x30)",
                self.path
            ),
            KeystoreErrorKind::JksParse(msg) => write!(
                f,
                "Failed to parse JKS tls_roots {:?}: {} \
                 (wrong password, truncated, or unsupported version?)",
                self.path, msg
            ),
            KeystoreErrorKind::Pkcs12Parse(msg) => write!(
                f,
                "Failed to parse PKCS#12 tls_roots {:?}: {} \
                 (wrong password, truncated, or unsupported algorithm?)",
                self.path, msg
            ),
            KeystoreErrorKind::NoTrustedCerts => write!(
                f,
                "tls_roots {:?} contains no trusted-certificate entries — \
                 a trust store with only private keys is not usable",
                self.path
            ),
        }
    }
}

/// Load all trusted-certificate entries from a JKS or PKCS#12
/// keystore, returning their DER bytes.
///
/// Auto-detects the format by the first 4 bytes:
/// - `0xFEEDFEED` (big-endian): JKS — parsed via `jks` crate.
/// - `0x30`: ASN.1 SEQUENCE — PKCS#12, parsed via `p12-keystore`.
///
/// The password unlocks the file (verifies the JKS HMAC digest /
/// the PKCS#12 MAC). Private-key entries inside the file are silently
/// ignored — this is the trust-store half of the Java
/// `KeyStore.getInstance(...).load(...)` flow.
pub(crate) fn load_truststore_certs(
    path: &Path,
    password: &str,
) -> std::result::Result<LoadedCerts, KeystoreError> {
    let buf = fs::read(path).map_err(|e| KeystoreError {
        path: path.to_path_buf(),
        kind: KeystoreErrorKind::Io(e),
    })?;

    if buf.len() < 4 {
        return Err(KeystoreError {
            path: path.to_path_buf(),
            kind: KeystoreErrorKind::UnknownFormat,
        });
    }

    let magic = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
    let certs = if magic == 0xFEED_FEED {
        load_jks(path, &buf, password)?
    } else if buf[0] == 0x30 {
        load_pkcs12(path, &buf, password)?
    } else {
        return Err(KeystoreError {
            path: path.to_path_buf(),
            kind: KeystoreErrorKind::UnknownFormat,
        });
    };

    if certs.is_empty() {
        return Err(KeystoreError {
            path: path.to_path_buf(),
            kind: KeystoreErrorKind::NoTrustedCerts,
        });
    }
    Ok(certs)
}

fn load_jks(
    path: &Path,
    data: &[u8],
    password: &str,
) -> std::result::Result<LoadedCerts, KeystoreError> {
    let mut ks = jks::KeyStore::new();
    ks.load(data, password.as_bytes())
        .map_err(|e| KeystoreError {
            path: path.to_path_buf(),
            kind: KeystoreErrorKind::JksParse(e.to_string()),
        })?;

    let mut out = Vec::new();
    for alias in ks.aliases() {
        if !ks.is_trusted_certificate_entry(&alias) {
            continue;
        }
        let entry = ks
            .get_trusted_certificate_entry(&alias)
            .map_err(|e| KeystoreError {
                path: path.to_path_buf(),
                kind: KeystoreErrorKind::JksParse(e.to_string()),
            })?;
        out.push(CertificateDer::from(entry.certificate.content));
    }
    Ok(out)
}

fn load_pkcs12(
    path: &Path,
    data: &[u8],
    password: &str,
) -> std::result::Result<LoadedCerts, KeystoreError> {
    let ks = p12_keystore::KeyStore::from_pkcs12(data, password).map_err(|e| KeystoreError {
        path: path.to_path_buf(),
        kind: KeystoreErrorKind::Pkcs12Parse(e.to_string()),
    })?;

    let mut out = Vec::new();
    for (_alias, entry) in ks.entries() {
        if let p12_keystore::KeyStoreEntry::Certificate(cert) = entry {
            out.push(CertificateDer::from(cert.as_der().to_vec()));
        }
        // PrivateKeyChain / Secret entries: we're a trust store
        // loader, so ignore them (the Java reference does the same
        // by feeding the KeyStore to TrustManagerFactory, which
        // surfaces only the trusted-cert aliases).
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn missing_file() {
        let err = load_truststore_certs(Path::new("/no/such/file"), "x").unwrap_err();
        assert!(matches!(err.kind, KeystoreErrorKind::Io(_)));
    }

    #[test]
    fn empty_file_is_unknown_format() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("empty.bin");
        std::fs::File::create(&path).unwrap();
        let err = load_truststore_certs(&path, "x").unwrap_err();
        assert!(matches!(err.kind, KeystoreErrorKind::UnknownFormat));
    }

    #[test]
    fn random_bytes_are_unknown_format() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("garbage.bin");
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(&[0x12, 0x34, 0x56, 0x78, 0x9a]).unwrap();
        let err = load_truststore_certs(&path, "x").unwrap_err();
        assert!(matches!(err.kind, KeystoreErrorKind::UnknownFormat));
    }

    #[test]
    fn jks_magic_but_garbage_body_is_jks_parse_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad.jks");
        let mut f = std::fs::File::create(&path).unwrap();
        // FEEDFEED magic + garbage that fails further parsing or the
        // HMAC verify with this password.
        f.write_all(&[
            0xFE, 0xED, 0xFE, 0xED, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
        ])
        .unwrap();
        let err = load_truststore_certs(&path, "wrong").unwrap_err();
        assert!(
            matches!(err.kind, KeystoreErrorKind::JksParse(_)),
            "got: {:?}",
            err.kind
        );
    }

    // Round-trip a real CA cert through a synthetic JKS trust store
    // and confirm we recover the same DER bytes. The fixture is built
    // in-process via the `jks` crate so the test doesn't depend on a
    // pre-baked binary file checked into the repo.
    #[test]
    fn jks_truststore_round_trip() {
        use rustls_pki_types::CertificateDer;
        use rustls_pki_types::pem::PemObject;

        // Read the repo's CA fixture (PEM) and pick the first cert.
        let mut ca_path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        ca_path.pop();
        ca_path.push("tls_certs");
        ca_path.push("server_rootCA.pem");
        let pem_bytes = std::fs::read(&ca_path).unwrap();
        let mut der_iter = CertificateDer::pem_slice_iter(&pem_bytes);
        let ca_der = der_iter.next().unwrap().unwrap();
        let ca_der_bytes: Vec<u8> = ca_der.as_ref().to_vec();

        // Build an in-memory JKS keystore with that one trusted entry.
        let mut ks = jks::KeyStore::new();
        ks.set_trusted_certificate_entry(
            "ca",
            jks::TrustedCertificateEntry {
                creation_time: std::time::SystemTime::now(),
                certificate: jks::Certificate {
                    cert_type: "X.509".to_string(),
                    content: ca_der_bytes.clone(),
                },
            },
        )
        .unwrap();

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("trust.jks");
        let mut out = std::fs::File::create(&path).unwrap();
        ks.store(&mut out, b"changeit").unwrap();
        drop(out);

        // Wrong password must surface as JksParse (HMAC mismatch),
        // not as a silent "no certs".
        let err = load_truststore_certs(&path, "wrong").unwrap_err();
        assert!(
            matches!(err.kind, KeystoreErrorKind::JksParse(_)),
            "got: {:?}",
            err.kind
        );

        // Correct password recovers the same DER bytes.
        let certs = load_truststore_certs(&path, "changeit").unwrap();
        assert_eq!(certs.len(), 1);
        assert_eq!(certs[0].as_ref(), ca_der_bytes.as_slice());
    }
}
