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

//! Build a `rustls::ClientConfig` for the QWP WebSocket transport.
//!
//! Mirrors the ingress sender's TLS-config flow (`crate::ingress::tls`) and
//! reports failures through the crate-wide [`Error`](crate::Error) surface.
//! The vocabulary of root sources matches the ingress `CertificateAuthority`
//! enum, which is re-exported from `crate::egress` for parity with the
//! connect-string keys.

use std::fs::File;
use std::path::Path;
use std::sync::Arc;

use rustls::RootCertStore;
use rustls_pki_types::CertificateDer;
use rustls_pki_types::pem::PemObject;

use crate::egress::config::ReaderConfig;
#[cfg(feature = "insecure-skip-verify")]
use crate::egress::config::TlsVerify;
use crate::error::{Result, fmt};
use crate::ingress::CertificateAuthority;

#[cfg(feature = "insecure-skip-verify")]
mod danger {
    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::{DigitallySignedStruct, Error, SignatureScheme};
    use rustls_pki_types::{CertificateDer, ServerName, UnixTime};

    #[derive(Debug)]
    pub struct NoCertificateVerification {}

    impl ServerCertVerifier for NoCertificateVerification {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp_response: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, Error> {
            Ok(ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        #[cfg(feature = "aws-lc-crypto")]
        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            rustls::crypto::aws_lc_rs::default_provider()
                .signature_verification_algorithms
                .supported_schemes()
        }

        #[cfg(feature = "ring-crypto")]
        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            rustls::crypto::ring::default_provider()
                .signature_verification_algorithms
                .supported_schemes()
        }
    }
}

#[cfg(feature = "tls-webpki-certs")]
fn add_webpki_roots(root_store: &mut RootCertStore) {
    root_store
        .roots
        .extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
}

#[cfg(feature = "tls-native-certs")]
fn add_os_roots(root_store: &mut RootCertStore) -> Result<()> {
    let res = rustls_native_certs::load_native_certs();
    if !res.errors.is_empty() {
        return Err(fmt!(
            TlsError,
            "Could not load OS native TLS certificates: {}",
            res.errors
                .iter()
                .map(|e| e.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    let total = res.certs.len();
    let (added, ignored) = root_store.add_parsable_certificates(res.certs);
    if added == 0 && ignored > 0 {
        return Err(fmt!(
            TlsError,
            "No valid certificates found in native root store ({} found but were invalid)",
            total
        ));
    }
    Ok(())
}

fn load_pem_file(path: &Path) -> Result<Vec<CertificateDer<'static>>> {
    let file = File::open(path).map_err(|e| {
        fmt!(
            TlsError,
            "Could not open tls_roots certificate file {:?}: {}",
            path,
            e
        )
    })?;
    CertificateDer::pem_reader_iter(file)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| {
            fmt!(
                TlsError,
                "Could not read tls_roots certificate file {:?}: {}",
                path,
                e
            )
        })
}

/// Build the rustls client config for the negotiated TLS knobs.
///
/// Returns `None` when TLS is disabled (plain `ws://` scheme) — the
/// transport then handshakes directly over the bare TCP stream.
pub(crate) fn build_client_config(
    config: &ReaderConfig,
) -> Result<Option<Arc<rustls::ClientConfig>>> {
    if !config.tls {
        return Ok(None);
    }

    let mut root_store = RootCertStore::empty();

    #[cfg(feature = "insecure-skip-verify")]
    let skip_verify = matches!(config.tls_verify, TlsVerify::UnsafeOff);
    #[cfg(not(feature = "insecure-skip-verify"))]
    let skip_verify = false;

    if !skip_verify {
        match config.tls_ca {
            #[cfg(feature = "tls-webpki-certs")]
            CertificateAuthority::WebpkiRoots => {
                if config.tls_roots.is_some() {
                    return Err(fmt!(
                        ConfigError,
                        "\"tls_roots\" must be unset when \"tls_ca=webpki_roots\""
                    ));
                }
                add_webpki_roots(&mut root_store);
            }

            #[cfg(feature = "tls-native-certs")]
            CertificateAuthority::OsRoots => {
                if config.tls_roots.is_some() {
                    return Err(fmt!(
                        ConfigError,
                        "\"tls_roots\" must be unset when \"tls_ca=os_roots\""
                    ));
                }
                add_os_roots(&mut root_store)?;
            }

            #[cfg(all(feature = "tls-webpki-certs", feature = "tls-native-certs"))]
            CertificateAuthority::WebpkiAndOsRoots => {
                if config.tls_roots.is_some() {
                    return Err(fmt!(
                        ConfigError,
                        "\"tls_roots\" must be unset when \"tls_ca=webpki_and_os_roots\""
                    ));
                }
                add_webpki_roots(&mut root_store);
                add_os_roots(&mut root_store)?;
            }

            CertificateAuthority::PemFile => {
                let path = config.tls_roots.as_deref().ok_or_else(|| {
                    fmt!(
                        ConfigError,
                        "\"tls_roots\" is required when \"tls_ca=pem_file\""
                    )
                })?;
                let der_certs = match config.tls_roots_password.as_deref() {
                    // No password -> PEM bundle (rustls' native input).
                    None => load_pem_file(Path::new(path))?,
                    // Password -> JKS / PKCS#12 trust store, matching
                    // the Java reference's `KeyStore.getInstance(...)`
                    // surface. Auto-detect by magic.
                    Some(pwd) => crate::keystore_roots::load_truststore_certs(Path::new(path), pwd)
                        .map_err(|e| fmt!(TlsError, "{}", e))?,
                };
                let total = der_certs.len();
                let (added, ignored) = root_store.add_parsable_certificates(der_certs);
                if added == 0 {
                    return Err(fmt!(
                        TlsError,
                        "No valid certificates found in tls_roots {:?} \
                         ({} parsed, {} rejected by rustls)",
                        path,
                        total,
                        ignored
                    ));
                }
            }
        }
    }

    #[cfg_attr(
        not(any(feature = "tls-key-log", feature = "insecure-skip-verify")),
        allow(unused_mut)
    )]
    let mut client_config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    #[cfg(feature = "tls-key-log")]
    {
        client_config.key_log = Arc::new(rustls::KeyLogFile::new());
    }

    #[cfg(feature = "insecure-skip-verify")]
    if skip_verify {
        client_config
            .dangerous()
            .set_certificate_verifier(Arc::new(danger::NoCertificateVerification {}));
    }

    Ok(Some(Arc::new(client_config)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::egress::config::ReaderConfig;
    use crate::error::ErrorCode;
    use std::io::Write;

    fn config_with_roots(path: &str) -> ReaderConfig {
        ReaderConfig::from_conf(format!("wss::addr=h:9000;tls_ca=pem_file;tls_roots={path}"))
            .unwrap()
    }

    #[test]
    fn pem_file_empty_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("empty.pem");
        std::fs::File::create(&path).unwrap();
        let cfg = config_with_roots(path.to_str().unwrap());
        let err = build_client_config(&cfg).unwrap_err();
        assert_eq!(err.code(), ErrorCode::TlsError);
        assert!(
            err.msg().contains("No valid certificates"),
            "got: {}",
            err.msg()
        );
    }

    #[test]
    fn pem_file_all_invalid_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("garbage.pem");
        let mut f = std::fs::File::create(&path).unwrap();
        // A syntactically valid PEM block whose body is not a valid DER
        // certificate. `pem_reader_iter` parses it; rustls then rejects
        // the bytes — so `added == 0 && ignored > 0`.
        writeln!(
            f,
            "-----BEGIN CERTIFICATE-----\nbm90LWEtY2VydA==\n-----END CERTIFICATE-----"
        )
        .unwrap();
        let cfg = config_with_roots(path.to_str().unwrap());
        let err = build_client_config(&cfg).unwrap_err();
        assert_eq!(err.code(), ErrorCode::TlsError);
        assert!(
            err.msg().contains("rejected by rustls"),
            "got: {}",
            err.msg()
        );
    }

    #[test]
    fn pem_file_missing_rejected() {
        let cfg = config_with_roots("/this/path/does/not/exist.pem");
        let err = build_client_config(&cfg).unwrap_err();
        assert_eq!(err.code(), ErrorCode::TlsError);
        assert!(err.msg().contains("Could not open"), "got: {}", err.msg());
    }
}
