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
//! Mirrors the ingress sender's TLS-config flow (`crate::ingress::tls`)
//! but plugs into egress error types so callers see a consistent
//! `egress::Error` surface. The vocabulary of root sources matches the
//! ingress `CertificateAuthority` enum, which is re-exported from
//! `crate::egress` for parity with the connect-string keys.

#![cfg(feature = "sync-reader-ws")]

use std::fs::File;
use std::path::Path;
use std::sync::Arc;

use rustls::RootCertStore;
use rustls_pki_types::CertificateDer;
use rustls_pki_types::pem::PemObject;

use crate::egress::config::{ReaderConfig, TlsVerify};
use crate::egress::error::{Result, fmt};
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
/// Returns `None` when TLS is disabled (plain `qwp://` scheme) — the
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
                let der_certs = load_pem_file(Path::new(path))?;
                root_store.add_parsable_certificates(der_certs);
            }
        }
    }

    let mut client_config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    client_config.key_log = Arc::new(rustls::KeyLogFile::new());

    #[cfg(feature = "insecure-skip-verify")]
    if skip_verify {
        client_config
            .dangerous()
            .set_certificate_verifier(Arc::new(danger::NoCertificateVerification {}));
    }

    Ok(Some(Arc::new(client_config)))
}
