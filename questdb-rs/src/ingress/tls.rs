use crate::error::{Result, fmt};
use crate::ingress::CertificateAuthority;
use rustls::RootCertStore;
use rustls_pki_types::CertificateDer;
use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use std::sync::Arc;

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
        .extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned())
}

#[cfg(feature = "tls-native-certs")]
fn unpack_os_native_certs(
    res: rustls_native_certs::CertificateResult,
) -> crate::Result<Vec<rustls::pki_types::CertificateDer<'static>>> {
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

    Ok(res.certs)
}

#[cfg(feature = "tls-native-certs")]
fn add_os_roots(root_store: &mut RootCertStore) -> crate::Result<()> {
    let os_certs = unpack_os_native_certs(rustls_native_certs::load_native_certs())?;

    let (valid_count, invalid_count) = root_store.add_parsable_certificates(os_certs);
    if valid_count == 0 && invalid_count > 0 {
        return Err(fmt!(
            TlsError,
            "No valid certificates found in native root store ({} found but were invalid)",
            invalid_count
        ));
    }
    Ok(())
}

#[derive(Debug)]
pub(crate) enum TlsSettings {
    #[cfg(feature = "insecure-skip-verify")]
    SkipVerify,

    #[cfg(feature = "tls-webpki-certs")]
    WebpkiRoots,

    #[cfg(feature = "tls-native-certs")]
    OsRoots,

    #[cfg(all(feature = "tls-webpki-certs", feature = "tls-native-certs"))]
    WebpkiAndOsRoots,

    PemFile(Vec<CertificateDer<'static>>),
}

impl TlsSettings {
    pub fn build(
        enabled: bool,

        #[cfg(feature = "insecure-skip-verify")] verify_hostname: bool,

        ca: CertificateAuthority,
        roots: Option<&Path>,
    ) -> Result<Option<Self>> {
        if !enabled {
            return Ok(None);
        }

        #[cfg(feature = "insecure-skip-verify")]
        if !verify_hostname {
            return Ok(Some(TlsSettings::SkipVerify));
        }

        Ok(Some(match (ca, roots) {
            #[cfg(feature = "tls-webpki-certs")]
            (CertificateAuthority::WebpkiRoots, None) => TlsSettings::WebpkiRoots,

            #[cfg(feature = "tls-webpki-certs")]
            (CertificateAuthority::WebpkiRoots, Some(_)) => {
                return Err(fmt!(
                    ConfigError,
                    "Config parameter \"tls_roots\" must be unset when \"tls_ca\" is set to \"webpki_roots\"."
                ));
            }

            #[cfg(feature = "tls-native-certs")]
            (CertificateAuthority::OsRoots, None) => TlsSettings::OsRoots,

            #[cfg(feature = "tls-native-certs")]
            (CertificateAuthority::OsRoots, Some(_)) => {
                return Err(fmt!(
                    ConfigError,
                    "Config parameter \"tls_roots\" must be unset when \"tls_ca\" is set to \"os_roots\"."
                ));
            }

            #[cfg(all(feature = "tls-webpki-certs", feature = "tls-native-certs"))]
            (CertificateAuthority::WebpkiAndOsRoots, None) => TlsSettings::WebpkiAndOsRoots,

            #[cfg(all(feature = "tls-webpki-certs", feature = "tls-native-certs"))]
            (CertificateAuthority::WebpkiAndOsRoots, Some(_)) => {
                return Err(fmt!(
                    ConfigError,
                    "Config parameter \"tls_roots\" must be unset when \"tls_ca\" is set to \"webpki_and_os_roots\"."
                ));
            }

            (CertificateAuthority::PemFile, None) => {
                return Err(fmt!(
                    ConfigError,
                    "Config parameter \"tls_roots\" is required when \"tls_ca\" is set to \"pem_file\"."
                ));
            }

            (CertificateAuthority::PemFile, Some(pem_file)) => {
                let certfile = File::open(pem_file).map_err(|io_err| {
                    fmt!(
                        TlsError,
                        concat!(
                            "Could not open tls_roots certificate authority ",
                            "file from path {:?}: {}"
                        ),
                        pem_file,
                        io_err
                    )
                })?;
                let mut reader = BufReader::new(certfile);
                let der_certs = rustls_pemfile::certs(&mut reader)
                    .collect::<std::result::Result<Vec<_>, _>>()
                    .map_err(|io_err| {
                        fmt!(
                            TlsError,
                            concat!(
                                "Could not read certificate authority ",
                                "file from path {:?}: {}"
                            ),
                            pem_file,
                            io_err
                        )
                    })?;
                TlsSettings::PemFile(der_certs)
            }
        }))
    }
}

pub(crate) fn configure_tls(tls: TlsSettings) -> Result<Arc<rustls::ClientConfig>> {
    let mut root_store = RootCertStore::empty();

    #[cfg(feature = "insecure-skip-verify")]
    let mut verify_hostname = true;

    match tls {
        #[cfg(feature = "tls-webpki-certs")]
        TlsSettings::WebpkiRoots => add_webpki_roots(&mut root_store),

        #[cfg(feature = "tls-native-certs")]
        TlsSettings::OsRoots => add_os_roots(&mut root_store)?,

        #[cfg(all(feature = "tls-webpki-certs", feature = "tls-native-certs"))]
        TlsSettings::WebpkiAndOsRoots => {
            add_webpki_roots(&mut root_store);
            add_os_roots(&mut root_store)?;
        }

        TlsSettings::PemFile(der_certs) => {
            root_store.add_parsable_certificates(der_certs);
        }

        #[cfg(feature = "insecure-skip-verify")]
        TlsSettings::SkipVerify => {
            verify_hostname = false;
        }
    }

    let mut config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    // TLS log file for debugging.
    // Set the SSLKEYLOGFILE env variable to a writable location.
    config.key_log = Arc::new(rustls::KeyLogFile::new());

    #[cfg(feature = "insecure-skip-verify")]
    if !verify_hostname {
        config
            .dangerous()
            .set_certificate_verifier(Arc::new(danger::NoCertificateVerification {}));
    }

    Ok(Arc::new(config))
}
