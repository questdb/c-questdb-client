use crate::error;
use crate::ingress::{add_webpki_roots, CertificateAuthority};
use rustls::RootCertStore;
use std::io::BufReader;
use std::path::Path;
use std::sync::Arc;

pub(crate) fn configure_tls(
    tls_enabled: bool,
    tls_verify: bool,
    tls_ca: CertificateAuthority,
    tls_roots: Option<&Path>,
) -> crate::Result<Option<Arc<rustls::ClientConfig>>> {
    if !tls_enabled {
        return Ok(None);
    }

    let mut root_store = RootCertStore::empty();
    if tls_verify {
        match (tls_ca, tls_roots) {
            #[cfg(feature = "tls-webpki-certs")]
            (CertificateAuthority::WebpkiRoots, None) => {
                add_webpki_roots(&mut root_store);
            }

            #[cfg(feature = "tls-webpki-certs")]
            (CertificateAuthority::WebpkiRoots, Some(_)) => {
                return Err(error::fmt!(ConfigError, "Config parameter \"tls_roots\" must be unset when \"tls_ca\" is set to \"webpki_roots\"."));
            }

            #[cfg(feature = "tls-native-certs")]
            (CertificateAuthority::OsRoots, None) => {
                crate::ingress::add_os_roots(&mut root_store)?;
            }

            #[cfg(feature = "tls-native-certs")]
            (CertificateAuthority::OsRoots, Some(_)) => {
                return Err(error::fmt!(ConfigError, "Config parameter \"tls_roots\" must be unset when \"tls_ca\" is set to \"os_roots\"."));
            }

            #[cfg(all(feature = "tls-webpki-certs", feature = "tls-native-certs"))]
            (CertificateAuthority::WebpkiAndOsRoots, None) => {
                add_webpki_roots(&mut root_store);
                crate::ingress::add_os_roots(&mut root_store)?;
            }

            #[cfg(all(feature = "tls-webpki-certs", feature = "tls-native-certs"))]
            (CertificateAuthority::WebpkiAndOsRoots, Some(_)) => {
                return Err(error::fmt!(ConfigError, "Config parameter \"tls_roots\" must be unset when \"tls_ca\" is set to \"webpki_and_os_roots\"."));
            }

            (CertificateAuthority::PemFile, Some(ca_file)) => {
                let certfile = std::fs::File::open(ca_file).map_err(|io_err| {
                    error::fmt!(
                        TlsError,
                        concat!(
                            "Could not open tls_roots certificate authority ",
                            "file from path {:?}: {}"
                        ),
                        ca_file,
                        io_err
                    )
                })?;
                let mut reader = BufReader::new(certfile);
                let der_certs = rustls_pemfile::certs(&mut reader)
                    .collect::<std::result::Result<Vec<_>, _>>()
                    .map_err(|io_err| {
                        error::fmt!(
                            TlsError,
                            concat!(
                                "Could not read certificate authority ",
                                "file from path {:?}: {}"
                            ),
                            ca_file,
                            io_err
                        )
                    })?;
                root_store.add_parsable_certificates(der_certs);
            }

            (CertificateAuthority::PemFile, None) => {
                return Err(error::fmt!(ConfigError, "Config parameter \"tls_roots\" is required when \"tls_ca\" is set to \"pem_file\"."));
            }
        }
    }

    let mut config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    // TLS log file for debugging.
    // Set the SSLKEYLOGFILE env variable to a writable location.
    config.key_log = Arc::new(rustls::KeyLogFile::new());

    #[cfg(feature = "insecure-skip-verify")]
    if !tls_verify {
        config.dangerous().set_certificate_verifier(Arc::new(
            crate::ingress::danger::NoCertificateVerification {},
        ));
    }

    Ok(Some(Arc::new(config)))
}
