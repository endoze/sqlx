#![cfg(any(
    feature = "tls-rustls-aws-lc-rs",
    feature = "tls-rustls-ring-webpki",
    feature = "tls-rustls-ring-native-roots"
))]

use std::env;
use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::WebPkiServerVerifier;
use rustls::crypto::CryptoProvider;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{
    CertificateError, ClientConfig, DigitallySignedStruct, Error as TlsError, RootCertStore,
    SignatureScheme,
};
use sqlx::postgres::{PgConnectOptions, PgConnection, PgSslMode};
use sqlx::{ConnectOptions, Connection};
use sqlx_core::rustls;

const TEST_CA: &str = "tests/certs/ca.crt";
const OTHER_CA: &str = "tests/certs/rsa/ca.crt";

#[sqlx_macros::test]
async fn it_requires_tls_with_a_custom_config() -> anyhow::Result<()> {
    let Some(options) = tcp_options()? else {
        return Ok(());
    };
    let options = options
        .ssl_mode(PgSslMode::Disable)
        .ssl_client_config(client_config(TEST_CA)?);

    let mut conn = PgConnection::connect_with(&options).await?;
    let ssl: bool = sqlx::query_scalar("SELECT ssl FROM pg_stat_ssl WHERE pid = pg_backend_pid()")
        .fetch_one(&mut conn)
        .await?;

    assert!(ssl);

    conn.close().await?;

    Ok(())
}

#[sqlx_macros::test]
async fn it_rejects_a_server_outside_the_custom_roots() -> anyhow::Result<()> {
    let Some(options) = tcp_options()? else {
        return Ok(());
    };
    let options = options
        .ssl_mode(PgSslMode::VerifyCa)
        .ssl_root_cert(TEST_CA)
        .ssl_client_config(client_config(OTHER_CA)?);

    let err = PgConnection::connect_with(&options)
        .await
        .expect_err("server cert is not signed by the configured root");

    let tls_err = match &err {
        sqlx::Error::Io(io) => io.get_ref().and_then(|e| e.downcast_ref::<TlsError>()),
        _ => None,
    };

    assert!(
        matches!(
            tls_err,
            Some(TlsError::InvalidCertificate(
                CertificateError::UnknownIssuer
            ))
        ),
        "expected an unknown issuer error, got {err:?}"
    );

    Ok(())
}

#[sqlx_macros::test]
async fn it_marks_a_custom_config_in_the_url() -> anyhow::Result<()> {
    let options = PgConnectOptions::new_without_pgpass()
        .host("localhost")
        .ssl_client_config(client_config(TEST_CA)?);

    let url = options.to_url_lossy();

    assert!(url
        .query_pairs()
        .any(|(k, v)| k == "danger-custom-ssl-config" && v == "true"));

    let err = PgConnection::connect(url.as_str())
        .await
        .expect_err("URL without its TLS config must not connect");

    assert!(
        matches!(err, sqlx::Error::Configuration(_)),
        "expected a configuration error, got {err:?}"
    );

    Ok(())
}

fn tcp_options() -> anyhow::Result<Option<PgConnectOptions>> {
    let options: PgConnectOptions = env::var("DATABASE_URL")?.parse()?;

    if options.get_socket().is_some() || options.get_host().starts_with('/') {
        return Ok(None);
    }

    Ok(Some(options))
}

/// Trusts only `ca_path` and presents the test client certificate.
///
/// The test server certificate has no subject alternative name, so the hostname check is
/// skipped, as with `sslmode=verify-ca`.
fn client_config(ca_path: &str) -> anyhow::Result<Arc<ClientConfig>> {
    let provider = provider();
    let mut roots = RootCertStore::empty();

    for cert in CertificateDer::pem_file_iter(ca_path)? {
        roots.add(cert?)?;
    }

    let verifier =
        WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider.clone()).build()?;
    let client_chain =
        CertificateDer::pem_file_iter("tests/certs/client.crt")?.collect::<Result<Vec<_>, _>>()?;
    let client_key = PrivateKeyDer::from_pem_file("tests/certs/keys/client.key")?;
    let config = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(IgnoreHostname(verifier)))
        .with_client_auth_cert(client_chain, client_key)?;

    Ok(Arc::new(config))
}

fn provider() -> Arc<CryptoProvider> {
    #[cfg(feature = "tls-rustls-aws-lc-rs")]
    return Arc::new(rustls::crypto::aws_lc_rs::default_provider());

    #[cfg(not(feature = "tls-rustls-aws-lc-rs"))]
    return Arc::new(rustls::crypto::ring::default_provider());
}

#[derive(Debug)]
struct IgnoreHostname(Arc<WebPkiServerVerifier>);

impl ServerCertVerifier for IgnoreHostname {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        match self
            .0
            .verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)
        {
            Err(TlsError::InvalidCertificate(
                CertificateError::NotValidForName | CertificateError::NotValidForNameContext { .. },
            )) => Ok(ServerCertVerified::assertion()),
            res => res,
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        self.0.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        self.0.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.supported_verify_schemes()
    }
}
