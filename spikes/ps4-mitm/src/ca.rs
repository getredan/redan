/// Ephemeral CA for MITM TLS interception.
/// Generates a self-signed root CA on startup, then mints leaf certificates
/// on-the-fly for each SNI hostname the guest connects to.

use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose, SanType,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::sync::Arc;

pub struct MitmCa {
    ca_cert: Certificate,
    ca_key: KeyPair,
    ca_cert_der: CertificateDer<'static>,
    ca_cert_pem: String,
}

impl MitmCa {
    pub fn generate() -> Self {
        let mut params = CertificateParams::default();
        params
            .distinguished_name
            .push(DnType::CommonName, "Redan MITM CA");
        params
            .distinguished_name
            .push(DnType::OrganizationName, "Redan");
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        params.not_before = rcgen::date_time_ymd(2020, 1, 1);
        params.not_after = rcgen::date_time_ymd(2030, 1, 1);

        let key = KeyPair::generate().expect("CA key generation failed");
        let cert = params.self_signed(&key).expect("CA self-sign failed");
        let ca_cert_der = CertificateDer::from(cert.der().to_vec());
        let ca_cert_pem = cert.pem();

        Self {
            ca_cert: cert,
            ca_key: key,
            ca_cert_der,
            ca_cert_pem,
        }
    }

    /// PEM-encoded CA certificate (for installing in guest trust store)
    pub fn ca_cert_pem(&self) -> &str {
        &self.ca_cert_pem
    }

    /// Build a rustls ServerConfig for a given hostname.
    pub fn server_config_for(&self, hostname: &str) -> Arc<rustls::ServerConfig> {
        let mut params = CertificateParams::default();
        params
            .distinguished_name
            .push(DnType::CommonName, hostname);
        params.subject_alt_names = vec![SanType::DnsName(hostname.try_into().unwrap())];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.not_before = rcgen::date_time_ymd(2020, 1, 1);
        params.not_after = rcgen::date_time_ymd(2030, 1, 1);

        let leaf_key = KeyPair::generate().expect("leaf key generation failed");
        let leaf_cert = params
            .signed_by(&leaf_key, &self.ca_cert, &self.ca_key)
            .expect("leaf cert signing failed");

        let cert_der = CertificateDer::from(leaf_cert.der().to_vec());
        let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));

        let config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der, self.ca_cert_der.clone()], key_der)
            .expect("rustls ServerConfig failed");
        Arc::new(config)
    }
}
