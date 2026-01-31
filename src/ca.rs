/// Ephemeral CA for MITM TLS interception.
///
/// Generates a self-signed root CA on startup, then mints leaf certificates
/// on-the-fly for each SNI hostname the guest connects to. Leaf certs are
/// cached per hostname to avoid repeated key generation during burst
/// workloads (e.g., npm install hitting the same registry 30+ times).
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose, SanType,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::collections::HashMap;
use std::sync::Arc;

pub struct MitmCa {
    ca_params: CertificateParams,
    ca_key: KeyPair,
    ca_cert_der: CertificateDer<'static>,
    ca_cert_pem: String,
    /// Cached leaf certs per hostname. The cache lives for the process
    /// lifetime (ephemeral per redan run), so no expiration needed.
    cert_cache: HashMap<String, Arc<rustls::ServerConfig>>,
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
        // CA is ephemeral (regenerated per run). Short validity limits
        // exposure if the key is somehow extracted from host memory.
        let now = time::OffsetDateTime::now_utc();
        let one_year = now + time::Duration::days(365);
        params.not_before = now;
        params.not_after = one_year;

        let key = KeyPair::generate().expect("CA key generation failed");
        let cert = params.self_signed(&key).expect("CA self-sign failed");
        let ca_cert_der = CertificateDer::from(cert.der().to_vec());
        let ca_cert_pem = cert.pem();

        Self {
            ca_params: params,
            ca_key: key,
            ca_cert_der,
            ca_cert_pem,
            cert_cache: HashMap::new(),
        }
    }

    /// PEM-encoded CA certificate (for installing in guest trust store).
    pub fn ca_cert_pem(&self) -> &str {
        &self.ca_cert_pem
    }

    /// Build a rustls ServerConfig that presents an ephemeral leaf cert for `hostname`,
    /// signed by this CA. Caches the result per hostname.
    pub fn server_config_for(&mut self, hostname: &str) -> Arc<rustls::ServerConfig> {
        if let Some(cached) = self.cert_cache.get(hostname) {
            return Arc::clone(cached);
        }
        let mut params = CertificateParams::default();
        params.distinguished_name.push(DnType::CommonName, hostname);
        params.subject_alt_names = vec![SanType::DnsName(hostname.try_into().unwrap())];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let now = time::OffsetDateTime::now_utc();
        params.not_before = now;
        params.not_after = now + time::Duration::days(1);

        let leaf_key = KeyPair::generate().expect("leaf key generation failed");
        let issuer = Issuer::from_params(&self.ca_params, &self.ca_key);
        let leaf_cert = params
            .signed_by(&leaf_key, &issuer)
            .expect("leaf cert signing failed");

        let cert_der = CertificateDer::from(leaf_cert.der().to_vec());
        let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));

        let config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der, self.ca_cert_der.clone()], key_der)
            .expect("rustls ServerConfig failed");
        let config = Arc::new(config);
        self.cert_cache
            .insert(hostname.to_string(), Arc::clone(&config));
        config
    }
}
