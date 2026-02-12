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
use rustls::server::ResolvesServerCert;
use rustls::sign::CertifiedKey;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

#[derive(Debug)]
pub struct MitmCa {
    ca_params: CertificateParams,
    ca_key: KeyPair,
    ca_cert_der: CertificateDer<'static>,
    ca_cert_pem: String,
    /// Cached leaf CertifiedKeys per hostname.
    key_cache: HashMap<String, Arc<CertifiedKey>>,
}

impl MitmCa {
    #[must_use]
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
            key_cache: HashMap::new(),
        }
    }

    /// PEM-encoded CA certificate (for installing in guest trust store).
    #[must_use]
    pub fn ca_cert_pem(&self) -> &str {
        &self.ca_cert_pem
    }

    /// Mint (or return cached) leaf CertifiedKey for `hostname`.
    /// Returns None if the hostname is not a valid DNS name.
    pub fn certified_key_for(&mut self, hostname: &str) -> Option<Arc<CertifiedKey>> {
        if let Some(cached) = self.key_cache.get(hostname) {
            return Some(Arc::clone(cached));
        }

        let san: SanType = hostname
            .try_into()
            .map(SanType::DnsName)
            .ok()?;
        let mut params = CertificateParams::default();
        params.distinguished_name.push(DnType::CommonName, hostname);
        params.subject_alt_names = vec![san];
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

        let signing_key = rustls::crypto::ring::sign::any_supported_type(&key_der)
            .expect("signing key creation failed");
        let certified = Arc::new(CertifiedKey::new(
            vec![cert_der, self.ca_cert_der.clone()],
            signing_key,
        ));

        self.key_cache
            .insert(hostname.to_string(), Arc::clone(&certified));
        Some(certified)
    }
}

/// Dynamic cert resolver for rustls ServerConfig. Called during TLS
/// handshake with the client's SNI, generates a MITM leaf cert on
/// the fly. This lets rustls manage the entire handshake state machine.
#[derive(Debug)]
pub struct MitmCertResolver {
    pub ca: Arc<Mutex<MitmCa>>,
}

impl ResolvesServerCert for MitmCertResolver {
    fn resolve(
        &self,
        client_hello: rustls::server::ClientHello<'_>,
    ) -> Option<Arc<CertifiedKey>> {
        let sni = client_hello.server_name()?;
        let mut ca = self.ca.lock().ok()?;
        ca.certified_key_for(sni)
    }
}

/// Build a shared ServerConfig with dynamic MITM cert resolution.
/// One config is shared across all connections.
pub fn mitm_server_config(resolver: Arc<MitmCertResolver>) -> Arc<rustls::ServerConfig> {
    let mut config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(resolver);
    // Force HTTP/1.1 via ALPN. Prevents HTTP/2 negotiation which
    // would bypass our header-level secret injection/scrubbing.
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    // Disable session resumption. Each MITM connection does a full
    // handshake. Without this, clients cache tickets and attempt
    // resumption that fails because the cert resolver produces
    // per-hostname keys.
    config.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
    config.send_tls13_tickets = 0;
    Arc::new(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ca_generation() {
        let ca = MitmCa::generate();
        assert!(ca.ca_cert_pem().contains("BEGIN CERTIFICATE"));
    }

    #[test]
    fn test_certified_key_generation() {
        let mut ca = MitmCa::generate();
        let key1 = ca.certified_key_for("example.com").unwrap();
        let key2 = ca.certified_key_for("example.com").unwrap();
        // Same pointer (cached)
        assert!(Arc::ptr_eq(&key1, &key2));
    }

    #[test]
    fn test_cert_resolver() {
        let ca = Arc::new(Mutex::new(MitmCa::generate()));
        let resolver = MitmCertResolver { ca };
        // ResolvesServerCert requires a ClientHello, which is hard to
        // construct in tests. Just verify the type exists and compiles.
        let _: &dyn ResolvesServerCert = &resolver;
    }

    #[test]
    fn test_mitm_server_config() {
        rustls::crypto::ring::default_provider()
            .install_default()
            .ok(); // ignore if already installed
        let ca = Arc::new(Mutex::new(MitmCa::generate()));
        let resolver = Arc::new(MitmCertResolver { ca });
        let config = mitm_server_config(resolver);
        assert_eq!(config.alpn_protocols, vec![b"http/1.1".to_vec()]);
    }
}
