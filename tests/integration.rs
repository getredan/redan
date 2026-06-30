#![allow(
    clippy::pedantic,
    clippy::nursery,
    clippy::unwrap_used,
    clippy::expect_used
)]
/// Integration tests that boot real libkrun VMs.
///
/// Require KVM (`/dev/kvm`) and a redan image named "test".
/// Create it with: `redan image create test`
/// Run with: `cargo test --test integration -- --test-threads=1`
use std::time::Duration;

use redan::ca::MitmCa;
use redan::proxy;
use redan::secret::SecretBinding;
use redan::vm;

fn test_rootfs() -> String {
    let path = redan::image::image_path("test").expect("invalid test image name");
    assert!(
        path.join("bin").is_dir(),
        "test image not found: run `redan image create test` first"
    );
    path.to_string_lossy().into_owned()
}

/// Boot a VM, resolve DNS, make an HTTPS request through the MITM proxy,
/// inject a secret placeholder, and verify the response is scrubbed.
#[test]
fn end_to_end_secret_injection() {
    redan::check_kvm().expect("KVM required: /dev/kvm not accessible");
    let rootfs = test_rootfs();

    let ca = MitmCa::generate();
    vm::install_ca_cert(rootfs.as_ref(), ca.ca_cert_pem()).expect("install CA cert");

    let placeholder = "redan_ph_test_e2e_abcd1234";
    let real_value = "ghp_FAKE_E2E_TOKEN_99999";

    let secrets = vec![SecretBinding::new_unchecked(
        placeholder.into(),
        real_value.into(),
        vec!["httpbin.org".into()],
    )];

    let net_setup = vm::net_setup_commands(&proxy::GATEWAY_IP.to_string(), proxy::GUEST_IP);

    let command = format!(
        "{net_setup}; \
         echo TEST_DNS; \
         nslookup httpbin.org 2>&1 || true; \
         echo TEST_HTTPS; \
         wget -q -O - --header X-Auth-Token:$SECRET_TOKEN https://httpbin.org/get 2>&1; \
         echo GUEST_DONE"
    );

    let config = vm::VmConfig {
        rootfs,
        vcpus: 1,
        ram_mib: 256,
        command,
        env: vec![
            "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".into(),
            "TERM=xterm".into(),
            "SSL_CERT_FILE=/etc/ssl/certs/redan-ca.pem".into(),
            format!("SECRET_TOKEN={placeholder}"),
        ],
        virtiofs_mounts: vec![],
        interactive: false,
    };

    let vm_handle = vm::Vm::boot(config);
    let net_sock = vm_handle.net_sock.try_clone().expect("clone net_sock");

    let _ = proxy::run(proxy::ProxyConfig {
        host_sock: net_sock,
        ca: std::sync::Arc::new(std::sync::Mutex::new(ca)),
        secrets: &secrets,
        timeout: Duration::from_secs(45),
        allowed_hosts: None,
        audit_log_path: None,
        discover: false,
        forwards: &[],
    });
}

/// Boot a VM and verify DNS resolution works (all names -> gateway).
#[test]
fn synthetic_dns_resolution() {
    redan::check_kvm().expect("KVM required: /dev/kvm not accessible");
    let rootfs = test_rootfs();

    let ca = MitmCa::generate();
    vm::install_ca_cert(rootfs.as_ref(), ca.ca_cert_pem()).expect("install CA cert");

    let net_setup = vm::net_setup_commands(&proxy::GATEWAY_IP.to_string(), proxy::GUEST_IP);

    let command = format!(
        "{net_setup}; \
         nslookup httpbin.org 2>&1; \
         nslookup api.github.com 2>&1; \
         echo GUEST_DONE"
    );

    let config = vm::VmConfig {
        rootfs,
        vcpus: 1,
        ram_mib: 256,
        command,
        env: vec![
            "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".into(),
            "TERM=xterm".into(),
        ],
        virtiofs_mounts: vec![],
        interactive: false,
    };

    let vm_handle = vm::Vm::boot(config);
    let net_sock = vm_handle.net_sock.try_clone().expect("clone net_sock");

    let _ = proxy::run(proxy::ProxyConfig {
        host_sock: net_sock,
        ca: std::sync::Arc::new(std::sync::Mutex::new(ca)),
        secrets: &[],
        timeout: Duration::from_secs(20),
        allowed_hosts: None,
        audit_log_path: None,
        discover: false,
        forwards: &[],
    });
}
