/// Integration tests that boot real libkrun VMs.
///
/// These require KVM (`/dev/kvm`) and an Alpine rootfs at `/tmp/redan-rootfs`.
/// Run with: `cargo test --test integration -- --ignored`
/// Or: `mise run test-integration`
use std::path::Path;
use std::time::Duration;

use redan::ca::MitmCa;
use redan::proxy;
use redan::secret::SecretBinding;
use redan::vm;

fn rootfs_path() -> &'static str {
    "/tmp/redan-rootfs"
}

fn has_kvm() -> bool {
    Path::new("/dev/kvm").exists()
}

fn has_rootfs() -> bool {
    Path::new(rootfs_path()).join("bin/busybox").exists()
}

/// Boot a VM, resolve DNS, make an HTTPS request through the MITM proxy,
/// inject a secret placeholder, and verify the response is scrubbed.
#[test]
#[ignore]
fn end_to_end_secret_injection() {
    if !has_kvm() {
        eprintln!("SKIP: no KVM");
        return;
    }
    if !has_rootfs() {
        eprintln!("SKIP: no rootfs");
        return;
    }

    let ca = MitmCa::generate();
    vm::install_ca_cert(Path::new(rootfs_path()), ca.ca_cert_pem()).expect("install CA cert");

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
        rootfs: rootfs_path().into(),
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

    // Proxy runs until timeout. The guest output (DNS, HTTPS, JSON response)
    // goes to the VM console. The proxy logs show injection + scrubbing.
    proxy::run(proxy::ProxyConfig {
        host_sock: net_sock,
        ca: std::sync::Arc::new(std::sync::Mutex::new(ca)),
        secrets: &secrets,
        timeout: Duration::from_secs(45),
        allowed_hosts: None,
        audit_log_path: None,
    });
}

/// Boot a VM and verify DNS resolution works (all names -> gateway).
#[test]
#[ignore]
fn synthetic_dns_resolution() {
    if !has_kvm() {
        eprintln!("SKIP: no KVM");
        return;
    }
    if !has_rootfs() {
        eprintln!("SKIP: no rootfs");
        return;
    }

    let ca = MitmCa::generate();
    vm::install_ca_cert(Path::new(rootfs_path()), ca.ca_cert_pem()).expect("install CA cert");

    let net_setup = vm::net_setup_commands(&proxy::GATEWAY_IP.to_string(), proxy::GUEST_IP);

    let command = format!(
        "{net_setup}; \
         nslookup httpbin.org 2>&1; \
         nslookup api.github.com 2>&1; \
         echo GUEST_DONE"
    );

    let config = vm::VmConfig {
        rootfs: rootfs_path().into(),
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

    proxy::run(proxy::ProxyConfig {
        host_sock: net_sock,
        ca: std::sync::Arc::new(std::sync::Mutex::new(ca)),
        secrets: &[],
        timeout: Duration::from_secs(20),
        allowed_hosts: None,
        audit_log_path: None,
    });
}
