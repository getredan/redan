#![allow(
    clippy::pedantic,
    clippy::nursery,
    clippy::unwrap_used,
    clippy::expect_used
)]
//! Integration tests against a real Vault instance.
//!
//! Require VAULT_ADDR + VAULT_TOKEN and `redan/test` seeded with:
//!   vault kv put secret/redan/test github_token=ghp_test123 npm_token=npm_test456

use redan::provider::{SecretProvider, Vault, resolve_secret_value};
use redan::secret::SecretBinding;

fn vault() -> Vault {
    Vault::from_env().expect("Vault env not configured")
}

#[test]
fn vault_fetch_real_secret() {
    let value = vault().resolve("redan/test#github_token").unwrap();
    assert_eq!(value, "ghp_test123");
}

#[test]
fn vault_fetch_second_field() {
    let value = vault().resolve("redan/test#npm_token").unwrap();
    assert_eq!(value, "npm_test456");
}

#[test]
fn vault_missing_field_errors() {
    let err = vault().resolve("redan/test#nonexistent").unwrap_err();
    assert!(err.to_string().contains("not found"));
}

#[test]
fn vault_missing_path_errors() {
    let err = vault().resolve("nonexistent/path#field").unwrap_err();
    assert!(err.to_string().contains("vault request failed"));
}

#[test]
fn vault_via_resolve_function() {
    let value =
        resolve_secret_value("vault://redan/test#github_token").expect("Vault env not configured");
    assert_eq!(value, "ghp_test123");
}

#[test]
fn vault_resolve_into_secret_binding() {
    let value = resolve_secret_value("vault://redan/test#github_token").unwrap();
    let binding = SecretBinding::new("TOKEN", value, vec!["api.github.com".into()]).unwrap();
    assert_eq!(binding.real_value(), "ghp_test123");
    assert_eq!(binding.allowed_hosts(), &["api.github.com"]);
}
