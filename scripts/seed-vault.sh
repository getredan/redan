#!/usr/bin/env bash
# Seed Vault with test data for integration tests.
# Uses curl (no vault CLI required).
set -euo pipefail

: "${VAULT_ADDR:=http://127.0.0.1:8200}"
: "${VAULT_TOKEN:=redan-dev-token}"

echo "waiting for Vault at ${VAULT_ADDR}..."
for i in $(seq 1 30); do
    if curl -sf "${VAULT_ADDR}/v1/sys/health" >/dev/null 2>&1; then
        break
    fi
    if [ "$i" -eq 30 ]; then
        echo "error: Vault not ready after 30s" >&2
        exit 1
    fi
    sleep 1
done

curl -sf \
    -H "X-Vault-Token: ${VAULT_TOKEN}" \
    -X POST \
    -d '{"data": {"github_token": "ghp_test123", "npm_token": "npm_test456"}}' \
    "${VAULT_ADDR}/v1/secret/data/redan/test" >/dev/null

echo "Vault seeded: secret/redan/test"
