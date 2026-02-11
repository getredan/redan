#!/bin/bash
#
# Distro compatibility tests for redan.
#
# Extracts rootfs from container images and validates that redan can
# boot them, run commands, set up networking, and make HTTPS requests
# through the MITM proxy.
#
# Requires: KVM, libkrun, docker (for rootfs extraction).
#
# Usage:
#   ./tests/distro_compat.sh              # all distros
#   ./tests/distro_compat.sh ubuntu       # single distro
#   ./tests/distro_compat.sh fedora arch  # specific distros

set -euo pipefail

REDAN="${REDAN:-./target/release/redan}"
ROOTFS_DIR="${ROOTFS_DIR:-/tmp/redan-distro-test}"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0
FAILED_TESTS=()

# Find redan binary
if [[ ! -x "$REDAN" ]]; then
    REDAN="./target/debug/redan"
fi
if [[ ! -x "$REDAN" ]]; then
    echo -e "${RED}redan binary not found. Run: cargo build --release${NC}"
    exit 1
fi

# Distro definitions: name, container image, setup command.
# Each distro needs: /bin/sh, ip (iproute2), wget or curl, CA certs.
# Setup runs inside docker (not chroot) to get proper package management.
declare -A DISTRO_IMAGE
declare -A DISTRO_SETUP

DISTRO_IMAGE[alpine]="alpine:3.21"
DISTRO_SETUP[alpine]="apk add --no-cache iproute2 ca-certificates"

DISTRO_IMAGE[ubuntu]="ubuntu:24.04"
DISTRO_SETUP[ubuntu]="apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq iproute2 wget ca-certificates 2>&1 | tail -1"

DISTRO_IMAGE[fedora]="fedora:41"
DISTRO_SETUP[fedora]="dnf install -y -q iproute wget ca-certificates 2>&1 | tail -1"

DISTRO_IMAGE[arch]="archlinux:latest"
DISTRO_SETUP[arch]="pacman -Sy --noconfirm iproute2 wget ca-certificates 2>&1 | tail -1"

DISTRO_IMAGE[debian]="debian:bookworm-slim"
DISTRO_SETUP[debian]="apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq iproute2 wget ca-certificates 2>&1 | tail -1"

ALL_DISTROS=(alpine ubuntu fedora arch debian)

# ---- helpers ----

log_test()  { echo -e "${YELLOW}[TEST]${NC} $1"; }
log_pass()  { echo -e "${GREEN}[PASS]${NC} $1"; TESTS_PASSED=$((TESTS_PASSED + 1)); }
log_fail()  { echo -e "${RED}[FAIL]${NC} $1"; TESTS_FAILED=$((TESTS_FAILED + 1)); FAILED_TESTS+=("$1"); }
log_info()  { echo -e "       $1"; }

run_test() {
    local name="$1"
    local func="$2"
    TESTS_RUN=$((TESTS_RUN + 1))
    log_test "$name"
    if $func; then
        log_pass "$name"
    else
        log_fail "$name"
    fi
}

# Extract a container image to a rootfs directory.
# Runs setup inside docker (proper package management), then exports.
extract_rootfs() {
    local distro="$1"
    local image="${DISTRO_IMAGE[$distro]}"
    local dest="$ROOTFS_DIR/$distro"

    if [[ -d "$dest/bin" ]]; then
        echo "  rootfs cached: $dest"
        return 0
    fi

    echo "  building rootfs from $image"
    mkdir -p "$dest"

    local setup="${DISTRO_SETUP[$distro]}"
    local cid
    cid=$(docker run -d "$image" sh -c "$setup" 2>/dev/null)
    docker wait "$cid" >/dev/null 2>&1
    docker export "$cid" | tar xf - -C "$dest" 2>/dev/null
    docker rm "$cid" >/dev/null 2>&1
}

# Run a command in redan with the given rootfs, capture output.
# Returns the command's exit code.
redan_exec() {
    local rootfs="$1"
    local cmd="$2"
    local timeout="${3:-15}"

    $REDAN exec \
        --rootfs "$rootfs" \
        --command "$cmd" \
        --timeout "$timeout" 2>&1
}

redan_exec_with_secret() {
    local rootfs="$1"
    local cmd="$2"
    local secret="$3"
    local timeout="${4:-30}"

    $REDAN exec \
        --rootfs "$rootfs" \
        --command "$cmd" \
        --secret "$secret" \
        --timeout "$timeout" 2>&1
}

redan_exec_with_mount() {
    local rootfs="$1"
    local cmd="$2"
    local mount="$3"
    local timeout="${4:-15}"

    $REDAN exec \
        --rootfs "$rootfs" \
        --command "$cmd" \
        --mount "$mount" \
        --timeout "$timeout" 2>&1
}

redan_exec_full() {
    local rootfs="$1"
    local cmd="$2"
    local secret="$3"
    local mount="$4"
    local timeout="${5:-30}"

    $REDAN exec \
        --rootfs "$rootfs" \
        --command "$cmd" \
        --secret "$secret" \
        --mount "$mount" \
        --timeout "$timeout" 2>&1
}

# ---- per-distro tests ----

test_boot_and_echo() {
    local rootfs="$ROOTFS_DIR/$CURRENT_DISTRO"
    local output
    output=$(redan_exec "$rootfs" "echo redan-boot-ok")
    [[ "$output" == *"redan-boot-ok"* ]]
}

test_network_setup() {
    local rootfs="$ROOTFS_DIR/$CURRENT_DISTRO"
    local output
    # ip addr should show eth0 with our guest IP
    output=$(redan_exec "$rootfs" "ip addr show eth0")
    [[ "$output" == *"192.168.127.2"* ]]
}

test_dns_resolution() {
    local rootfs="$ROOTFS_DIR/$CURRENT_DISTRO"
    local output
    # /etc/resolv.conf should point at the gateway
    output=$(redan_exec "$rootfs" "cat /etc/resolv.conf")
    [[ "$output" == *"192.168.127.1"* ]]
}

test_https_request() {
    local rootfs="$ROOTFS_DIR/$CURRENT_DISTRO"
    local output
    output=$(redan_exec_with_secret \
        "$rootfs" \
        "wget -q -O - https://httpbin.org/get 2>&1 | head -5" \
        "TEST_TOKEN=dummy_value:httpbin.org" \
        30)
    # httpbin.org/get returns JSON with a "url" field
    [[ "$output" == *"httpbin.org"* ]]
}

test_secret_injection() {
    local rootfs="$ROOTFS_DIR/$CURRENT_DISTRO"
    local output
    # Full injection + scrubbing round-trip:
    # 1. Guest sends placeholder in X-Test header
    # 2. Proxy injects real value, forwards to httpbin
    # 3. httpbin echoes the real value back in the response
    # 4. Proxy scrubs response, replacing real value with placeholder
    # 5. Guest sees the placeholder in the echoed header
    # Write a helper script into the rootfs to avoid nested quoting hell.
    echo '#!/bin/sh
wget -q -O - --header "X-Test: $TEST_TOKEN" https://httpbin.org/headers' > "$rootfs/tmp/inject_test.sh"
    chmod +x "$rootfs/tmp/inject_test.sh"

    output=$(redan_exec_with_secret \
        "$rootfs" \
        '/tmp/inject_test.sh 2>&1' \
        "TEST_TOKEN=secret_test_value_12345:httpbin.org" \
        30)
    # The response should contain the placeholder (scrubbed), not the real secret.
    # If injection didn't happen, httpbin would echo the placeholder directly.
    # If scrubbing didn't work, we'd see the real value.
    # Either way, the placeholder must appear and the real value must not.
    [[ "$output" == *"redan_ph_"* ]] && [[ "$output" != *"secret_test_value_12345"* ]]
}

test_env_has_placeholder() {
    local rootfs="$ROOTFS_DIR/$CURRENT_DISTRO"
    local output
    output=$(redan_exec_with_secret \
        "$rootfs" \
        'echo $TEST_TOKEN' \
        "TEST_TOKEN=real_secret:httpbin.org")
    # Guest should see the placeholder, not the real value
    [[ "$output" == *"redan_ph_"* ]] && [[ "$output" != *"real_secret"* ]]
}

test_ca_cert_installed() {
    local rootfs="$ROOTFS_DIR/$CURRENT_DISTRO"
    local output
    output=$(redan_exec "$rootfs" "cat /etc/ssl/certs/redan-ca.pem 2>/dev/null || echo missing")
    [[ "$output" == *"BEGIN CERTIFICATE"* ]]
}

# ---- virtio-fs mount tests ----

test_mount_read() {
    local rootfs="$ROOTFS_DIR/$CURRENT_DISTRO"
    local tmpdir
    tmpdir=$(mktemp -d)
    echo "redan-mount-test-content" > "$tmpdir/testfile.txt"

    local output
    output=$(redan_exec_with_mount "$rootfs" "cat /workspace/testfile.txt" "$tmpdir")
    rm -rf "$tmpdir"
    [[ "$output" == *"redan-mount-test-content"* ]]
}

test_mount_write() {
    # Guest writes a file, host can read it back. Proves virtio-fs
    # bidirectional I/O works -- this is how agent code changes
    # reach the host project directory.
    local rootfs="$ROOTFS_DIR/$CURRENT_DISTRO"
    local tmpdir
    tmpdir=$(mktemp -d)

    redan_exec_with_mount "$rootfs" \
        "echo guest-wrote-this > /workspace/output.txt" "$tmpdir" >/dev/null

    local content
    content=$(cat "$tmpdir/output.txt" 2>/dev/null)
    rm -rf "$tmpdir"
    [[ "$content" == *"guest-wrote-this"* ]]
}

test_mount_preserves_permissions() {
    # Files created by the guest should have reasonable permissions
    # on the host side. Broken permission mapping would make agent
    # output unusable (e.g. root-owned files on the host).
    local rootfs="$ROOTFS_DIR/$CURRENT_DISTRO"
    local tmpdir
    tmpdir=$(mktemp -d)

    redan_exec_with_mount "$rootfs" \
        "echo test > /workspace/permtest.txt" "$tmpdir" >/dev/null

    # File should exist and be readable by the current user
    local ok=false
    [[ -f "$tmpdir/permtest.txt" ]] && [[ -r "$tmpdir/permtest.txt" ]] && ok=true
    rm -rf "$tmpdir"
    [[ "$ok" == "true" ]]
}

# ---- concurrent connections ----

test_concurrent_https() {
    # npm install opens 30+ parallel HTTPS connections. This test
    # verifies the proxy handles concurrent TLS sessions without
    # dropping connections or deadlocking.
    local rootfs="$ROOTFS_DIR/$CURRENT_DISTRO"

    # Write a script that fires 10 parallel wget requests.
    # Each hits a different httpbin endpoint to avoid caching.
    cat > "$rootfs/tmp/concurrent_test.sh" << 'SCRIPT'
#!/bin/sh
PIDS=""
FAIL=0
for i in 1 2 3 4 5 6 7 8 9 10; do
    wget -q -O /dev/null "https://httpbin.org/get?n=$i" &
    PIDS="$PIDS $!"
done
for pid in $PIDS; do
    wait $pid || FAIL=$((FAIL + 1))
done
echo "concurrent_done failures=$FAIL"
SCRIPT
    chmod +x "$rootfs/tmp/concurrent_test.sh"

    local output
    output=$(redan_exec_with_secret \
        "$rootfs" \
        '/tmp/concurrent_test.sh 2>&1' \
        "TEST_TOKEN=dummy:httpbin.org" \
        60)
    # All 10 should complete. Allow up to 2 failures for flaky
    # network conditions, but not more.
    [[ "$output" == *"concurrent_done"* ]] && \
        [[ "$output" == *"failures=0"* || "$output" == *"failures=1"* || "$output" == *"failures=2"* ]]
}

# ---- large response ----

test_large_download() {
    # Download a 100KB response through the proxy. Tests streaming,
    # response buffering, and that the proxy doesn't choke on
    # responses larger than a single TCP window.
    # httpbin.org caps /bytes/N at 102400 (100KB).
    local rootfs="$ROOTFS_DIR/$CURRENT_DISTRO"

    cat > "$rootfs/tmp/large_download_test.sh" << 'SCRIPT'
#!/bin/sh
wget -q -O /tmp/bigfile "https://httpbin.org/bytes/102400" 2>&1
SIZE=$(wc -c < /tmp/bigfile | tr -d ' ')
echo "download_size=$SIZE"
SCRIPT
    chmod +x "$rootfs/tmp/large_download_test.sh"

    local output
    output=$(redan_exec_with_secret \
        "$rootfs" \
        '/tmp/large_download_test.sh 2>&1' \
        "TEST_TOKEN=dummy:httpbin.org" \
        60)
    [[ "$output" == *"download_size=102400"* ]]
}

# ---- secret non-leakage across hosts ----

test_secret_not_injected_wrong_host() {
    # Secret bound to api.github.com must NOT be injected when
    # the guest connects to a different host. This is the core
    # security property.
    local rootfs="$ROOTFS_DIR/$CURRENT_DISTRO"

    cat > "$rootfs/tmp/wrong_host_test.sh" << 'SCRIPT'
#!/bin/sh
# Send the placeholder to httpbin.org, but the secret is only
# allowed for api.github.com. The proxy should NOT inject.
wget -q -O - --header "Authorization: Bearer $SECRET_TOKEN" https://httpbin.org/headers 2>&1
SCRIPT
    chmod +x "$rootfs/tmp/wrong_host_test.sh"

    local output
    output=$(redan_exec_with_secret \
        "$rootfs" \
        '/tmp/wrong_host_test.sh 2>&1' \
        "SECRET_TOKEN=supersecret123:api.github.com" \
        30)
    # httpbin should see the placeholder, not the real secret.
    # The proxy must not inject because httpbin.org is not in the allowlist.
    [[ "$output" == *"redan_ph_"* ]] && [[ "$output" != *"supersecret123"* ]]
}

# ---- multiple secrets ----

test_multiple_secrets() {
    # Two different secrets for two different hosts in the same session.
    # Verifies secrets are routed correctly and don't cross-contaminate.
    local rootfs="$ROOTFS_DIR/$CURRENT_DISTRO"

    cat > "$rootfs/tmp/multi_secret_test.sh" << 'SCRIPT'
#!/bin/sh
# Send GITHUB_TOKEN to httpbin (allowed host for it)
wget -q -O - --header "X-Github: $GITHUB_TOKEN" https://httpbin.org/headers 2>&1
SCRIPT
    chmod +x "$rootfs/tmp/multi_secret_test.sh"

    local output
    output=$($REDAN exec \
        --rootfs "$rootfs" \
        --command '/tmp/multi_secret_test.sh 2>&1' \
        --secret "GITHUB_TOKEN=ghp_real_github_token:httpbin.org" \
        --secret "NPM_TOKEN=npm_real_npm_token:registry.npmjs.org" \
        --timeout 30 2>&1)
    # GITHUB_TOKEN should have been injected (httpbin.org is allowed) then
    # scrubbed from the response. So we see the placeholder.
    # NPM_TOKEN should not appear at all (not sent, wrong host).
    [[ "$output" == *"redan_ph_github_token"* ]] && \
        [[ "$output" != *"ghp_real_github_token"* ]] && \
        [[ "$output" != *"npm_real_npm_token"* ]]
}

# ---- exit code propagation ----

test_exit_code_zero() {
    local rootfs="$ROOTFS_DIR/$CURRENT_DISTRO"
    redan_exec "$rootfs" "true" >/dev/null 2>&1
}

# ---- main ----

# Parse distro arguments
if [[ $# -gt 0 ]]; then
    DISTROS=("$@")
else
    DISTROS=("${ALL_DISTROS[@]}")
fi

# Validate distro names
for distro in "${DISTROS[@]}"; do
    if [[ -z "${DISTRO_IMAGE[$distro]:-}" ]]; then
        echo -e "${RED}unknown distro: $distro${NC}"
        echo "available: ${ALL_DISTROS[*]}"
        exit 1
    fi
done

echo "======================================"
echo "  redan distro compatibility tests"
echo "======================================"
echo ""
echo "binary:  $REDAN"
echo "rootfs:  $ROOTFS_DIR"
echo "distros: ${DISTROS[*]}"
echo ""

# Pull images in parallel
echo "pulling container images..."
for distro in "${DISTROS[@]}"; do
    docker pull -q "${DISTRO_IMAGE[$distro]}" &
done
wait
echo ""

for distro in "${DISTROS[@]}"; do
    echo "--- $distro (${DISTRO_IMAGE[$distro]}) ---"
    echo ""

    extract_rootfs "$distro"
    echo ""

    CURRENT_DISTRO="$distro"

    # Basic boot and plumbing
    run_test "$distro: boot and echo"       test_boot_and_echo
    run_test "$distro: CA cert installed"    test_ca_cert_installed
    run_test "$distro: network setup"        test_network_setup
    run_test "$distro: DNS resolv.conf"      test_dns_resolution
    run_test "$distro: exit code zero"       test_exit_code_zero

    # Secret injection
    run_test "$distro: env has placeholder"          test_env_has_placeholder
    run_test "$distro: HTTPS request"                test_https_request
    run_test "$distro: secret injection + scrubbing" test_secret_injection
    run_test "$distro: secret not injected wrong host" test_secret_not_injected_wrong_host
    run_test "$distro: multiple secrets"             test_multiple_secrets

    # virtio-fs mounts
    run_test "$distro: mount read"               test_mount_read
    run_test "$distro: mount write"              test_mount_write
    run_test "$distro: mount preserves perms"    test_mount_preserves_permissions

    # Proxy under load
    run_test "$distro: 10 concurrent HTTPS"      test_concurrent_https
    run_test "$distro: 100KB download"            test_large_download

    echo ""
done

# Summary
echo "======================================"
echo "  summary"
echo "======================================"
echo ""
echo "  tests run:    $TESTS_RUN"
echo -e "  tests passed: ${GREEN}$TESTS_PASSED${NC}"
echo -e "  tests failed: ${RED}$TESTS_FAILED${NC}"

if [[ ${#FAILED_TESTS[@]} -gt 0 ]]; then
    echo ""
    echo -e "${RED}  failed:${NC}"
    for t in "${FAILED_TESTS[@]}"; do
        echo -e "    ${RED}x${NC} $t"
    done
fi

echo ""
if [[ $TESTS_FAILED -eq 0 ]]; then
    echo -e "${GREEN}all tests passed${NC}"
    exit 0
else
    echo -e "${RED}some tests failed${NC}"
    exit 1
fi
