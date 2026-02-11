#!/bin/bash
#
# Benchmark: redan boot-to-proxy-ready time.
#
# Measures time from `redan exec` to the first successful HTTPS
# request through the proxy. Requires KVM, libkrun, and an image
# with curl and ca-certificates.
#
# Usage:
#   ./tests/bench_boot.sh [iterations] [image]
#
# Example:
#   ./tests/bench_boot.sh 5 claude-code

set -euo pipefail

ITERATIONS="${1:-5}"
IMAGE="${2:-}"
REDAN="${REDAN:-./target/release/redan}"

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

# Find redan binary
if [[ ! -x "$REDAN" ]]; then
    REDAN="./target/debug/redan"
fi
if [[ ! -x "$REDAN" ]]; then
    echo -e "${RED}redan binary not found. Run: cargo build --release${NC}"
    exit 1
fi

# Find an image if not specified
if [[ -z "$IMAGE" ]]; then
    IMAGE=$($REDAN image list 2>/dev/null | awk '{print $1}' | head -1)
fi
if [[ -z "$IMAGE" ]]; then
    echo -e "${RED}no image found. Create one: redan image create bench --packages 'curl ca-certificates'${NC}"
    exit 1
fi

echo "======================================"
echo "  redan boot-to-proxy benchmark"
echo "======================================"
echo ""
echo "binary:     $REDAN"
echo "image:      $IMAGE"
echo "iterations: $ITERATIONS"
echo ""

# A dummy secret so the proxy actually runs in MITM mode.
# The value doesn't matter -- we just need the proxy to start.
SECRET="BENCH_TOKEN=bench_dummy_value:httpbin.org"

# Guest command: wait for network, then curl through the proxy.
# The proxy terminates TLS so this exercises the full chain:
# guest -> smoltcp -> TLS MITM -> upstream -> response -> scrub -> guest
GUEST_CMD="curl -sf -o /dev/null -w '%{http_code}' https://httpbin.org/get"

declare -a TIMES

for i in $(seq 1 "$ITERATIONS"); do
    # Time the full cycle: redan exec boots the VM, sets up networking,
    # starts the proxy, guest runs curl, proxy shuts down.
    START=$(date +%s%N)

    OUTPUT=$($REDAN exec \
        --image "$IMAGE" \
        --command "$GUEST_CMD" \
        --secret "$SECRET" \
        --timeout 30 2>&1) || true

    END=$(date +%s%N)
    DURATION_MS=$(( (END - START) / 1000000 ))
    TIMES+=("$DURATION_MS")

    # Check if the request succeeded (200 in output)
    if echo "$OUTPUT" | grep -q "200"; then
        echo -e "  run $i: ${GREEN}${DURATION_MS}ms${NC} (ok)"
    else
        echo -e "  run $i: ${RED}${DURATION_MS}ms${NC} (failed)"
        echo "    output: $OUTPUT"
    fi
done

# Stats
echo ""
echo "======================================"
echo "  results"
echo "======================================"

TIMES_CSV=$(IFS=,; echo "${TIMES[*]}")

python3 -c "
times = [$TIMES_CSV]
n = len(times)
avg = sum(times) / n
mn = min(times)
mx = max(times)
variance = sum((t - avg) ** 2 for t in times) / n
stddev = variance ** 0.5

print(f'  runs:    {n}')
print(f'  min:     {mn}ms')
print(f'  max:     {mx}ms')
print(f'  avg:     {avg:.0f}ms')
print(f'  stddev:  {stddev:.0f}ms')
"

echo ""
echo -e "${GREEN}done${NC}"
