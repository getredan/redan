#!/bin/bash
# Script to prepare CodeRabbit analysis for recent redan changes
# Usage: ./scripts/coderabbit-analyze.sh [commit_range] [focus_areas]

set -euo pipefail

COMMIT_RANGE="${1:-HEAD~30..HEAD}"
FOCUS_AREAS="${2:-security,safety}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

OUTPUT_FILE="$PROJECT_ROOT/coderabbit-analysis-$(date +%Y%m%d-%H%M%S).md"

cd "$PROJECT_ROOT"

cat > "$OUTPUT_FILE" << 'HEADER'
# CodeRabbit Analysis Request: Recent Changes Review

## Project Context
**redan** - Secure, local-first AI agent execution environment
- Language: Rust
- Architecture: Rust + libkrun microVMs + network-layer secret injection
- Security Model: Zero-trust guest execution with TLS MITM for secret injection

## Recent Development Themes (Past 4 Weeks)
1. **Session Management** - Added session lifecycle, listing, and management
2. **Devcontainer Support** - Claude Code integration, template generation
3. **Configuration System** - redan.toml support with minijinja templates
4. **Security Hardening** - Oracle review rounds 4-9, secret redaction
5. **Network Policy** - Default-deny networking, host allowlists
6. **Audit Logging** - Structured event logging for compliance

HEADER

echo "## Analysis Scope" >> "$OUTPUT_FILE"
echo "" >> "$OUTPUT_FILE"
echo "- **Commit Range:** \`$COMMIT_RANGE\`" >> "$OUTPUT_FILE"
echo "- **Focus Areas:** $FOCUS_AREAS" >> "$OUTPUT_FILE"
echo "" >> "$OUTPUT_FILE"

echo "## Commits in Range" >> "$OUTPUT_FILE"
echo "" >> "$OUTPUT_FILE"
echo "\`\`\`" >> "$OUTPUT_FILE"
git log --oneline "$COMMIT_RANGE" >> "$OUTPUT_FILE"
echo "\`\`\`" >> "$OUTPUT_FILE"
echo "" >> "$OUTPUT_FILE"

echo "## Changed Files" >> "$OUTPUT_FILE"
echo "" >> "$OUTPUT_FILE"
echo "\`\`\`" >> "$OUTPUT_FILE"
git diff --stat "$COMMIT_RANGE" >> "$OUTPUT_FILE"
echo "\`\`\`" >> "$OUTPUT_FILE"
echo "" >> "$OUTPUT_FILE"

# Module-specific analysis sections
declare -A MODULES=(
    ["src/proxy.rs"]="TLS MITM Proxy - Connection state machine, secret injection, host filtering"
    ["src/secret.rs"]="Secret Handling - Injection, scrubbing, provider interface"
    ["src/ca.rs"]="Certificate Authority - Ephemeral CA, leaf cert generation"
    ["src/vm.rs"]="VM Lifecycle - libkrun integration, resource limits"
    ["src/session.rs"]="Session Management - Lifecycle, metadata, path handling"
    ["src/config.rs"]="Configuration - redan.toml parsing, validation"
    ["src/main.rs"]="CLI - Command interface, argument handling"
    ["src/image.rs"]="Image Management - Docker integration, devcontainer support"
    ["src/templates.rs"]="Template Engine - Minijinja rendering"
)

echo "## Module-by-Module Analysis" >> "$OUTPUT_FILE"
echo "" >> "$OUTPUT_FILE"

for file in "${!MODULES[@]}"; do
    description="${MODULES[$file]}"

    # Check if file was modified in the range
    if git diff --name-only "$COMMIT_RANGE" | grep -q "^$file$"; then
        echo "### $file" >> "$OUTPUT_FILE"
        echo "*$description*" >> "$OUTPUT_FILE"
        echo "" >> "$OUTPUT_FILE"

        # Show commits affecting this file
        echo "**Relevant commits:**" >> "$OUTPUT_FILE"
        git log --oneline --format='- %h: %s' "$COMMIT_RANGE" -- "$file" >> "$OUTPUT_FILE" 2>/dev/null || echo "- (no commits found)" >> "$OUTPUT_FILE"
        echo "" >> "$OUTPUT_FILE"

        # Show diff stat
        echo "**Changes:**" >> "$OUTPUT_FILE"
        echo "\`\`\`" >> "$OUTPUT_FILE"
        git diff --stat "$COMMIT_RANGE" -- "$file" >> "$OUTPUT_FILE" 2>/dev/null || echo "(unable to get stats)" >> "$OUTPUT_FILE"
        echo "\`\`\`" >> "$OUTPUT_FILE"
        echo "" >> "$OUTPUT_FILE"
    fi
done

cat >> "$OUTPUT_FILE" << 'FOOTER'
## Security-Focused Questions for CodeRabbit

### Critical Security Boundaries
1. **Proxy Module (src/proxy.rs)**
   - [ ] Is the TLS MITM state machine free from race conditions?
   - [ ] Does host allowlist enforcement happen before any upstream connection?
   - [ ] Are secrets properly scrubbed from all response paths (headers, body, errors)?
   - [ ] Is there any request smuggling vulnerability?
   - [ ] Are chunked transfer encodings handled safely?

2. **Secret Handling (src/secret.rs)**
   - [ ] Are secrets ever exposed in error messages?
   - [ ] Is the scrubbing regex safe from ReDoS attacks?
   - [ ] Are binary secrets handled correctly without UTF-8 assumptions?
   - [ ] Is secret redaction comprehensive across all output paths?

3. **Certificate Authority (src/ca.rs)**
   - [ ] Is CA private key material properly protected in memory?
   - [ ] Are leaf certificates generated with appropriate constraints?
   - [ ] Is the certificate validation logic complete?

4. **VM/Isolation (src/vm.rs)**
   - [ ] Are resource limits (rlimits) properly enforced?
   - [ ] Is the virtio-net socket handling race-condition-free?
   - [ ] Is guest isolation guaranteed (no host file system access)?

5. **Session Management (src/session.rs)**
   - [ ] Is session path handling safe from directory traversal attacks?
   - [ ] Are session metadata files properly validated before use?
   - [ ] Is session cleanup complete (no resource leaks)?

### Code Quality & Safety
1. **Unsafe Code**
   - [ ] Any new `unsafe` blocks must have justification comments
   - [ ] Are FFI boundaries (libkrun) properly encapsulated?

2. **Error Handling**
   - [ ] Are `unwrap()` and `expect()` limited to test code and truly invariant cases?
   - [ ] Are errors properly propagated with context?
   - [ ] Do error messages leak sensitive information?

3. **Concurrency**
   - [ ] Is `Arc<Mutex<T>>` usage correct (no potential for deadlocks)?
   - [ ] Are there any blocking operations in async contexts?
   - [ ] Is lock ordering consistent to prevent deadlocks?

4. **Input Validation**
   - [ ] Is all external input validated (config files, CLI args, network data)?
   - [ ] Are there any injection vulnerabilities in template rendering?

### Testing
1. **Security Testing**
   - [ ] Are security boundaries tested with adversarial inputs?
   - [ ] Do tests cover error paths, not just happy paths?
   - [ ] Are race conditions in concurrent code tested?

2. **Integration Testing**
   - [ ] Do integration tests properly clean up resources?
   - [ ] Are KVM-dependent tests properly marked with `#[ignore]`?

## Please Provide

1. **High-level Summary**: Overall security posture of the recent changes
2. **Module-by-Module Findings**: Specific issues or praise for each changed module
3. **Pattern Recommendations**: Code patterns that should be encouraged or avoided
4. **Risk Assessment**: Overall risk level and any immediate concerns
5. **Testing Recommendations**: Gaps in test coverage that should be addressed

---
*Generated for redan security review*
FOOTER

echo "Analysis file created: $OUTPUT_FILE"
echo ""
echo "To use with CodeRabbit:"
echo "1. Review the generated file"
echo "2. Use it as context in a PR description or CodeRabbit chat"
echo "3. Or trigger the GitHub workflow: .github/workflows/coderabbit-analyze.yml"
