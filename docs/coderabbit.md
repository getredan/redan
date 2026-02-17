# CodeRabbit Integration for redan

Systematic AI-powered code review for a security-critical Rust project.

## Overview

CodeRabbit provides automated code review using AI. For redan (a security-critical AI agent execution environment), we use it to:

1. **Systematically review recent changes** - Security-focused analysis of commits
2. **Full codebase security audits** - Periodic comprehensive review
3. **PR-style reviews** - Automatic review on PR-like contexts

## Setup

### Prerequisites

1. **Install the CodeRabbit GitHub App** (if not already done):
   - Go to https://github.com/apps/coderabbitai
   - Install for the `getredan/redan` repository
   - Grant read access to code and pull requests

2. **Configuration Files** (already created):
   - `.coderabbit.yaml` - Main configuration with security-focused rules
   - `.github/workflows/coderabbit-analyze.yml` - GitHub Actions workflow
   - `scripts/coderabbit-analyze.sh` - Local analysis generator

## Usage

### Option 1: Local Analysis Generation (Recommended for Quick Review)

Generate a structured analysis prompt for CodeRabbit:

```bash
# Analyze last 30 commits (default)
./scripts/coderabbit-analyze.sh

# Analyze specific commit range
./scripts/coderabbit-analyze.sh HEAD~20..HEAD

# Analyze with specific focus
./scripts/coderabbit-analyze.sh HEAD~30..HEAD "security,performance"
```

This creates a timestamped markdown file (`coderabbit-analysis-YYYYMMDD-HHMMSS.md`) containing:
- Commit summary
- Module-by-module breakdown
- Security-focused questions
- Risk assessment framework

Use this file as context when:
- Commenting on a PR (paste into PR description)
- Using CodeRabbit chat interface
- Manual review with the questions as a checklist

### Option 2: GitHub Actions Workflow (For PR-Style Review)

Trigger via GitHub Actions to get CodeRabbit's full PR review experience:

1. Go to **Actions** → **CodeRabbit Analysis** → **Run workflow**

2. Choose analysis type:
   - `recent_changes` - Generate summary for manual review
   - `full_codebase` - Comprehensive review of entire codebase
   - `security_audit` - Security-focused analysis
   - `pr_style_review` - Creates a PR to trigger automatic CodeRabbit review

3. For `pr_style_review`:
   - Workflow creates a temporary PR
   - CodeRabbit automatically reviews it
   - Review the findings, then close the PR without merging

### Option 3: Direct CodeRabbit Chat

In any PR or commit view on GitHub where CodeRabbit is active:

```
@coderabbitai Please analyze the recent changes with focus on:
1. Secret handling safety
2. TLS implementation correctness
3. Host allowlist enforcement
4. Session path traversal protection
```

## Configuration Details

### `.coderabbit.yaml`

Security-focused configuration with:

- **Path-specific instructions** for each critical module
- **Tool integration**: clippy, rustfmt, gitleaks (secrets detection), semgrep
- **Review scope**: request_changes_workflow enabled for security issues

### Module-Specific Review Focus

| Module | Security Focus |
|--------|---------------|
| `src/proxy.rs` | TLS MITM correctness, host filtering, request smuggling, secret scrubbing |
| `src/secret.rs` | Secret redaction, regex safety, binary handling |
| `src/ca.rs` | CA key protection, cert constraints, validation |
| `src/vm.rs` | Resource limits, virtio-net safety, guest isolation |
| `src/session.rs` | Path traversal, metadata validation, cleanup |
| `tests/` | Security boundary testing, adversarial coverage |

## Analysis Checklist

When reviewing changes, CodeRabbit is configured to check:

### Security
- [ ] No secrets in logs/errors
- [ ] Input validation on all external data
- [ ] Proper error handling (no unwrap in prod)
- [ ] TLS/CA implementation correctness
- [ ] Host allowlist enforcement before upstream connection
- [ ] No request smuggling vulnerabilities

### Safety
- [ ] No unsafe blocks without justification
- [ ] Proper Arc/Mutex usage
- [ ] Resource limits enforced
- [ ] No panic paths in request handling
- [ ] Race-condition-free state machines

### API/UX
- [ ] CLI interface consistency
- [ ] Config file format stability
- [ ] Error messages are actionable
- [ ] Documentation matches code

### Testing
- [ ] Security boundaries tested with adversarial inputs
- [ ] Error handling tested (not just happy paths)
- [ ] No mocks for security-critical components
- [ ] Proper resource cleanup in tests

## Recent Changes Worth Analyzing (Past 4 Weeks)

```bash
# Generate analysis for the major recent development
./scripts/coderabbit-analyze.sh "9b1e336..HEAD" "security,safety"
```

Key themes to highlight to CodeRabbit:
1. **Session management** (`src/session.rs`) - Path traversal protection
2. **Devcontainer support** (`src/image.rs`) - Docker integration safety
3. **Template generation** (`src/templates.rs`) - Injection prevention
4. **Config system** (`src/config.rs`) - Input validation
5. **Security hardening** - Multiple Oracle review round fixes

## Interpreting Results

### High-Priority Findings
CodeRabbit will request changes (not just comment) for:
- Potential secret exposure
- Unsafe blocks without justification
- Unwrap/expect in production paths
- Missing input validation
- Race conditions

### Medium-Priority Findings
Comments (not blocking) for:
- Style inconsistencies
- Documentation gaps
- Test coverage suggestions
- Performance considerations

## Troubleshooting

### CodeRabbit not reviewing
1. Check the app is installed for this repo
2. Ensure `.coderabbit.yaml` is valid YAML
3. Try `@coderabbitai review` in a PR comment

### Workflow failures
1. Check `GITHUB_TOKEN` has proper permissions
2. For `pr_style_review`, ensure branch protection allows PR creation

### Analysis seems shallow
- Use the local script to generate detailed context
- Ask specific questions in CodeRabbit chat
- Specify focus areas in the workflow inputs

## Best Practices

1. **Run analysis before major releases** - Use full_codebase or security_audit
2. **Review PRs with context** - Include generated analysis in PR description
3. **Track patterns** - CodeRabbit learns from local patterns over time
4. **Don't ignore security findings** - All security warnings should be addressed

## Integration with Development Workflow

```
Feature Branch
     |
     v
Code Review (CodeRabbit + Human)
     |
     v
Security Audit (if security-critical changes)
     |
     v
Merge to main
```

For security-critical projects like redan:
- **Every PR** gets CodeRabbit review automatically
- **Major features** get additional `security_audit` workflow run
- **Before releases** run `full_codebase` review

---

For questions or issues with CodeRabbit integration, refer to:
- [CodeRabbit Documentation](https://docs.coderabbit.ai)
- Configuration: `.coderabbit.yaml`
- Workflow: `.github/workflows/coderabbit-analyze.yml`
