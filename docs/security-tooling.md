# Security Tooling for redan

Rust equivalents of Python's `ruff` (linter/formatter) and `bandit` (security linter).

## Quick Reference

| Python | Rust | Purpose | Local Command |
|--------|------|---------|---------------|
| ruff check | clippy | Linting | `mise run lint` |
| ruff format | rustfmt | Formatting | `mise run format` |
| bandit | cargo-audit | Dependency vulnerabilities | `cargo audit` |
| bandit | cargo-deny | Policy enforcement | `cargo deny check advisories` |
| safety | cargo-geiger | Unsafe code detection | `cargo geiger` |

## Tools Overview

### cargo-audit (bandit equivalent - dependency security)

Checks dependencies against the [RustSec Advisory Database](https://rustsec.org/).

```bash
# Install
cargo install cargo-audit

# Run audit
cargo audit

# Update database and audit
cargo audit --update
```

**CI**: Runs on every PR, push to main, and daily via `security-audit.yml`.

### cargo-deny (bandit equivalent - policy enforcement)

Comprehensive policy enforcement for dependencies:
- **Advisories**: Known vulnerabilities (like cargo-audit but with policy controls)
- **Licenses**: License compliance checking
- **Bans**: Block specific crates/versions
- **Bans (duplicates)**: Detect duplicate transitive dependencies

```bash
# Install
cargo install cargo-deny

# Check advisories (security)
cargo deny check advisories

# Check licenses
cargo deny check licenses

# Check banned crates
cargo deny check bans

# Check everything
cargo deny check
```

**Configuration**: `deny.toml` - controls allowed licenses, banned crates, etc.

**CI**: Runs on every PR and daily.

### cargo-geiger (unsafe code detection)

Finds usage of `unsafe` in your code and dependencies.

```bash
# Install
cargo install cargo-geiger

# Detect unsafe in your code + dependencies
cargo geiger --all-features --all-targets

# Unsafe in your code only
cargo geiger --all-features --all-targets --include-tests
```

**CI**: Runs weekly to track unsafe usage.

**Output**: Shows count of `unsafe` blocks per crate. For redan (security-critical), we aim to minimize unsafe code and justify every usage.

### cargo-outdated (dependency freshness)

Check for outdated dependencies.

```bash
# Install
cargo install cargo-outdated

# List outdated dependencies
cargo outdated

# Only root dependencies (major version bumps)
cargo outdated --root-deps-only
```

**CI**: Runs weekly to notify of available updates.

### Miri (undefined behavior detection)

Detects undefined behavior in `unsafe` Rust code.

```bash
# Install (requires nightly)
rustup component add miri

# Run tests under Miri
cargo miri test --lib

# Run specific test
cargo miri test test_name
```

**CI**: Runs weekly on the test suite.

**Note**: Some code (especially with FFI/libkrun) may not be Miri-compatible. This is expected for VM-related code.

## Security-Focused Clippy

Comprehensive clippy with security-focused lints:

```bash
mise run lint
```

The lint configuration includes:
- Standard warnings (`-D warnings`)
- `clippy::pedantic`: Additional correctness checks
- `clippy::nursery`: Newer lints that may have false positives
- `clippy::unwrap_used`: Flag all `.unwrap()` calls
- `clippy::expect_used`: Flag all `.expect()` calls
- `clippy::panic`: Flag `panic!()` usage
- `clippy::unwrap_in_result`: Flag unwrap in functions returning Result
- `clippy::fallible_impl_from`: Check From impls for panic safety
- `clippy::string_slice`: Flag string slicing that may panic

## Local Development

```bash
# Fast gate (format + lint + test)
mise run check

# Security audit (all checks)
mise run audit

# Just dependency vulnerabilities
mise run audit-deps

# Just unsafe code check
mise run audit-unsafe

# License compliance
mise run audit-licenses
```

## CI Integration

All tools run in `.github/workflows/security-audit.yml`:

| Job | Frequency | Purpose |
|-----|-----------|---------|
| cargo-audit | Push/PR/Daily | Known vulnerabilities |
| cargo-deny | Push/PR/Daily | Policy enforcement |
| cargo-geiger | Push/PR | Unsafe code tracking |
| cargo-outdated | Daily | Dependency freshness |
| miri | Weekly | Undefined behavior |
| clippy | Push/PR/Daily | Comprehensive linting with security focus |

## Response to Findings

### cargo-audit finds vulnerability

1. Check if vulnerability affects your usage pattern
2. Update dependency if possible
3. If no update available, evaluate workarounds
4. Document in `deny.toml` ignore list with justification if temporarily accepted

### cargo-geiger finds unsafe code

Expected in redan due to libkrun FFI bindings. For each unsafe block:

1. Document why unsafe is necessary in comment
2. Add `// SAFETY:` explanation
3. Ensure preconditions are checked
4. Consider if safe wrapper is possible

Example:
```rust
// SAFETY: krun_start_enter blocks until VM exits. We ensure VM is
// properly initialized and all preconditions (rootfs, network) are met.
unsafe { krun_start_enter(ctx) };
```

### cargo-deny license issue

1. Review the dependency's license
2. If acceptable, add to `deny.toml` `licenses.allow`
3. If problematic, find alternative crate or request license change upstream

## Comparison with Python Tooling

| Concern | Python | Rust |
|---------|--------|------|
| Linting | ruff, flake8, pylint | clippy |
| Formatting | ruff format, black | rustfmt |
| Security scanning | bandit | cargo-audit, cargo-deny |
| Dependency check | safety, pip-audit | cargo-audit, cargo-deny |
| Type checking | mypy, pyright | rustc (built-in) |
| Unsafe detection | N/A | cargo-geiger |
| Undefined behavior | N/A | Miri |

## Further Reading

- [RustSec Advisory Database](https://rustsec.org/)
- [cargo-deny book](https://embarkstudios.github.io/cargo-deny/)
- [Clippy lints](https://rust-lang.github.io/rust-clippy/master/index.html)
- [Miri documentation](https://github.com/rust-lang/miri)
