# Releasing use-security

`use-security` is experimental while the release line remains below `0.3.0`.

## Local Readiness

Run the main validation path from the repository root:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo test --workspace --no-default-features
cargo doc --workspace --all-features --no-deps
```

## First Publish Order

Publish focused crates before the facade crate:

1. `use-cve`
2. `use-cwe`
3. `use-cvss`
4. `use-owasp`
5. `use-security-risk`
6. `use-threat`
7. `use-security-finding`
8. `use-authn`
9. `use-authz`
10. `use-secret`
11. `use-crypto`
12. `use-security-header`
13. `use-sbom`
14. `use-security`

The facade dry-run can require the focused crates to be visible on crates.io because package verification resolves published dependency versions.
