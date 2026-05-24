# use-security

Feature-gated facade crate for `RustUse` security primitives.

## Experimental

`use-security` is experimental while the `use-security` workspace remains below `0.3.0`. Expect small API adjustments during the first release wave.

## Example

```toml
[dependencies]
use-security = { version = "0.0.1", default-features = false, features = ["cve", "cwe", "cvss"] }
```

```rust,ignore
use use_security::{CveId, CweId, CvssScore, severity_from_score};

let cve: CveId = "CVE-2024-12345".parse()?;
let cwe: CweId = "CWE-79".parse()?;
let score = CvssScore::new(9.8)?;

assert_eq!(cve.as_str(), "CVE-2024-12345");
assert_eq!(cwe.to_string(), "CWE-79");
assert_eq!(severity_from_score(score).as_str(), "critical");
# Ok::<(), Box<dyn std::error::Error>>(())
```

## Feature Flags

- `cve`: re-export `use-cve`
- `cwe`: re-export `use-cwe`
- `cvss`: re-export `use-cvss`
- `owasp`: re-export `use-owasp`
- `risk`: re-export `use-security-risk`
- `threat`: re-export `use-threat`
- `finding`: re-export `use-security-finding`
- `authn`: re-export `use-authn`
- `authz`: re-export `use-authz`
- `secret`: re-export `use-secret`
- `crypto`: re-export `use-crypto`
- `security-header`: re-export `use-security-header`
- `sbom`: re-export `use-sbom`
- `full`: enable all child crates

## Scope

- Facade imports and namespace aliases for focused `use-security` child crates.
- Small primitive metadata APIs for security-related identifiers, labels, and validation helpers.

## Non-goals

- Implementation logic beyond re-exports.
- Security scanning, authentication, authorization, encryption, SBOM generation, or policy enforcement.

## License

Licensed under either of the following, at your option:

- Apache License, Version 2.0
- MIT license
