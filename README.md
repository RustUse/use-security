# RustUse use-security

`use-security` is a RustUse workspace for small, focused Rust 2024 utility crates around security identifiers, taxonomy labels, metadata, and primitive validation helpers.

## Experimental

Every crate in this workspace is experimental while the release line remains below `0.3.0`. Expect incremental API cleanup as the first wave settles.

## Crate List

- `use-security`: feature-gated umbrella crate for the full workspace
- `use-cve`: CVE identifier and vulnerability metadata primitives
- `use-cwe`: CWE weakness identifier and category primitives
- `use-cvss`: CVSS severity, vector, and score metadata primitives
- `use-owasp`: OWASP category and application-security taxonomy primitives
- `use-security-risk`: generic cybersecurity risk primitives
- `use-threat`: threat modeling and threat-category primitives
- `use-security-finding`: security finding and remediation metadata primitives
- `use-authn`: authentication metadata primitives
- `use-authz`: authorization, role, scope, claim, and permission metadata primitives
- `use-secret`: secret classification, masking, and secret-reference primitives
- `use-crypto`: cryptographic algorithm and key metadata labels
- `use-security-header`: web security header and browser-policy primitives
- `use-sbom`: software bill of materials and supply-chain metadata primitives

## Scope

- Validated identifiers and labels such as CVE IDs, CWE IDs, CVSS scores, and security header names.
- Small enums and metadata models for risk, threats, findings, authentication, authorization, secrets, cryptographic labels, and supply-chain records.
- Lightweight helpers that are transparent, dependency-light, and suitable for application glue code, docs tooling, test fixtures, and CLIs.

## Non-goals

- Security scanning, vulnerability database mirroring, advisory lookup, or registry access.
- Cryptographic operations, key generation, hashing, token generation, or certificate generation.
- Authentication servers, authorization engines, policy engines, WAFs, SIEMs, linters, compliance products, or SBOM generators.
- Complete standards implementations for CVSS, OWASP, CWE, CycloneDX, SPDX, CSP, or browser behavior.

## Example Usage

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
assert_eq!(cwe.as_str(), "CWE-79");
assert_eq!(severity_from_score(score).as_str(), "critical");
# Ok::<(), Box<dyn std::error::Error>>(())
```

## License

Licensed under either of the following, at your option:

- Apache License, Version 2.0
- MIT license
