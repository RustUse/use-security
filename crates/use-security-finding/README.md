# use-security-finding

Security finding, scanner result, and remediation metadata primitives for `RustUse`.

## Experimental

`use-security-finding` is experimental while the `use-security` workspace remains below `0.3.0`. Expect small API adjustments during the first release wave.

## Example

```rust
use use_security_finding::{FindingKind, FindingSeverity, SecurityFinding, SecurityFindingId};

let finding = SecurityFinding::new(
    SecurityFindingId::new("F-1")?,
    FindingKind::Vulnerability,
    FindingSeverity::High,
);

assert_eq!(finding.kind(), FindingKind::Vulnerability);
# Ok::<(), use_security_finding::SecurityFindingError>(())
```

## Scope

- Finding IDs, source labels, kinds, statuses, confidence, severity, locations, evidence, references, and remediation statuses.
- Metadata models that can represent output from many kinds of tools without depending on a specific scanner.

## Non-goals

- Running scanners.
- Parsing scanner-specific report formats.
- Contacting advisory databases or package registries.

## License

Licensed under either of the following, at your option:

- Apache License, Version 2.0
- MIT license
