# use-cve

CVE identifier and vulnerability metadata primitives for `RustUse`.

## Experimental

`use-cve` is experimental while the `use-security` workspace remains below `0.3.0`. Expect small API adjustments during the first release wave.

## Example

```rust
use use_cve::{CveId, CveStatus};

let id: CveId = "CVE-2024-12345".parse()?;

assert_eq!(id.year().value(), 2024);
assert_eq!(id.sequence().as_str(), "12345");
assert_eq!(CveStatus::Published.as_str(), "published");
# Ok::<(), use_cve::CveIdError>(())
```

## Scope

- CVE ID validation for strings such as `CVE-2024-12345`.
- Small CVE status, source, reference, and record-kind labels.
- Display and parsing helpers for local metadata models.

## Non-goals

- CVE, NVD, GitHub, GitLab, or advisory database access.
- Vulnerability scanning.
- Mirroring CVE records or vulnerability feeds.

## License

Licensed under either of the following, at your option:

- Apache License, Version 2.0
- MIT license
