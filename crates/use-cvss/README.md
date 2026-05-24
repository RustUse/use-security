# use-cvss

CVSS severity, vector, and score metadata primitives for `RustUse`.

## Experimental

`use-cvss` is experimental while the `use-security` workspace remains below `0.3.0`. Expect small API adjustments during the first release wave.

## Example

```rust
use use_cvss::{CvssScore, CvssSeverity, severity_from_score};

let score = CvssScore::new(9.8)?;

assert_eq!(score.value(), 9.8);
assert_eq!(severity_from_score(score), CvssSeverity::Critical);
# Ok::<(), use_cvss::CvssScoreError>(())
```

## Scope

- CVSS version, severity, metric, and vector metadata.
- Score range validation for values from `0.0` through `10.0`.
- Lightweight severity classification from a numeric score.

## Non-goals

- Full CVSS mathematical scoring.
- Vector metric normalization beyond non-empty validation.
- Vulnerability scanning or advisory lookup.

## License

Licensed under either of the following, at your option:

- Apache License, Version 2.0
- MIT license
