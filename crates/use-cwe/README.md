# use-cwe

CWE weakness identifier and category primitives for `RustUse`.

## Experimental

`use-cwe` is experimental while the `use-security` workspace remains below `0.3.0`. Expect small API adjustments during the first release wave.

## Example

```rust
use use_cwe::{CWE_79_XSS, CweId, CweWeaknessKind};

let id: CweId = "CWE-79".parse()?;

assert_eq!(id, CWE_79_XSS);
assert_eq!(CweWeaknessKind::CrossSiteScripting.as_str(), "cross-site-scripting");
# Ok::<(), use_cwe::CweIdError>(())
```

## Scope

- CWE ID validation for strings such as `CWE-79` and `CWE-352`.
- Common high-value CWE constants.
- Small weakness, impact, likelihood, and taxonomy-source labels.

## Non-goals

- Mirroring the full CWE database.
- Weakness detection or static analysis.
- CWE website scraping or network lookup.

## License

Licensed under either of the following, at your option:

- Apache License, Version 2.0
- MIT license
