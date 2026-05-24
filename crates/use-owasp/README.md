# use-owasp

OWASP category and application-security taxonomy primitives for `RustUse`.

## Experimental

`use-owasp` is experimental while the `use-security` workspace remains below `0.3.0`. Expect small API adjustments during the first release wave.

## Example

```rust
use use_owasp::{OwaspTop10Category, OwaspTop10Version};

let category: OwaspTop10Category = "broken-access-control".parse()?;

assert_eq!(category, OwaspTop10Category::BrokenAccessControl);
assert_eq!(OwaspTop10Version::Top10_2021.as_str(), "top-10-2021");
# Ok::<(), use_owasp::OwaspParseError>(())
```

## Scope

- Stable labels for OWASP Top 10 style categories.
- Lightweight OWASP project, risk ID, and control-area metadata.
- Display and parsing helpers for local categorization.

## Non-goals

- OWASP scraping.
- Mirroring entire OWASP standards.
- Scanner behavior or browser/runtime enforcement.

## License

Licensed under either of the following, at your option:

- Apache License, Version 2.0
- MIT license
