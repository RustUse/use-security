# use-security-header

Web security header and browser-policy primitives for `RustUse`.

## Experimental

`use-security-header` is experimental while the `use-security` workspace remains below `0.3.0`. Expect small API adjustments during the first release wave.

## Example

```rust
use use_security_header::{SecurityHeaderKind, SecurityHeaderName};

let name = SecurityHeaderName::new("Content-Security-Policy")?;

assert_eq!(name.as_str(), "Content-Security-Policy");
assert_eq!(SecurityHeaderKind::StrictTransportSecurity.header_name(), "Strict-Transport-Security");
# Ok::<(), use_security_header::SecurityHeaderNameError>(())
```

## Scope

- Security header names, categories, and directive labels.
- CSP, HSTS, referrer policy, frame options, CORS, and permissions policy metadata.

## Non-goals

- HTTP server or browser behavior.
- WAF behavior.
- Complete CSP or header parsing.

## License

Licensed under either of the following, at your option:

- Apache License, Version 2.0
- MIT license
