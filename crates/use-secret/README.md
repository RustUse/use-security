# use-secret

Secret classification, masking, and secret-reference primitives for `RustUse`.

## Experimental

`use-secret` is experimental while the `use-security` workspace remains below `0.3.0`. Expect small API adjustments during the first release wave.

## Example

```rust
use use_secret::{MaskedSecret, SecretReference, mask_keep_last};

let reference = SecretReference::new("prod/database/password")?;
let masked = MaskedSecret::new("super-secret-token");

assert_eq!(reference.as_str(), "prod/database/password");
assert_eq!(mask_keep_last("abcdef", 2), "****ef");
assert_eq!(format!("{masked:?}"), "MaskedSecret(\"<redacted>\")");
# Ok::<(), use_secret::SecretTextError>(())
```

## Scope

- Secret kind, provider, scope, sensitivity, and rotation labels.
- Secret names and references.
- Simple masking helpers and redacted secret wrappers.

## Non-goals

- Secret generation.
- Secret storage, encryption, retrieval, or synchronization.
- Secret scanning or pattern classification beyond local metadata.

## License

Licensed under either of the following, at your option:

- Apache License, Version 2.0
- MIT license
