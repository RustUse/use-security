# use-authn

Authentication primitive metadata for `RustUse`.

## Experimental

`use-authn` is experimental while the `use-security` workspace remains below `0.3.0`. Expect small API adjustments during the first release wave.

## Example

```rust
use use_authn::{AuthenticationFactor, AuthenticationMethod, MfaStatus};

assert_eq!(AuthenticationMethod::Passkey.as_str(), "passkey");
assert_eq!(AuthenticationFactor::Possession.as_str(), "possession");
assert_eq!(MfaStatus::Enforced.to_string(), "enforced");
```

## Scope

- Authentication methods, factors, schemes, credential kinds, session kinds, token-binding labels, password-policy levels, and MFA status labels.
- Local metadata for tools, documentation, and application glue code.

## Non-goals

- Authenticating users.
- Password hashing.
- Token generation, validation, or storage.
- Identity provider or session server behavior.

## License

Licensed under either of the following, at your option:

- Apache License, Version 2.0
- MIT license
