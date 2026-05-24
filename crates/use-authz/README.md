# use-authz

Authorization, permissions, roles, scopes, claims, and access-control primitives for `RustUse`.

## Experimental

`use-authz` is experimental while the `use-security` workspace remains below `0.3.0`. Expect small API adjustments during the first release wave.

## Example

```rust
use use_authz::{AccessDecision, PermissionName, PolicyEffect};

let permission = PermissionName::new("document:read")?;

assert_eq!(permission.as_str(), "document:read");
assert_eq!(AccessDecision::Allow.as_str(), "allow");
assert_eq!(PolicyEffect::Deny.to_string(), "deny");
# Ok::<(), use_authz::AuthzNameError>(())
```

## Scope

- Authorization model, decision, and policy-effect labels.
- Validated permission, role, scope, claim, subject, resource, and action names.
- ASCII-safe metadata primitives for local application code.

## Non-goals

- Policy engines.
- Real access decisions.
- Role storage, identity providers, or authorization servers.

## License

Licensed under either of the following, at your option:

- Apache License, Version 2.0
- MIT license
