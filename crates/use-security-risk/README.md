# use-security-risk

Generic cybersecurity risk primitives for `RustUse`.

## Experimental

`use-security-risk` is experimental while the `use-security` workspace remains below `0.3.0`. Expect small API adjustments during the first release wave.

## Example

```rust
use use_security_risk::{RiskImpact, RiskLikelihood, RiskPriority, priority_from_likelihood_impact};

let priority = priority_from_likelihood_impact(RiskLikelihood::Likely, RiskImpact::Major);

assert_eq!(priority, RiskPriority::P1);
assert!(priority.sort_key() < RiskPriority::P3.sort_key());
```

## Scope

- Cybersecurity risk identifiers, categories, severities, likelihoods, impacts, treatments, owners, statuses, and priorities.
- Small label and sorting helpers.
- Lightweight risk metadata models for local application code.

## Non-goals

- A GRC platform.
- Risk workflow automation.
- Compliance scoring or policy enforcement.

## License

Licensed under either of the following, at your option:

- Apache License, Version 2.0
- MIT license
