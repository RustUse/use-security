# use-threat

Threat modeling and threat-category primitives for `RustUse`.

## Experimental

`use-threat` is experimental while the `use-security` workspace remains below `0.3.0`. Expect small API adjustments during the first release wave.

## Example

```rust
use use_threat::{ThreatActorKind, ThreatCategory, ThreatId, ThreatScenario};

let scenario = ThreatScenario::new(
    ThreatId::new("T-1")?,
    ThreatCategory::Spoofing,
    ThreatActorKind::External,
);

assert_eq!(scenario.category().as_str(), "spoofing");
# Ok::<(), use_threat::ThreatError>(())
```

## Scope

- Threat IDs, actor kinds, categories, capabilities, intents, surfaces, models, and scenarios.
- STRIDE-style labels and local metadata helpers.

## Non-goals

- MITRE ATT&CK mapping.
- Attack simulation.
- Detection engineering, SIEM behavior, or threat intelligence feeds.

## License

Licensed under either of the following, at your option:

- Apache License, Version 2.0
- MIT license
