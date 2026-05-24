# use-sbom

Software bill of materials and software supply-chain security primitives for `RustUse`.

## Experimental

`use-sbom` is experimental while the `use-security` workspace remains below `0.3.0`. Expect small API adjustments during the first release wave.

## Example

```rust
use use_sbom::{SbomComponent, SbomComponentName, SbomComponentVersion};

let component = SbomComponent::new(
    SbomComponentName::new("example")?,
    SbomComponentVersion::new("1.0.0")?,
);

assert_eq!(component.name().as_str(), "example");
# Ok::<(), use_sbom::SbomTextError>(())
```

## Scope

- SBOM format, component, package URL, digest, license expression, relationship, and supply-chain risk metadata.
- Small validation helpers for non-empty SBOM text values.

## Non-goals

- Generating full SBOM documents.
- Full `CycloneDX` or `SPDX` parsing.
- Contacting package registries or advisory databases.

## License

Licensed under either of the following, at your option:

- Apache License, Version 2.0
- MIT license
