# use-crypto

Cryptographic algorithm, key, signature, digest, and encoding-label primitives for `RustUse`.

## Experimental

`use-crypto` is experimental while the `use-security` workspace remains below `0.3.0`. Expect small API adjustments during the first release wave.

## Example

```rust
use use_crypto::{CryptoStrength, HashAlgorithm};

assert_eq!(HashAlgorithm::Sha256.strength(), CryptoStrength::Strong);
assert!(HashAlgorithm::Md5.is_deprecated_like());
```

## Scope

- Cryptographic algorithm, hash, signature, encryption, key, usage, encoding, and strength labels.
- Metadata helpers for deprecated or weak algorithm labels.

## Non-goals

- Cryptographic operations.
- Key generation.
- Hashing, signing, encryption, decryption, or certificate handling.

## License

Licensed under either of the following, at your option:

- Apache License, Version 2.0
- MIT license
