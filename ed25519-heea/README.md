# ed25519-heea

**ZIP-215-compliant Ed25519 signatures with HEEA-accelerated verification, forked from
[ed25519-zebra].**

> For the original ed25519-zebra documentation see [README_zebra.md](README_zebra.md).

This crate is part of the [curve25519-sol](../README.md) workspace.

---

## Changes from ed25519-zebra

### `verify_heea`: fast-path signature verification

A new method `VerificationKey::verify_heea` has been added alongside the existing `verify`.
Both methods accept the same arguments and produce identical results — `verify_heea` is a
**drop-in accelerated replacement** for `verify`.

The HEEA method (from the TCHES 2025 paper _"Accelerating EdDSA Signature Verification with
Faster Scalar Size Halving"_) transforms the standard 2-point MSM:

```text
[8][s]B = [8]R + [8][h]A     (standard)
```

into a 4-point MSM over half-size (~128-bit) scalars:

```text
τs_lo·B + τs_hi·(2¹²⁸·B) = τ·R + ρ·A     (HEEA)
```

where `ρ ≡ ±τ·h (mod ℓ)` and `τs = τs_hi·2¹²⁸ + τs_lo`.  All four scalars are ≤128 bits,
and the two basepoints (`B` and `2¹²⁸B`) use precomputed lookup tables, giving approximately
**~15% faster** verification compared to the standard path.

### Dependencies

`ed25519-zebra` was updated to depend on this fork's `curve25519` crate instead of
`curve25519-dalek`, in order to access `HEEADecomposition` and `vartime_triple_scalar_mul_basepoint`.

---

## ZIP 215

ZIP-215-compliant Ed25519 validation rules are fully preserved from ed25519-zebra:

- Non-canonical point encodings are accepted for `A` and `R`.
- `s` must be a canonical integer less than the group order `ℓ`.
- The cofactor-cleared equation `[8][s]B = [8]R + [8][h]A` is used (not the RFC 8032 variant).

See [README_zebra.md](README_zebra.md) and [ZIP 215] for full details.

---

## Usage

```toml
[dependencies]
ed25519-heea = { git = "https://github.com/zz-sol/ed25519-sol", package = "ed25519-heea" }
```

### Example

```rust,no_run
use core::convert::TryFrom;
use rand::thread_rng;
use ed25519_heea::{SigningKey, VerificationKey};

let msg = b"curve25519-sol";

// Generate key and sign
let sk = SigningKey::new(thread_rng());
let sig = sk.sign(msg);
let vk = VerificationKey::from(&sk);

// Standard ZIP-215 verification (from ed25519-zebra)
vk.verify(&sig, msg).expect("valid signature");

// HEEA-accelerated verification (same result, ~15% faster)
vk.verify_heea(&sig, msg).expect("valid signature");
```

### Batch verification

Batch verification is unchanged from ed25519-zebra and uses a randomised linear combination to
check multiple signatures in one pass:

```rust,ignore
#[cfg(feature = "alloc")]
{
    use ed25519_heea::batch;

    let mut verifier = batch::Verifier::new();
    for (vk_bytes, sig, msg) in items {
        verifier.queue((vk_bytes, sig, msg));
    }
    verifier.verify(thread_rng()).expect("all valid");
}
```

---

## Features

| Feature | Default? | Description |
|---|:---:|---|
| `std` | ✓ | Enables `std`; without it the crate is `no_std` + `alloc`. |
| `alloc` | ✓ | Enables batch verification. |
| `serde` | | Serialization for key and signature types. |
| `pkcs8` | | PKCS#8 DER encoding/decoding for `VerificationKey`. |

---

## MSRV

Rust **1.85.0** (Edition 2024).

---

## References

- [TCHES 2025 paper] – _Accelerating EdDSA Signature Verification with Faster Scalar Size Halving_
- [ed25519-zebra] – upstream library (Zcash Foundation)
- [ZIP 215] – Ed25519 validation rules for Zcash
- [Original ed25519-zebra README](README_zebra.md)

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.

[TCHES 2025 paper]: https://tches.iacr.org/index.php/TCHES/article/view/11971
[ed25519-zebra]: https://github.com/ZcashFoundation/ed25519-zebra
[ZIP 215]: https://zips.z.cash/zip-0215
