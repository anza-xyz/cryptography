# curve25519 (`solana-ed25519`)

**A pure-Rust implementation of group operations on Ristretto and Curve25519, forked from
[curve25519-dalek] with HEEA scalar decomposition and a reduced backend set.**

> For the original curve25519-dalek documentation see [README_dalek.md](README_dalek.md).

This crate is part of the [cryptography](https://github.com/anza-xyz/cryptography/) workspace.

---

## Changes from curve25519-dalek

### HEEA Scalar Decomposition

A new `HEEADecomposition` trait and implementation have been added in:

- [`src/scalar/heea.rs`](src/scalar/heea.rs) – `curve25519_heea_vartime`, the core
  half-extended Euclidean algorithm
- [`src/traits.rs`](src/traits.rs) – `HEEADecomposition` trait (`heea_decompose`)
- [`src/backend/serial/scalar_mul/vartime_triple_base.rs`](src/backend/serial/scalar_mul/vartime_triple_base.rs) –
  `mul_128_128_256`, a four-variable MSM optimised for two 128-bit and one 256-bit scalar

Given a 256-bit hash scalar `h`, `heea_decompose` returns `(ρ, τ, flip_h)` such that:

```text
flip_h = false:  ρ ≡  τ·h  (mod ℓ)
flip_h = true:   ρ ≡ -τ·h  (mod ℓ)
```

This allows verification of `sB = R + hA` to be rewritten as a 4-point MSM over ~128-bit
scalars, reducing the number of point doublings required and yielding roughly **~15% faster**
verification in practice.

See the [TCHES 2025 paper] for the full algorithm description.

### Reduced Backends

Only the following backends are maintained in this fork:

| Backend | Selection | Notes |
|---|---|---|
| `serial` | Automatic fallback | Pure Rust, 64-bit word size on 64-bit targets |
| AVX2 vector backend | Runtime on x86-64 | Vectorised 4-wide field arithmetic |
| AVX-512 Ed25519 verifier | Opt-in (`avx512` feature + target features) | Batched Ed25519 verification, per-input results |
| CUDA | Opt-in (`curve25519-cuda` crate) | GPU MSM via SPPARK/BLST |

The `fiat` (formally-verified fiat-crypto) and `unstable_avx512` backends present in upstream
have been removed. The AVX-512 code in this fork is not the upstream curve arithmetic backend; it
is a separate Ed25519 batch verifier exposed under `ed_sigs::avx512`.

---

## Ed25519 Signatures (`ed_sigs`)

This crate includes a **ZIP-215-compliant Ed25519 signature implementation** in the
`ed_sigs` module, forked from [ed25519-zebra] and extended with HEEA-accelerated
verification.

> For the original ed25519-zebra documentation see [README_zebra.md](README_zebra.md).

### `verify_zebra`: fast-path signature verification

`VerificationKey::verify_zebra` is the HEEA implementation used by the default
`VerificationKey::verify` method. Both accept the same arguments and produce identical
ZIP-215 results.

The HEEA method (TCHES 2025) transforms the standard 2-point MSM:

```text
[8][s]B = [8]R + [8][h]A     (standard)
```

into a 4-point MSM over half-size (~128-bit) scalars:

```text
flip_h = false:  τs_lo·B + τs_hi·(2¹²⁸·B) = τ·R + ρ·A
flip_h = true:   τs_lo·B + τs_hi·(2¹²⁸·B) = τ·R - ρ·A
```

where `ρ ≡ τ·h (mod ℓ)` when `flip_h` is false, `ρ ≡ -τ·h (mod ℓ)` when
`flip_h` is true, and `τs = τs_hi·2¹²⁸ + τs_lo`. All four scalars are ≤128 bits
and the two basepoints (`B` and `2¹²⁸B`) use precomputed lookup tables, giving approximately
**~15% faster** verification compared to the standard path.

### ZIP 215

ZIP-215-compliant Ed25519 validation rules are fully preserved from ed25519-zebra:

- Non-canonical point encodings are accepted for `A` and `R`.
- `s` must be a canonical integer less than the group order `ℓ`.
- The cofactor-cleared equation `[8][s]B = [8]R + [8][h]A` is used (not the RFC 8032 variant).

See [ZIP 215] for full details.

---

## Use

```toml
solana-ed25519 = { git = "https://github.com/anza-xyz/cryptography" }
```

### Ed25519 signing and verification

```rust,no_run
use core::convert::TryFrom;
use solana_ed25519::ed_sigs::{SigningKey, VerificationKey};

let msg = b"curve25519-sol";

// Generate key and sign
let sk = SigningKey::from_bytes(&[1u8; 32]);
let sig = sk.sign(msg);
let vk = VerificationKey::from(&sk);

// Standard ZIP-215 verification with heea acceleration
vk.verify(&sig, msg).expect("valid signature");
```

### Batch verification

```rust,ignore
use solana_ed25519::ed_sigs::batch;

let mut verifier = batch::Verifier::new();
for (vk_bytes, sig, msg) in items {
    verifier.queue((vk_bytes, sig, msg));
}
verifier.verify().expect("all valid");
```

### HEEA decomposition example

```rust,ignore
use solana_ed25519::traits::HEEADecomposition;
use solana_ed25519::scalar::Scalar;
use sha2::{Sha512, Digest};

// h is a typical 256-bit hash scalar
let h = Scalar::from_hash(Sha512::new().chain_update(b"some message"));

// Decompose into two ~128-bit scalars
let (rho, tau, flip_h) = h.heea_decompose();
// flip_h == false: rho ≡  tau·h  (mod ℓ)
// flip_h == true:  rho ≡ -tau·h  (mod ℓ)
```

---

## Feature Flags

| Feature | Default? | Description |
|---|:---:|---|
| `alloc` | ✓ | Multiscalar multiplication, batch inversion, batch compress, and the Ed25519 batch module. |
| `zeroize` | ✓ | `Zeroize` for all scalar and point types. |
| `precomputed-tables` | ✓ | Precomputed basepoint tables (~400 KB, ~4× faster basepoint mul). |
| `rand_core` | ✓ | `Scalar::random`, `RistrettoPoint::random`, `SigningKey::new`, and randomized batch verification. |
| `digest` | ✓ | Hash-to-curve, `Scalar::from_hash`, and Ed25519 hashing. |
| `std` | | Enables `std::error::Error` impl on `ed_sigs::Error`. |
| `serde` | | Serialization for all point, scalar, and key types. |
| `pkcs8` | | PKCS#8 DER encoding/decoding for Ed25519 keys. |
| `pem` | | PEM encoding/decoding for Ed25519 keys (requires `pkcs8`). |
| `avx512` | | Enables the `ed_sigs::avx512` batched verifier API. Requires an AVX-512 IFMA build for the optimized path. |
| `legacy_compatibility` | | `Scalar::from_bits` (broken arithmetic, use only if required). |
| `group` | | `group` and `ff` crate trait impls. |
| `group-bits` | | `ff::PrimeFieldBits` for `Scalar`. |
| `lizard` | | Bytestring-to-Ristretto-point injection. |

---

## Backends

There are two separate backend decisions:

- Curve arithmetic for `EdwardsPoint`, `RistrettoPoint`, scalar multiplication, and the default
  Ed25519 verifier is selected automatically at runtime.
- The AVX-512 Ed25519 batch verifier is an explicit API under `ed_sigs::avx512`; callers choose it
  directly and must build for the required AVX-512 target features to get the optimized path.

### Curve Arithmetic: Serial Fallback

Pure-Rust, available on all targets.  64-bit arithmetic on 64-bit platforms.

### Curve Arithmetic: AVX2 on x86-64

Runtime CPU-feature detection via `cpufeatures`.  4-wide vectorised field elements in
radix-25.5 representation.  Automatically selected when the CPU supports AVX2; falls through to
`serial` otherwise.

To hard-code AVX2 at compile time:

```sh
RUSTFLAGS='-C target-feature=+avx2' cargo build --release
```

### Ed25519 Batch Verification: AVX-512 IFMA

Enable the `avx512` feature to expose `solana_ed25519::ed_sigs::avx512`.  This verifier processes
eight signatures per SIMD chunk, supports `Zip215` and Dalek-style policies, and returns one
boolean per input instead of one pass/fail result for the whole batch.

> Forked from [ed25519-simd] (Apache-2.0, efagerho); see
> [ACKNOWLEDGEMENTS.md](ACKNOWLEDGEMENTS.md).

The optimized implementation is compiled only for `x86_64` builds with all of:

- `avx512f`
- `avx512dq`
- `avx512ifma`

For example:

```sh
RUSTFLAGS='-C target-feature=+avx512f,+avx512dq,+avx512ifma' \
  cargo build --release --features avx512 --target x86_64-unknown-linux-gnu
```

> **Always pass `--target`, even when it equals your host triple.** Without it, cargo applies
> `RUSTFLAGS` to host artifacts too — build scripts and proc macros — and then *executes* them
> during the build. On a machine without AVX-512 that aborts with `SIGILL: illegal instruction`
> in an unrelated dependency's build script, long before any of this crate is compiled. Passing
> `--target` makes cargo build host artifacts without `RUSTFLAGS`.

The `Verifier` constructors return `Result<_, avx512::UnsupportedError>` in every build. Builds
with all three target features return a verifier; other builds compile the same public API but
return an error, so one code path can fall back to another verifier:

```rust,ignore
match avx512::Verifier::new() {
    Ok(mut verifier) => verifier.verify_batch(&inputs, &mut out),
    Err(_) => { /* fall back to `ed_sigs::batch` */ }
}
```

This reports which implementation was selected at compile time; it is not a runtime CPU check. A
binary compiled with the AVX-512 target features may execute AVX-512 instructions anywhere, so it
must only run on a CPU and OS that support them.

To compare the AVX2 and AVX-512 Ed25519 verification paths on an AVX-512 IFMA-capable host, run
[`scripts/bench-ed25519-backends.sh`](../../scripts/bench-ed25519-backends.sh) from the workspace
root.

### CUDA (opt-in)

See the [`curve25519-cuda`](../curve25519-cuda) crate.  Provides GPU-accelerated
multi-scalar multiplication using the [SPPARK] library.

---

## Safety

All point types enforce validity invariants at the type level (no invalid `EdwardsPoint` can be
constructed).  All secret-operand operations use constant-time logic via the [`subtle`] crate.
Variable-time functions are explicitly marked `vartime`.

The AVX2 curve arithmetic backend and AVX-512 Ed25519 verifier use `unsafe` internally for SIMD
intrinsics. AVX2 dispatch is guarded by runtime CPU-feature detection. The AVX-512 verifier also
requires compile-time target features, then checks runtime CPU/OS support when the verifier is
constructed.

---

## MSRV

Rust **1.89.0** (Edition 2024).

---

## References

- [TCHES 2025 paper] – _Accelerating EdDSA Signature Verification with Faster Scalar Size Halving_
- [curve25519-dalek] – upstream curve25519 library (isis lovecruft, Henry de Valence)
- [ed25519-zebra] – upstream Ed25519 library (Zcash Foundation)
- [ed25519-simd] – upstream AVX-512 IFMA Ed25519 batch verifier (efagerho)
- [ZIP 215] – Ed25519 validation rules for Zcash
- [Original curve25519-dalek README](README_dalek.md)
- [Original ed25519-zebra README](README_zebra.md)
- [ACKNOWLEDGEMENTS.md](ACKNOWLEDGEMENTS.md) – upstream sources and their licenses

[TCHES 2025 paper]: https://tches.iacr.org/index.php/TCHES/article/view/11971
[curve25519-dalek]: https://github.com/dalek-cryptography/curve25519-dalek
[ed25519-zebra]: https://github.com/ZcashFoundation/ed25519-zebra
[ed25519-simd]: https://github.com/efagerho/ed25519-simd-rs
[ZIP 215]: https://zips.z.cash/zip-0215
[SPPARK]: https://github.com/supranational/sppark
[subtle]: https://docs.rs/subtle
