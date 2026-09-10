# solana-secp256r1

Pure-Rust secp256r1/P-256 field, scalar, and group operations.

This crate is scoped to low-level public curve arithmetic for benchmarking,
experimentation, and syscall plumbing. It does not expose ECDSA signing or
verification APIs.

## Status

All APIs are intended for public inputs only. No API provides a constant-time
guarantee.

Execution time and memory access patterns may depend on field elements,
scalars, and points. This includes arithmetic, inversion, point operations,
conversions, and comparisons.

Do not use this crate for computations on secret values, including private
keys or signing nonces.

Current scope:

- Base-field arithmetic modulo the P-256 field modulus
- Scalar-field arithmetic modulo the P-256 group order
- Affine and Jacobian projective point operations
- Compressed and uncompressed fixed-length point input
- Compressed and uncompressed fixed-length point output
- Single-scalar, fixed-base scalar, double-scalar, and multiscalar multiplication

OpenSSL and `p256` are used only as dev/benchmark comparison dependencies.

## Installation

```toml
[dependencies]
solana-secp256r1 = "0.1.0"
```

## API

```rust
use solana_secp256r1::{
    Endianness,
    group::{AffinePoint, ProjectivePoint},
    scalar::Scalar,
};
```

### Scalar Multiplication

These methods accept canonical 32-byte scalars in big-endian byte order.

```rust
use solana_secp256r1::group::{AffinePoint, ProjectivePoint};

let mut scalar = [0u8; 32];
scalar[31] = 7;

let fixed_base = ProjectivePoint::fixed_base_scalar_mul_vartime(scalar).unwrap();
let variable_base = ProjectivePoint::from_affine(AffinePoint::generator())
    .mul_scalar_vartime(scalar)
    .unwrap();

assert_eq!(fixed_base.to_affine(), variable_base.to_affine());
```

The checked scalar-multiplication APIs return `None` for non-canonical scalar
encodings (values greater than or equal to the P-256 group order). Explicit
`*_unchecked` variants retain reduction modulo the group order for callers that
need that behavior.

### Multiscalar Multiplication

```rust
use solana_secp256r1::group::{AffinePoint, ProjectivePoint};

let points = [
    AffinePoint::generator(),
    ProjectivePoint::generator().double().to_affine(),
];
let mut scalars = [[0u8; 32]; 2];
scalars[0][31] = 7;
scalars[1][31] = 11;

let msm = ProjectivePoint::multi_scalar_mul_vartime(&points, &scalars).unwrap();
let separate = ProjectivePoint::from_affine(points[0])
    .mul_scalar_vartime(scalars[0])
    .unwrap()
    + ProjectivePoint::from_affine(points[1])
        .mul_scalar_vartime(scalars[1])
        .unwrap();

assert_eq!(msm.to_affine(), separate.to_affine());
```

### Encoded Points

Uncompressed points use 64 bytes: `X || Y`, with each coordinate encoded
in the requested byte order. Exactly 64 zero bytes represent the identity.
Compressed points use a parity prefix (`0x02` or `0x03`) followed by a
32-byte X-coordinate in the requested byte order. The prefix stays first;
the identity has no compressed representation.

```rust
use solana_secp256r1::{Endianness, group::AffinePoint};

let point = AffinePoint::generator();
for endianness in [Endianness::Big, Endianness::Little] {
    let uncompressed = point.to_uncompressed(endianness);
    let parsed = AffinePoint::from_uncompressed(&uncompressed, endianness).unwrap();
    assert_eq!(parsed, point);

    let compressed = point.to_compressed(endianness).unwrap();
    assert_eq!(
        AffinePoint::from_compressed(&compressed, endianness),
        Some(point)
    );
}

assert_eq!(
    AffinePoint::IDENTITY.to_uncompressed(Endianness::Big),
    [0u8; 64]
);
assert!(AffinePoint::IDENTITY.to_compressed(Endianness::Big).is_none());
```

## Benchmarks

Run all secp256r1 benchmarks:

```sh
cargo bench -p solana-secp256r1
```

Focused benchmark groups:

```sh
cargo bench -p solana-secp256r1 --bench field
cargo bench -p solana-secp256r1 --bench scalar
cargo bench -p solana-secp256r1 --bench group
```

Representative local results from this workspace:

### Group Ops

| Benchmark                |      rust |               p256 |             OpenSSL |
| ------------------------ | --------: | -----------------: | ------------------: |
| point double             | 81.184 ns |          198.83 ns | 222.82 ns public EC |
| point add                | 131.49 ns |          222.38 ns | 216.44 ns public EC |
| mixed add                | 95.753 ns |          195.68 ns |                 n/a |
| variable-base scalar mul | 30.579 us |          75.541 us |                 n/a |
| fixed-base scalar mul    |  3.087 us |                n/a |            3.539 us |
| double scalar mul        | 36.716 us | 150.58 us separate |           25.352 us |

### Multiscalar Multiplication

| Benchmark    |  rust MSM | rust separate | p256 separate |
| ------------ | --------: | ------------: | ------------: |
| 8-point MSM  | 96.571 us |     244.41 us |     601.21 us |
| 32-point MSM | 322.63 us |      1.300 ms |      2.410 ms |

Benchmark numbers are machine- and compiler-dependent. Re-run locally before
making performance decisions.

## Safety

The crate forbids `unsafe` in library code. Benchmark code uses OpenSSL public
APIs for comparison and is not part of the library.
