# secp256r1

Pure-Rust secp256r1/P-256 field, scalar, and group operations.

This crate is scoped to low-level public curve arithmetic for benchmarking,
experimentation, and syscall plumbing. It does not expose ECDSA signing or
verification APIs.

## Status

This crate is performance-oriented and experimental. It has not been audited.
Group scalar multiplication APIs are variable time and intended for public
inputs. Do not use them with secret scalars in environments where local
timing/cache side channels are in scope.

Current scope:

- Base-field arithmetic modulo the P-256 field modulus
- Scalar-field arithmetic modulo the P-256 group order
- Affine and Jacobian projective point operations
- Compressed and uncompressed fixed-length point input
- Uncompressed fixed-length point output
- Single-scalar, fixed-base scalar, double-scalar, and multiscalar multiplication

OpenSSL and `p256` are used only as dev/benchmark comparison dependencies.

## Installation

```toml
[dependencies]
secp256r1 = { path = "." }
```

## API

```rust
use secp256r1::{
    group::{AffinePoint, ProjectivePoint},
    scalar::Scalar,
};
```

### Scalar Multiplication

```rust
use secp256r1::group::{AffinePoint, ProjectivePoint};

let scalar = [7u8; 32];

let fixed_base = ProjectivePoint::fixed_base_scalar_mul_vartime(scalar);
let variable_base = ProjectivePoint::from_affine(AffinePoint::generator())
    .mul_scalar_vartime(scalar);

assert_eq!(fixed_base.to_affine(), variable_base.to_affine());
```

### Multiscalar Multiplication

```rust
use secp256r1::group::{AffinePoint, ProjectivePoint};

let points = [AffinePoint::generator(), ProjectivePoint::generator().double().to_affine()];
let scalars = [[7u8; 32], [11u8; 32]];

let msm = ProjectivePoint::multi_scalar_mul_vartime(&points, &scalars).unwrap();
let separate = ProjectivePoint::from_affine(points[0]).mul_scalar_vartime(scalars[0])
    + ProjectivePoint::from_affine(points[1]).mul_scalar_vartime(scalars[1]);

assert_eq!(msm.to_affine(), separate.to_affine());
```

### Encoded Points

```rust
use secp256r1::group::{AffinePoint, ProjectivePoint};

let uncompressed = ProjectivePoint::generator().to_uncompressed().unwrap();
let parsed = AffinePoint::from_uncompressed(uncompressed).unwrap();

assert_eq!(parsed, AffinePoint::generator());
```

## Benchmarks

Run all secp256r1 benchmarks:

```sh
cargo bench -p secp256r1
```

Focused benchmark groups:

```sh
cargo bench -p secp256r1 --bench field
cargo bench -p secp256r1 --bench scalar
cargo bench -p secp256r1 --bench group
```

Representative local results from this workspace:

### Group Ops

| Benchmark | rust | p256 | OpenSSL |
|---|---:|---:|---:|
| point double | 81.184 ns | 198.83 ns | 222.82 ns public EC |
| point add | 131.49 ns | 222.38 ns | 216.44 ns public EC |
| mixed add | 95.753 ns | 195.68 ns | n/a |
| variable-base scalar mul | 30.579 us | 75.541 us | n/a |
| fixed-base scalar mul | 3.087 us | n/a | 3.539 us |
| double scalar mul | 36.716 us | 150.58 us separate | 25.352 us |

### Multiscalar Multiplication

| Benchmark | rust MSM | rust separate | p256 separate |
|---|---:|---:|---:|
| 8-point MSM | 96.571 us | 244.41 us | 601.21 us |
| 32-point MSM | 322.63 us | 1.300 ms | 2.410 ms |

Benchmark numbers are machine- and compiler-dependent. Re-run locally before
making performance decisions.

## Safety

The crate forbids `unsafe` in library code. Benchmark code uses OpenSSL public
APIs for comparison and is not part of the library.
