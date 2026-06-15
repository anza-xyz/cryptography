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
- Compressed and uncompressed SEC1 point input
- Uncompressed SEC1 point output
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

### SEC1 Points

```rust
use secp256r1::group::{AffinePoint, ProjectivePoint};

let uncompressed = ProjectivePoint::generator().to_sec1_uncompressed().unwrap();
let parsed = AffinePoint::from_sec1_uncompressed(uncompressed).unwrap();

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
| point double | 81.611 ns | 195.83 ns | 213.29 ns public EC |
| point add | 133.17 ns | 213.19 ns | 210.09 ns public EC |
| mixed add | 97.422 ns | 193.13 ns | n/a |
| base scalar mul | 3.033 us | 71.555 us | 3.415 us |
| double scalar mul | 31.197 us separate wNAF6 | 143.96 us | 24.258 us |

Benchmark numbers are machine- and compiler-dependent. Re-run locally before
making performance decisions.

## Safety

The crate forbids `unsafe` in library code. Benchmark code uses OpenSSL public
APIs for comparison and is not part of the library.
