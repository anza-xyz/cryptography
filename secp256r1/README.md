# secp256r1

Pure-Rust secp256r1/P-256 ECDSA keys, signatures, signing, and verification.

The public API is intentionally close to RustCrypto `p256` for the common flows:
`SigningKey`, `VerifyingKey`, `Signature`, SEC1 public keys, fixed-width
signatures, DER signatures, message signing with SHA-256, and prehashed
verification.

## Status

This crate is performance-oriented and experimental. It has not been audited.
Do not treat it as production cryptography without independent review.
Signing and signing-key import use variable-time scalar multiplication for
secret-dependent values. This is acceptable for local benchmarking, but not for
production signing or side-channel-exposed environments.
`SigningKey` and RFC6979 nonce state are zeroized on drop, but callers are
responsible for clearing secret byte arrays returned by APIs such as
`SigningKey::to_bytes`.

Current scope:

- secp256r1/P-256 ECDSA
- SHA-256 message signing and verification
- 32-byte prehash signing and verification
- deterministic RFC6979/SHA-256 signing nonces
- compressed and uncompressed SEC1 public-key input
- compressed and uncompressed SEC1 public-key output
- fixed-width `r || s` and DER signature encodings

OpenSSL and `p256` are used only as dev/benchmark comparison dependencies.

## Installation

```toml
[dependencies]
secp256r1 = { path = "." }
```

For key generation examples using `OsRng`, add:

```toml
rand_core = { version = "0.6", features = ["getrandom"] }
```

For the prehash examples below, add:

```toml
sha2 = "0.10"
```

## API

```rust
use secp256r1::{Signature, SigningKey, VerifyingKey};
```

### Generate a key and sign

```rust
use rand_core::OsRng;
use secp256r1::SigningKey;

let mut rng = OsRng;
let signing_key = SigningKey::random(&mut rng);
let verifying_key = signing_key.verifying_key();

let message = b"message";
let signature = signing_key.sign(message);

verifying_key.verify(message, &signature).unwrap();
```

### Load a signing key from bytes

```rust
use secp256r1::SigningKey;

let secret = [7u8; 32];
let signing_key = SigningKey::from_slice(&secret).unwrap();
let signature = signing_key.sign(b"message");

assert!(signing_key.verifying_key().verify(b"message", &signature).is_ok());
```

### SEC1 public keys

```rust
use secp256r1::{SigningKey, VerifyingKey};

let signing_key = SigningKey::from_slice(&[7u8; 32]).unwrap();
let public_key_sec1: Vec<u8> = signing_key
    .verifying_key()
    .to_encoded_point(false)
    .as_bytes()
    .to_vec();

let verifying_key = VerifyingKey::from_sec1_bytes(&public_key_sec1).unwrap();
```

`from_sec1_bytes` accepts compressed and uncompressed SEC1 public keys. Use
`to_encoded_point(true)` to emit compressed SEC1 public keys.

### Fixed-width and DER signatures

```rust
use secp256r1::{Signature, SigningKey};

let signing_key = SigningKey::from_slice(&[7u8; 32]).unwrap();
let signature = signing_key.sign(b"message");

let fixed = signature.to_bytes();        // 64 bytes: r || s
let reparsed = Signature::from_slice(&fixed).unwrap();

let der = signature.to_der();
let reparsed_der = Signature::from_der(der.as_bytes()).unwrap();

assert_eq!(signature, reparsed);
assert_eq!(signature, reparsed_der);
```

### Prehashed signing and verification

```rust
use secp256r1::SigningKey;
use sha2::{Digest as _, Sha256};

let signing_key = SigningKey::from_slice(&[7u8; 32]).unwrap();
let digest = Sha256::digest(b"message");

let signature = signing_key.sign_prehash(&digest).unwrap();
signing_key
    .verifying_key()
    .verify_prehash(&digest, &signature)
    .unwrap();
```

Prehash APIs require exactly 32 bytes.

## Benchmarks

Run all benchmarks:

```sh
cargo bench
```

Focused benchmark groups:

```sh
cargo bench --bench verify
cargo bench --bench sign
cargo bench --bench field
cargo bench --bench scalar
cargo bench --bench group
```

Representative local results from this workspace:

### Verify

| Benchmark | rust | p256 | OpenSSL |
|---|---:|---:|---:|
| prehashed, parsed sig | 35.842 us | 154.61 us | 30.896 us |
| prehashed, DER sig | 36.149 us | 153.55 us | 31.326 us |
| message SHA-256, parsed sig | 36.450 us | 154.69 us | 31.344 us |
| message SHA-256, DER sig | 36.622 us | 155.57 us | 31.842 us |

### Sign

| Benchmark | rust | p256 | OpenSSL |
|---|---:|---:|---:|
| keygen | 8.423 us | 78.101 us | 4.762 us |
| sign prehashed | 12.674 us | 94.367 us | 10.476 us |
| sign message SHA-256 | 12.869 us | 94.662 us | 10.753 us |

### Group Ops

| Benchmark | rust | p256 | OpenSSL |
|---|---:|---:|---:|
| point double | 89.851 ns | 210.85 ns | 57.582 ns nistz |
| point add | 141.95 ns | 229.71 ns | 99.978 ns nistz |
| mixed add | 101.93 ns | 205.46 ns | 75.010 ns nistz |
| base scalar mul | 3.236 us fixed-base window8 | 76.277 us | 3.543 us |
| double scalar mul | 32.682 us separate wNAF6 | 151.99 us | 25.704 us |

Benchmark numbers are machine- and compiler-dependent. Re-run locally before
making performance decisions.

## Design Notes

- `SigningKey::sign` hashes messages with SHA-256.
- `SigningKey::sign_prehash` signs a caller-provided 32-byte digest.
- `VerifyingKey::verify` hashes messages with SHA-256.
- `VerifyingKey::verify_prehash` verifies a caller-provided 32-byte digest.
- `Signature::from_der` enforces strict/minimal DER encodings.
- `field`, `scalar`, and `group` are exposed for low-level benchmarking and
  experimentation. The stable public surface should be considered the ECDSA key
  and signature API.

## Safety

The crate forbids `unsafe` in library code. Benchmark code links to OpenSSL
internal/public routines for comparison and is not part of the library.
