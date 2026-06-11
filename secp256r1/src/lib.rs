//! secp256r1/P-256 ECDSA keys, signatures, signing, and verification.
//!
//! This crate implements ECDSA signing and verification over the NIST P-256
//! (secp256r1) curve in pure Rust, with no C dependencies in the library.
//! It is designed for benchmarking and experimentation; see the [Security]
//! section before using it.
//!
//! [Security]: #security
//!
//! # Quick start
//!
//! ```rust
//! use secp256r1::{SigningKey, VerifyingKey};
//!
//! // Generate a key pair.
//! # let signing_key = SigningKey::from_slice(&[7u8; 32]).unwrap();
//! # let verifying_key = *signing_key.verifying_key();
//! // let signing_key = SigningKey::random(&mut rand_core::OsRng);
//! // let verifying_key = *signing_key.verifying_key();
//!
//! // Sign a message (SHA-256 is applied internally).
//! let signature = signing_key.sign(b"hello");
//!
//! // Verify.
//! verifying_key.verify(b"hello", &signature).unwrap();
//! ```
//!
//! # Types
//!
//! | Type | Description |
//! |---|---|
//! | [`SigningKey`] | Private key; produces [`Signature`]s |
//! | [`VerifyingKey`] | Public key; verifies [`Signature`]s |
//! | [`Signature`] | ECDSA signature; converts to/from fixed-width and DER |
//! | [`DerSignature`] | Borrowed view of a DER-encoded signature (up to 72 bytes) |
//! | [`EncodedPoint`] | Borrowed view of a SEC1-encoded public key (33 or 65 bytes) |
//! | [`Error`] | Error type returned by parsing and verification |
//!
//! # Signature formats
//!
//! Both fixed-width (`r || s`, 64 bytes) and DER formats are supported.
//!
//! ```rust
//! # use secp256r1::{Signature, SigningKey};
//! # let signing_key = SigningKey::from_slice(&[7u8; 32]).unwrap();
//! let signature = signing_key.sign(b"hello");
//!
//! // Fixed-width round-trip.
//! let bytes = signature.to_bytes();
//! let reparsed = Signature::from_slice(&bytes).unwrap();
//! assert_eq!(signature, reparsed);
//!
//! // DER round-trip.
//! let der = signature.to_der();
//! let reparsed_der = Signature::from_der(der.as_bytes()).unwrap();
//! assert_eq!(signature, reparsed_der);
//! ```
//!
//! # Public key encoding
//!
//! [`VerifyingKey`] accepts both compressed (33-byte) and uncompressed
//! (65-byte) SEC1 keys via [`VerifyingKey::from_sec1_bytes`].
//!
//! ```rust
//! # use secp256r1::{SigningKey, VerifyingKey};
//! # let signing_key = SigningKey::from_slice(&[7u8; 32]).unwrap();
//! // Uncompressed (0x04 prefix, 65 bytes).
//! let uncompressed = signing_key.verifying_key().to_encoded_point(false);
//! // Compressed (0x02/0x03 prefix, 33 bytes).
//! let compressed = signing_key.verifying_key().to_encoded_point(true);
//!
//! let key1 = VerifyingKey::from_sec1_bytes(uncompressed.as_bytes()).unwrap();
//! let key2 = VerifyingKey::from_sec1_bytes(compressed.as_bytes()).unwrap();
//! assert_eq!(key1, key2);
//! ```
//!
//! # Prehashed signing
//!
//! Use [`SigningKey::sign_prehash`] and [`VerifyingKey::verify_prehash`] when
//! the message digest has already been computed. Both require exactly 32 bytes.
//!
//! # Low-level modules
//!
//! [`field`], [`scalar`], and [`group`] are public for benchmarking and
//! experimentation. Their APIs are not considered stable.
//!
//! # Security
//!
//! This crate is experimental and has not been audited. Signing and
//! signing-key import currently use variable-time scalar multiplication for
//! secret-dependent values. Do not use this crate for production signing or in
//! environments where local timing/cache side channels are in scope.

#![forbid(unsafe_code)]

mod constants;
mod ecdsa;
mod error;

pub mod field;
pub mod group;
pub mod scalar;

pub use ecdsa::{DerSignature, EncodedPoint, Signature, SigningKey, VerifyingKey};
pub use error::{Error, Result};
