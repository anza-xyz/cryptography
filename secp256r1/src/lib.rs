//! secp256r1/P-256 field, scalar, and group operations.
//!
//! This crate implements low-level arithmetic for the NIST P-256
//! (secp256r1) curve in pure Rust, with no C dependencies in the library.
//! It is designed for benchmarking, experimentation, and public-input syscall
//! plumbing.
//!
//! # Scope
//!
//! The public modules are:
//!
//! - [`field`] for arithmetic modulo the P-256 base field.
//! - [`scalar`] for arithmetic modulo the P-256 group order.
//! - [`group`] for affine/projective points, fixed-length point parsing, scalar
//!   multiplication, double-scalar multiplication, and variable-time
//!   multiscalar multiplication.
//!
//! # Security
//!
//! All APIs are intended for public inputs only. No API provides a
//! constant-time guarantee.
//!
//! Execution time and memory access patterns may depend on field elements,
//! scalars, and points. This includes arithmetic, inversion, point operations,
//! conversions, and comparisons.
//!
//! Do not use this crate for computations on secret values, including private
//! keys or signing nonces.

#![forbid(unsafe_code)]

pub mod field;
pub mod group;
pub mod scalar;

#[cfg(doctest)]
#[doc = include_str!("../README.md")]
pub struct ReadmeDoctests;

/// Byte order used for scalars and individual point coordinates.
///
/// X and Y retain their positions in an uncompressed point. A compressed
/// point prefix remains the first byte in both orders.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Endianness {
    /// Most significant byte first.
    Big,
    /// Least significant byte first.
    Little,
}
