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
//! - [`group`] for affine/projective points, SEC1 point parsing, scalar
//!   multiplication, double-scalar multiplication, and variable-time
//!   multiscalar multiplication.
//!
//! # Security
//!
//! This crate is experimental and has not been audited. Group scalar
//! multiplication APIs are variable time and intended for public inputs. Do not
//! use them with secret scalars in environments where local timing/cache side
//! channels are in scope.

#![forbid(unsafe_code)]

pub mod field;
pub mod group;
pub mod scalar;
