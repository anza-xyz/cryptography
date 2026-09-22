#![no_std]

//! `solana-bn254`
//!
//! BN254 field arithmetic and Poseidon hashing for the
//! Solana Agave validator.
//!
//! # Security Warning
//! This crate is designed exclusively for PUBLIC DATA CONTEXTS.
//! It intentionally bypasses constant-time execution guarantees
//! to prioritize cycle efficiency and lowest possible Compute Units.

pub mod backend;
pub mod poseidon;

#[cfg(test)]
extern crate self as solana_bn254;
#[cfg(test)]
extern crate std;
