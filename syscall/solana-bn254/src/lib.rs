#![no_std]

//! `solana-bn254`
//!
//! BN254 elliptic curve operations and Poseidon hashing, optimized
//! for the Solana Agave validator.
//!
//! # Security Warning
//! This crate is designed exclusively for PUBLIC DATA CONTEXTS.
//! It intentionally bypasses constant-time execution guarantees
//! to prioritize cycle efficiency and lowest possible Compute Units.

pub mod backend;
pub mod poseidon;
