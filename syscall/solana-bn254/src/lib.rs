#![no_std]

//! `solana-bn254`
//!
//! Poseidon hashing over the BN254 scalar field, optimized for the
//! Solana Agave validator.
//!
//! # Security Warning
//! This crate is designed exclusively for PUBLIC DATA CONTEXTS.
//! It intentionally bypasses constant-time execution guarantees
//! to prioritize cycle efficiency and lowest possible Compute Units.

pub mod backend;
pub mod poseidon;
