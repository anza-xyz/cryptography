//! Ed25519 signing and verification (ZIP-215 / HEEA-accelerated).

#[cfg(test)]
mod tests;

#[cfg(feature = "alloc")]
pub mod batch;
mod error;
mod signing_key;
mod verification_key;

// Allows importing traits used by `Signature`.
pub use ::ed25519;
pub use ::ed25519::Signature;
pub use error::Error;
pub use signing_key::SigningKey;
pub use verification_key::{VerificationKey, VerificationKeyBytes};
