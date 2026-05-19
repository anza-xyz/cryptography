//! Ed25519 signing and verification (ZIP-215 / HEEA-accelerated).

use crate::scalar::Scalar;
use sha2::{Digest, Sha512};

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

pub(crate) fn scalar_from_sha512(hash: Sha512) -> Scalar {
    let output = hash.finalize();
    let mut bytes = [0u8; 64];
    bytes.copy_from_slice(output.as_slice());
    Scalar::from_bytes_mod_order_wide(&bytes)
}
