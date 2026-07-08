//! Ed25519 signing and verification (ZIP-215 / HEEA-accelerated).

use crate::scalar::Scalar;
use sha2::{Digest, Sha512};
#[cfg(feature = "zeroize")]
use zeroize::Zeroize;

#[cfg(test)]
mod tests;

#[cfg(feature = "alloc")]
pub mod batch;
mod bip32;
mod error;
mod signing_key;
#[cfg(feature = "simd")]
pub mod simd;
mod verification_key;

// Allows importing traits used by `Signature`.
pub use ::ed25519;
pub use ::ed25519::Signature;
pub use bip32::{BIP32_HARDENED_INDEX_FLAG, Bip32DerivationError, ExtendedSigningKey};
pub use error::Error;
pub use signing_key::SigningKey;
pub use verification_key::{VerificationKey, VerificationKeyBytes};

pub(crate) fn scalar_from_sha512(hash: Sha512) -> Scalar {
    #[cfg_attr(not(feature = "zeroize"), allow(unused_mut))]
    let mut output = hash.finalize();
    let mut bytes = [0u8; 64];
    bytes.copy_from_slice(output.as_slice());
    let scalar = Scalar::from_bytes_mod_order_wide(&bytes);

    #[cfg(feature = "zeroize")]
    {
        output.zeroize();
        bytes.zeroize();
    }

    scalar
}
