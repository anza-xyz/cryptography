//! BIP32-style hardened derivation for Ed25519 signing keys.

#[cfg(feature = "zeroize")]
use zeroize::Zeroize;
use {
    super::signing_key::{SECRET_KEY_LENGTH, SigningKey},
    core::fmt,
    sha2::{Digest, Sha512, digest::Update},
};

const ED25519_BIP32_NAME: &[u8] = b"ed25519 seed";
const CHAIN_CODE_LENGTH: usize = 32;
const SHA512_BLOCK_LENGTH: usize = 128;
const SHA512_OUTPUT_LENGTH: usize = 64;

/// The high bit used to encode hardened BIP32 child indexes.
pub const BIP32_HARDENED_INDEX_FLAG: u32 = 0x8000_0000;

/// Error returned by BIP32 hardened derivation.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum Bip32DerivationError {
    /// The child index does not have the hardened bit set.
    ExpectedHardenedChildIndex(u32),
}

impl fmt::Display for Bip32DerivationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ExpectedHardenedChildIndex(index) => {
                write!(f, "expected hardened child index: {index}")
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Bip32DerivationError {}

/// An Ed25519 signing key with a BIP32 chain code.
///
/// Child indexes are encoded as BIP32 `u32` values. Hardened indexes must have
/// [`BIP32_HARDENED_INDEX_FLAG`] set.
#[derive(Clone)]
pub struct ExtendedSigningKey {
    signing_key: SigningKey,
    chain_code: [u8; CHAIN_CODE_LENGTH],
}

impl fmt::Debug for ExtendedSigningKey {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt.debug_struct("ExtendedSigningKey")
            .field("signing_key", &self.signing_key)
            .finish_non_exhaustive()
    }
}

#[cfg(feature = "zeroize")]
impl Zeroize for ExtendedSigningKey {
    fn zeroize(&mut self) {
        self.signing_key.zeroize();
        self.chain_code.zeroize();
    }
}

#[cfg(feature = "zeroize")]
impl Drop for ExtendedSigningKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ExtendedSigningKey {
    /// Creates a root extended signing key from seed bytes.
    pub fn from_seed(seed: &[u8]) -> Self {
        Self::from_hmac_output(hmac_sha512(ED25519_BIP32_NAME, &[seed]))
    }

    /// Derives a hardened child extended signing key.
    pub fn derive_child(&self, child_index: u32) -> Result<Self, Bip32DerivationError> {
        if child_index & BIP32_HARDENED_INDEX_FLAG == 0 {
            return Err(Bip32DerivationError::ExpectedHardenedChildIndex(
                child_index,
            ));
        }

        let child_index_bytes = child_index.to_be_bytes();
        Ok(Self::from_hmac_output(hmac_sha512(
            &self.chain_code,
            &[
                &[0u8],
                self.signing_key.as_secret_key_bytes(),
                &child_index_bytes,
            ],
        )))
    }

    /// Derives an extended signing key over a hardened BIP32 path.
    pub fn derive_path<I>(mut self, path: I) -> Result<Self, Bip32DerivationError>
    where
        I: IntoIterator<Item = u32>,
    {
        for child_index in path {
            self = self.derive_child(child_index)?;
        }
        Ok(self)
    }

    /// Borrows the signing key.
    pub fn signing_key(&self) -> &SigningKey {
        &self.signing_key
    }

    /// Returns the signing key, consuming this extended signing key.
    #[cfg(feature = "zeroize")]
    pub fn into_signing_key(mut self) -> SigningKey {
        let signing_key = self.signing_key.clone();
        self.zeroize();
        signing_key
    }

    /// Returns the signing key, consuming this extended signing key.
    #[cfg(not(feature = "zeroize"))]
    pub fn into_signing_key(self) -> SigningKey {
        self.signing_key
    }

    /// Borrows the chain code.
    pub fn chain_code(&self) -> &[u8; CHAIN_CODE_LENGTH] {
        &self.chain_code
    }

    fn from_hmac_output(
        #[cfg_attr(not(feature = "zeroize"), allow(unused_mut))]
        mut bytes: [u8; SHA512_OUTPUT_LENGTH],
    ) -> Self {
        let mut secret_key = [0u8; SECRET_KEY_LENGTH];
        secret_key.copy_from_slice(&bytes[..SECRET_KEY_LENGTH]);

        let mut chain_code = [0u8; CHAIN_CODE_LENGTH];
        chain_code.copy_from_slice(&bytes[SECRET_KEY_LENGTH..]);

        let signing_key = SigningKey::from(secret_key);
        let extended = Self {
            signing_key,
            chain_code,
        };

        #[cfg(feature = "zeroize")]
        {
            secret_key.zeroize();
            chain_code.zeroize();
            bytes.zeroize();
        }

        extended
    }
}

impl SigningKey {
    /// Creates a signing key from seed bytes and a hardened BIP32 path.
    ///
    /// Path entries are encoded as BIP32 `u32` child indexes and must have
    /// [`BIP32_HARDENED_INDEX_FLAG`] set.
    pub fn from_bip32_seed_and_hardened_path<I>(
        seed: &[u8],
        path: I,
    ) -> Result<Self, Bip32DerivationError>
    where
        I: IntoIterator<Item = u32>,
    {
        ExtendedSigningKey::from_seed(seed)
            .derive_path(path)
            .map(ExtendedSigningKey::into_signing_key)
    }
}

impl From<ExtendedSigningKey> for SigningKey {
    fn from(extended: ExtendedSigningKey) -> Self {
        extended.into_signing_key()
    }
}

fn hmac_sha512(key: &[u8], data: &[&[u8]]) -> [u8; SHA512_OUTPUT_LENGTH] {
    let mut key_block = [0u8; SHA512_BLOCK_LENGTH];
    if key.len() > SHA512_BLOCK_LENGTH {
        #[cfg_attr(not(feature = "zeroize"), allow(unused_mut))]
        let mut key_hash = Sha512::digest(key);
        key_block[..SHA512_OUTPUT_LENGTH].copy_from_slice(key_hash.as_slice());
        #[cfg(feature = "zeroize")]
        key_hash.zeroize();
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }

    let mut inner_pad = [0x36u8; SHA512_BLOCK_LENGTH];
    let mut outer_pad = [0x5cu8; SHA512_BLOCK_LENGTH];
    for (inner, key_byte) in inner_pad.iter_mut().zip(key_block.iter()) {
        *inner ^= *key_byte;
    }
    for (outer, key_byte) in outer_pad.iter_mut().zip(key_block.iter()) {
        *outer ^= *key_byte;
    }

    let mut inner_hash = Sha512::default().chain(&inner_pad[..]);
    for item in data {
        inner_hash = inner_hash.chain(*item);
    }
    #[cfg_attr(not(feature = "zeroize"), allow(unused_mut))]
    let mut inner_output = inner_hash.finalize();

    #[cfg_attr(not(feature = "zeroize"), allow(unused_mut))]
    let mut output = Sha512::default()
        .chain(&outer_pad[..])
        .chain(inner_output.as_slice())
        .finalize();
    let mut bytes = [0u8; SHA512_OUTPUT_LENGTH];
    bytes.copy_from_slice(output.as_slice());

    #[cfg(feature = "zeroize")]
    {
        key_block.zeroize();
        inner_pad.zeroize();
        outer_pad.zeroize();
        inner_output.zeroize();
        output.zeroize();
    }

    bytes
}
