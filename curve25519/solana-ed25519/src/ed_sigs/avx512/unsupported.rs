//! Public API shim for builds without AVX-512 IFMA code generation.

use super::error::UnsupportedError;

/// Reason reported by every constructor in this shim.
const UNSUPPORTED_BUILD: &str = "this crate was not built for x86_64 with the \
                                 avx512f, avx512dq, and avx512ifma target features";

/// Byte length of an encoded Ed25519 public key.
pub const PUBLIC_KEY_LEN: usize = 32;
/// Byte length of an encoded Ed25519 signature.
pub const SIGNATURE_LEN: usize = 64;

/// One signature verification request: a public key, a signature over
/// `message`, and the message itself.
#[derive(Clone, Copy, Debug)]
pub struct VerifyInput<'a> {
    /// Encoded Ed25519 public key.
    pub public_key: [u8; PUBLIC_KEY_LEN],
    /// Encoded Ed25519 signature (`R || S`).
    pub signature: [u8; SIGNATURE_LEN],
    /// The signed message.
    pub message: &'a [u8],
}

/// Verification policy for the SIMD verifier.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum VerifyPolicy {
    /// ZIP-215 cofactored verification; accepts non-canonical point encodings.
    #[default]
    Zip215,
    /// Strict Dalek verification, including algebraic small-order rejection.
    Dalek,
}

/// A decoded public key and its precomputed multiplication table.
#[derive(Clone, Debug)]
pub struct CachedPublicKey {
    _private: (),
}

impl CachedPublicKey {
    /// Build a cached public key from its encoded bytes.
    pub fn from_encoded(encoded: [u8; PUBLIC_KEY_LEN]) -> Option<Self> {
        let _ = encoded;
        None
    }
}

pub(crate) mod private {
    pub trait Sealed {}
}

/// Storage policy for verifier-decoded public keys.
pub trait KeyCache: private::Sealed {
    /// Borrow a cached key, or `None` if it is absent.
    fn get(&self, encoded: &[u8; PUBLIC_KEY_LEN]) -> Option<&CachedPublicKey>;

    /// Optionally retain an already-decoded key for later chunks or batches.
    fn insert(&mut self, key: CachedPublicKey) {
        let _ = key;
    }
}

/// A [`KeyCache`] that retains no decoded keys.
#[derive(Clone, Copy, Debug, Default)]
pub struct NullKeyCache;

impl NullKeyCache {
    /// Create an empty cache.
    pub fn new() -> Self {
        Self
    }
}

impl private::Sealed for NullKeyCache {}

impl KeyCache for NullKeyCache {
    fn get(&self, encoded: &[u8; PUBLIC_KEY_LEN]) -> Option<&CachedPublicKey> {
        let _ = encoded;
        None
    }
}

/// A [`KeyCache`] that retains hot decoded keys across batches.
#[derive(Debug)]
pub struct HotKeyCache {
    capacity: usize,
}

impl HotKeyCache {
    /// Create a cache bounded to `capacity` retained keys, at least one.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(1),
        }
    }

    /// Set the maximum retained key count. Clamped to at least one key.
    pub fn set_capacity(&mut self, capacity: usize) {
        self.capacity = capacity.max(1);
    }
}

impl private::Sealed for HotKeyCache {}

impl KeyCache for HotKeyCache {
    fn get(&self, encoded: &[u8; PUBLIC_KEY_LEN]) -> Option<&CachedPublicKey> {
        let _ = encoded;
        None
    }
}

/// Batch Ed25519 verifier for a fixed [`VerifyPolicy`] and [`KeyCache`].
#[derive(Debug)]
pub struct Verifier<C: KeyCache = NullKeyCache> {
    policy: VerifyPolicy,
    cache: C,
}

impl Default for Verifier<NullKeyCache> {
    fn default() -> Self {
        Self::new()
    }
}

impl Verifier<NullKeyCache> {
    /// Create a verifier with the default policy and no retained-key cache.
    ///
    /// # Panics
    ///
    /// Always panics unless this crate was compiled for `x86_64` with
    /// `avx512f`, `avx512dq`, and `avx512ifma` target features. Use
    /// [`try_new`](Self::try_new) to handle that case instead.
    pub fn new() -> Self {
        Self::with_policy(VerifyPolicy::default())
    }

    /// Fallible [`new`](Self::new). Always returns [`UnsupportedError`] in this
    /// build.
    pub fn try_new() -> Result<Self, UnsupportedError> {
        Self::try_with_policy(VerifyPolicy::default())
    }

    /// Create a verifier with a specific policy and no retained-key cache.
    ///
    /// # Panics
    ///
    /// Always panics under the same condition as [`Verifier::new`].
    pub fn with_policy(policy: VerifyPolicy) -> Self {
        Self::with_cache(policy, NullKeyCache::new())
    }

    /// Fallible [`with_policy`](Self::with_policy). Always returns
    /// [`UnsupportedError`] in this build.
    pub fn try_with_policy(policy: VerifyPolicy) -> Result<Self, UnsupportedError> {
        Self::try_with_cache(policy, NullKeyCache::new())
    }
}

impl<C: KeyCache> Verifier<C> {
    /// Create a verifier backed by a caller-provided cache.
    ///
    /// # Panics
    ///
    /// Always panics unless this crate was compiled for `x86_64` with
    /// `avx512f`, `avx512dq`, and `avx512ifma` target features. Use
    /// [`try_with_cache`](Self::try_with_cache) to handle that case instead.
    pub fn with_cache(policy: VerifyPolicy, cache: C) -> Self {
        match Self::try_with_cache(policy, cache) {
            Ok(verifier) => verifier,
            Err(error) => panic!("{error}"),
        }
    }

    /// Fallible [`with_cache`](Self::with_cache). Always returns
    /// [`UnsupportedError`] in this build.
    pub fn try_with_cache(policy: VerifyPolicy, cache: C) -> Result<Self, UnsupportedError> {
        let _ = (policy, cache);
        Err(UnsupportedError::new(UNSUPPORTED_BUILD))
    }

    /// Borrow the configured cache.
    pub fn cache(&self) -> &C {
        &self.cache
    }

    /// Mutably borrow the configured cache.
    pub fn cache_mut(&mut self) -> &mut C {
        &mut self.cache
    }

    /// Return the verifier policy.
    pub fn policy(&self) -> VerifyPolicy {
        self.policy
    }

    /// Verify a batch and write one boolean result per input.
    ///
    /// # Panics
    ///
    /// Always panics in unsupported builds.
    pub fn verify_batch(&mut self, inputs: &[VerifyInput<'_>], out: &mut [bool]) {
        let _ = (inputs, out);
        panic!("{}", UnsupportedError::new(UNSUPPORTED_BUILD));
    }
}
