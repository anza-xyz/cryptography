//! AVX-512 Ed25519 batch verification with a scalar small-batch fallback.
//!
//! This module mirrors the main user-facing [`ed25519_simd`] verifier API while
//! adding a scalar fallback for small uncached batches.
//!
//! [`Verifier`](crate::ed_sigs::avx512::Verifier) is a distinct wrapper type and
//! is not type-compatible with [`ed25519_simd::Verifier`].
//!
//! The crate's scalar verifier is used when an uncached batch contains fewer than
//! [`SIMD_MIN_BATCH_SIZE`](crate::ed_sigs::avx512::SIMD_MIN_BATCH_SIZE)
//! signatures. A cached singleton stays on the SIMD path so the configured
//! cache is used and its recency state is refreshed.

use super::{Signature, VerificationKey};

pub use ed25519_simd::{
    CachedPublicKey, DalekPolicy, HotKeyCache, KeyCache, NullKeyCache, PUBLIC_KEY_LEN,
    SIGNATURE_LEN, VerificationPolicy, VerifyInput, VerifyPolicy, Zip215Policy,
};

/// The smallest batch delegated to the AVX-512 verifier.
///
/// Uncached batches containing zero or one signature use scalar verification.
/// A singleton already present in the configured cache uses SIMD. This cutoff
/// was measured on an AMD EPYC 9555P with AVX-512 enabled: scalar won for one
/// uncached signature under both policies, while SIMD won starting at two.
pub const SIMD_MIN_BATCH_SIZE: usize = 2;

/// Batch Ed25519 verifier for a compile-time [`VerificationPolicy`] and
/// [`KeyCache`].
///
/// Reuse one across [`verify_batch`](Self::verify_batch) calls. Uncached
/// batches smaller than [`SIMD_MIN_BATCH_SIZE`] use the corresponding scalar
/// verification method. Cached singletons and all larger batches are passed to
/// [`ed25519_simd::Verifier`]. A cold scalar verification does not build a SIMD
/// table or populate [`HotKeyCache`].
#[derive(Debug)]
pub struct Verifier<P: VerificationPolicy = Zip215Policy, C: KeyCache = NullKeyCache> {
    simd: ed25519_simd::Verifier<P, C>,
}

/// A verifier fixed to ZIP-215 at compile time.
pub type Zip215Verifier<C = NullKeyCache> = Verifier<Zip215Policy, C>;

/// A verifier fixed to Dalek-compatible rules at compile time.
pub type DalekVerifier<C = NullKeyCache> = Verifier<DalekPolicy, C>;

/// Explicit runtime choice between the two monomorphized verifier types.
///
/// Prefer [`Zip215Verifier`] or [`DalekVerifier`] when the policy is known at
/// compile time.
#[derive(Debug)]
pub enum RuntimeVerifier<C: KeyCache = NullKeyCache> {
    /// ZIP-215 verifier.
    Zip215(Zip215Verifier<C>),
    /// Dalek-compatible verifier.
    Dalek(DalekVerifier<C>),
}

impl<P: VerificationPolicy> Default for Verifier<P, NullKeyCache> {
    fn default() -> Self {
        Self::new()
    }
}

impl<P: VerificationPolicy> Verifier<P, NullKeyCache> {
    /// Create a verifier with its type-selected policy and no retained-key
    /// cache.
    pub fn new() -> Self {
        Self::with_cache(NullKeyCache::new())
    }
}

impl<P: VerificationPolicy, C: KeyCache> Verifier<P, C> {
    /// Create a verifier backed by a caller-provided cache.
    pub fn with_cache(cache: C) -> Self {
        Self {
            simd: ed25519_simd::Verifier::with_cache(cache),
        }
    }

    /// Borrow the configured cache.
    pub fn cache(&self) -> &C {
        self.simd.cache()
    }

    /// Mutably borrow the configured cache.
    pub fn cache_mut(&mut self) -> &mut C {
        self.simd.cache_mut()
    }

    /// Return the verifier policy.
    pub fn policy(&self) -> VerifyPolicy {
        P::POLICY
    }

    /// Verify a batch and write one boolean result per input. `out[i]` is
    /// `true` iff `inputs[i]`'s signature is valid for its `(public_key,
    /// message)`.
    ///
    /// # Panics
    ///
    /// Panics if `inputs.len() != out.len()`.
    pub fn verify_batch(&mut self, inputs: &[VerifyInput<'_>], out: &mut [bool]) {
        assert_eq!(inputs.len(), out.len());

        let use_scalar = inputs.len() < SIMD_MIN_BATCH_SIZE
            && inputs
                .iter()
                .all(|input| self.simd.cache().get(&input.public_key).is_none());

        if use_scalar {
            verify_scalar(inputs, out, P::POLICY);
        } else {
            self.simd.verify_batch(inputs, out);
        }
    }
}

impl Default for RuntimeVerifier<NullKeyCache> {
    fn default() -> Self {
        Self::new()
    }
}

impl RuntimeVerifier<NullKeyCache> {
    /// Create a ZIP-215 runtime verifier with no retained-key cache.
    pub fn new() -> Self {
        Self::with_policy(VerifyPolicy::default())
    }

    /// Create a runtime-selected verifier with no retained-key cache.
    pub fn with_policy(policy: VerifyPolicy) -> Self {
        Self::with_cache(policy, NullKeyCache::new())
    }
}

impl<C: KeyCache> RuntimeVerifier<C> {
    /// Create an explicitly runtime-selected verifier backed by `cache`.
    pub fn with_cache(policy: VerifyPolicy, cache: C) -> Self {
        match policy {
            VerifyPolicy::Zip215 => Self::Zip215(Zip215Verifier::with_cache(cache)),
            VerifyPolicy::Dalek => Self::Dalek(DalekVerifier::with_cache(cache)),
        }
    }

    /// Borrow the configured cache.
    pub fn cache(&self) -> &C {
        match self {
            Self::Zip215(verifier) => verifier.cache(),
            Self::Dalek(verifier) => verifier.cache(),
        }
    }

    /// Mutably borrow the configured cache.
    pub fn cache_mut(&mut self) -> &mut C {
        match self {
            Self::Zip215(verifier) => verifier.cache_mut(),
            Self::Dalek(verifier) => verifier.cache_mut(),
        }
    }

    /// Return the selected policy.
    pub fn policy(&self) -> VerifyPolicy {
        match self {
            Self::Zip215(_) => VerifyPolicy::Zip215,
            Self::Dalek(_) => VerifyPolicy::Dalek,
        }
    }

    /// Verify a batch with the selected policy.
    pub fn verify_batch(&mut self, inputs: &[VerifyInput<'_>], out: &mut [bool]) {
        match self {
            Self::Zip215(verifier) => verifier.verify_batch(inputs, out),
            Self::Dalek(verifier) => verifier.verify_batch(inputs, out),
        }
    }
}

fn verify_scalar(inputs: &[VerifyInput<'_>], out: &mut [bool], policy: VerifyPolicy) {
    for (input, valid) in inputs.iter().zip(out) {
        let signature = Signature::from(input.signature);
        *valid = VerificationKey::try_from(input.public_key)
            .and_then(|key| match policy {
                VerifyPolicy::Zip215 => key.verify_zebra(&signature, input.message),
                VerifyPolicy::Dalek => key.verify_dalek(&signature, input.message),
            })
            .is_ok();
    }
}
