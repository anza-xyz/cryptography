//! Tests for the unsupported-build shim. The counterpart to [`super::avx512`],
//! which only compiles when the AVX-512 target features are on.

use crate::ed_sigs::avx512::{HotKeyCache, Verifier, VerifyPolicy};

/// The point of `try_*`: a caller can compile one code path for every target
/// and pick a fallback verifier at runtime instead of panicking.
#[test]
fn try_constructors_report_the_unsupported_build() {
    let error = Verifier::try_new().expect_err("this build has no AVX-512 code");
    assert!(
        error.reason().contains("avx512ifma"),
        "unhelpful reason: {error}"
    );

    assert!(Verifier::try_with_policy(VerifyPolicy::Dalek).is_err());
    assert!(Verifier::try_with_cache(VerifyPolicy::Zip215, HotKeyCache::with_capacity(4)).is_err());
}

#[test]
#[should_panic(expected = "AVX-512 verification is unavailable")]
fn new_still_panics() {
    let _ = Verifier::new();
}
