//! Tests for the unsupported-build shim. The counterpart to [`super::avx512`],
//! which only compiles when the AVX-512 target features are on.

use crate::ed_sigs::avx512::{HotKeyCache, Verifier, VerifyPolicy};

/// A caller can compile one code path for every target and pick a fallback
/// verifier when the AVX-512 implementation was not included in this build.
#[test]
fn constructors_report_the_unsupported_build() {
    let error = Verifier::new().expect_err("this build has no AVX-512 code");
    assert!(
        error.reason().contains("avx512ifma"),
        "unhelpful reason: {error}"
    );

    assert!(Verifier::with_policy(VerifyPolicy::Dalek).is_err());
    assert!(Verifier::with_cache(VerifyPolicy::Zip215, HotKeyCache::with_capacity(4)).is_err());
}
