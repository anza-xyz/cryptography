//! Error returned when the AVX-512 verifier was not compiled into this build.

use core::fmt;

/// The AVX-512 verifier cannot be constructed.
///
/// Returned by the portable constructors when the crate was not built for
/// `x86_64` with the `avx512f`, `avx512dq`, and `avx512ifma` target features.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UnsupportedError {
    reason: &'static str,
}

impl UnsupportedError {
    #[cfg(not(all(
        target_arch = "x86_64",
        target_feature = "avx512f",
        target_feature = "avx512dq",
        target_feature = "avx512ifma",
    )))]
    pub(crate) const fn new(reason: &'static str) -> Self {
        Self { reason }
    }

    /// Why the verifier is unavailable.
    pub fn reason(&self) -> &'static str {
        self.reason
    }
}

impl fmt::Display for UnsupportedError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "solana-ed25519 AVX-512 verification is unavailable: {}",
            self.reason
        )
    }
}

impl std::error::Error for UnsupportedError {}
