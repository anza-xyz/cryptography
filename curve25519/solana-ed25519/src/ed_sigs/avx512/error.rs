//! Error returned by the fallible verifier constructors.

use core::fmt;

/// The AVX-512 verifier cannot be constructed.
///
/// Returned by `Verifier::try_new` and friends, in two situations:
///
/// * the crate was not built for `x86_64` with the `avx512f`, `avx512dq`, and
///   `avx512ifma` target features, so only the unsupported-build shim exists;
/// * it was, but the host CPU or OS does not actually provide those features.
///
/// Note that the second case is best-effort. A binary compiled with those
/// target features may execute AVX-512 instructions emitted anywhere, so it can
/// die with `SIGILL` before it ever reaches a verifier constructor. Handling
/// this error gracefully is only sound for a build that reaches the constructor
/// at all.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UnsupportedError {
    reason: &'static str,
}

impl UnsupportedError {
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
