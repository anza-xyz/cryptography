use std::fmt;

/// Errors returned by key construction, signature parsing, signing, and verification.
#[derive(Debug)]
pub enum Error {
    /// A prehashed verification API received a digest with the wrong length.
    InvalidDigestLength { expected: usize, actual: usize },
    /// The API rejected malformed input.
    InvalidInput(String),
    /// A syntactically valid ECDSA signature did not verify.
    InvalidSignature,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidDigestLength { expected, actual } => {
                write!(
                    f,
                    "invalid digest length: expected {expected}, got {actual}"
                )
            }
            Self::InvalidInput(error) => write!(f, "secp256r1 error: {error}"),
            Self::InvalidSignature => write!(f, "invalid ECDSA signature"),
        }
    }
}

impl std::error::Error for Error {}

/// Result type used by this crate.
pub type Result<T> = std::result::Result<T, Error>;
