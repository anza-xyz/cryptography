//! Scalar helpers for the AVX-512 verifier, over `crate::scalar::Scalar`.

use crate::constants::BASEPOINT_ORDER;
use crate::scalar::Scalar;

pub(crate) type Radix16 = [i8; 64];

const L_BYTES: [u8; 32] = *BASEPOINT_ORDER.as_bytes();

/// Whether `bytes` encodes a scalar `< L`.
///
/// `Scalar::from_canonical_bytes` checks this as `ct_eq(&self.reduce())`, a
/// full Montgomery reduction per signature. Signature scalars are public data,
/// so this early-exit comparison is equally sound and much cheaper.
pub(crate) fn is_canonical(bytes: &[u8; 32]) -> bool {
    let mut i = 32;
    while i > 0 {
        i -= 1;
        if bytes[i] < L_BYTES[i] {
            return true;
        }
        if bytes[i] > L_BYTES[i] {
            return false;
        }
    }
    false
}

/// Radix-16 digits of `bytes`, or `None` if it is not a canonical scalar.
pub(crate) fn canonical_radix16(bytes: [u8; 32]) -> Option<Radix16> {
    if !is_canonical(&bytes) {
        return None;
    }
    Some(Scalar::from_canonical_bytes_unchecked(bytes).as_radix_16())
}

/// Radix-16 digits of a 512-bit hash reduced mod `L`, taking the pre-swapped
/// words the SIMD SHA-512 already holds rather than bytes.
pub(crate) fn radix16_from_wide_words(words: [u64; 8]) -> Radix16 {
    Scalar::from_words_mod_order_wide(&words).as_radix_16()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// [`is_canonical`] is the one place here that deliberately does *not*
    /// call the crate's own check, so pin it against that check directly.
    #[test]
    fn is_canonical_matches_crate_scalar() {
        assert!(!is_canonical(&L_BYTES));
        let mut below = L_BYTES;
        below[0] -= 1;
        assert!(is_canonical(&below));

        let mut above = L_BYTES;
        above[0] += 1;
        assert!(!is_canonical(&above));

        let mut state = 0x6a09e667f3bcc908u64;
        let mut next = || {
            state = state
                .wrapping_mul(0xd1342543de82ef95)
                .wrapping_add(0x9e3779b97f4a7c15);
            state
        };

        let mut round = 0;
        while round < 4096 {
            let mut bytes = [0u8; 32];
            for chunk in bytes.chunks_mut(8) {
                chunk.copy_from_slice(&next().to_le_bytes());
            }
            // Unmasked bytes are almost never below `L`; also probe the range
            // just around it, where the two implementations could disagree.
            if round % 2 == 0 {
                bytes[31] &= 0x1f;
            }

            let expected = bool::from(Scalar::from_canonical_bytes(bytes).is_some());
            assert_eq!(
                is_canonical(&bytes),
                expected,
                "round {round}: {bytes:02x?}"
            );
            assert_eq!(
                canonical_radix16(bytes).is_some(),
                expected,
                "round {round}"
            );
            round += 1;
        }
    }

    /// The word-based hot path must agree with the crate's byte-based one.
    #[test]
    fn wide_words_match_crate_byte_reduction() {
        let mut state = 0x2545f4914f6cdd1du64;
        let mut next = || {
            state = state
                .wrapping_mul(0xd1342543de82ef95)
                .wrapping_add(0x9e3779b97f4a7c15);
            state
        };

        let mut round = 0;
        while round < 2048 {
            let words: [u64; 8] = core::array::from_fn(|_| next());
            let mut bytes = [0u8; 64];
            for (word, chunk) in words.iter().zip(bytes.chunks_mut(8)) {
                chunk.copy_from_slice(&word.to_le_bytes());
            }

            assert_eq!(
                radix16_from_wide_words(words),
                Scalar::from_bytes_mod_order_wide(&bytes).as_radix_16(),
                "round {round}"
            );
            round += 1;
        }
    }
}
