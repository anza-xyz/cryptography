//! Checked BN254 optimal-Ate pairings for public data.
//!
//! Values match the Arkworks 0.5 BN254 pairing convention. For coordinate-field
//! modulus q, scalar-field modulus r, x=4965661367192848881 and
//! c=2*x*(6*x^2+3*x+1), final exponentiation raises the Miller result to
//! c*(q^12-1)/r. This normalization preserves identity checks and matches
//! Arkworks' exact target-group values.
//! The implementation is variable-time, allocation-free and `no_std`.
//! Multi-pairing accepts arbitrary input length using bounded batches.

use crate::{g1, g2, gt::Gt};
use core::{borrow::Borrow, convert::Infallible, error::Error, fmt};

pub(crate) mod final_exp;
mod miller;

/// A pairing input error, preserving errors from a fallible iterator.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PairingError<E> {
    /// The input iterator yielded an error, such as a decoding failure.
    Input(E),
    /// A G2 point is not in the prime-order subgroup.
    InvalidG2,
}

impl<E: fmt::Display> fmt::Display for PairingError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Input(error) => write!(f, "pairing input error: {error}"),
            Self::InvalidG2 => f.write_str("G2 point is not in the prime-order subgroup"),
        }
    }
}

impl<E: Error + 'static> Error for PairingError<E> {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Input(error) => Some(error),
            Self::InvalidG2 => None,
        }
    }
}

/// Computes a pairing, checking G2 subgroup membership even when G1 is identity.
///
/// G1's validated type already establishes subgroup membership. G2's affine
/// type only establishes the curve equation, so a nonmember returns `None`.
/// See [`multi_pairing`] for the internal-invariant panic contract.
pub fn pairing(p: &g1::Affine, q: &g2::Affine) -> Option<Gt> {
    multi_pairing(core::iter::once((p, q)))
}

/// Computes the product of pairings, with one final exponentiation.
///
/// Each G2 point is subgroup-checked before identity pairs are skipped. A
/// cancelling or identity prefix never hides an invalid later point. Empty
/// input returns identity. There is no limit on the number of input pairs.
/// Both owned and borrowed points are accepted. Use [`try_multi_pairing`] when
/// streaming fallible inputs, so a decoding failure cannot be mistaken for the
/// end of the iterator.
/// Validation stops on failure. The iterator may be read ahead by one item
/// to select the single-pair path; later items need not be consumed or checked.
///
/// The workspace holds owned copies of at most 32 active pairs and their
/// evolving point state, plus arithmetic temporaries. Its entry-array size
/// is bounded by a unit test; total stack use also depends on compiler codegen.
/// Miller squarings are shared within each batch; batch results are multiplied
/// before final exponentiation. No prepared tables or heap allocation are used.
///
/// An empty iterator needs a point-type annotation:
/// ```
/// use solana_bn254::{g1, g2, gt::Gt, pairing::multi_pairing};
/// assert_eq!(
///     multi_pairing(core::iter::empty::<(g1::Affine, g2::Affine)>()),
///     Some(Gt::IDENTITY),
/// );
/// ```
///
/// # Panics
/// Panics if a validated Miller product is zero, which indicates an internal
/// arithmetic invariant failure. `None` is reserved for invalid G2 membership.
pub fn multi_pairing<P: Borrow<g1::Affine>, Q: Borrow<g2::Affine>>(
    pairs: impl IntoIterator<Item = (P, Q)>,
) -> Option<Gt> {
    try_multi_pairing(pairs.into_iter().map(Ok::<_, Infallible>)).ok()
}

/// Computes a pairing product from fallible owned or borrowed inputs.
///
/// An iterator error returns [`PairingError::Input`], even after an identity or
/// cancelling prefix. A nonmember G2 point returns [`PairingError::InvalidG2`].
/// Empty input returns identity. Validation stops at the first error in input
/// order, with the same one-item read-ahead and panic contract as [`multi_pairing`].
/// No heap allocation is used.
///
/// A decoder should yield `Err` for malformed input, including an incomplete
/// trailing pair; `None` from `Iterator::next` always means successful end of
/// input. Use `map` to preserve each decoder result, rather than `filter_map`
/// or `map_while`, which can discard errors or terminate the stream early.
/// ```
/// use solana_bn254::{g1, g2, pairing::{try_multi_pairing, PairingError}};
/// let pairs = [
///     Ok((g1::Affine::IDENTITY, g2::Affine::IDENTITY)),
///     Err("truncated pair"),
/// ];
/// assert_eq!(try_multi_pairing(pairs), Err(PairingError::Input("truncated pair")));
/// ```
pub fn try_multi_pairing<P: Borrow<g1::Affine>, Q: Borrow<g2::Affine>, E>(
    pairs: impl IntoIterator<Item = Result<(P, Q), E>>,
) -> Result<Gt, PairingError<E>> {
    miller::multi_miller_loop(pairs).map(finish_pairing)
}

fn finish_pairing(value: miller::MillerOutput) -> Gt {
    // The field has no zero divisors. Nonidentity validated points produce
    // nonzero lines throughout the fixed schedule; identity pairs contribute 1.
    // The schedule and line geometry are checked independently in miller tests.
    let value =
        final_exp::final_exponentiation(value.0).expect("validated Miller product must be nonzero");
    Gt::from_final_exponentiation(value)
}

/// Checks whether a pairing product is identity, with the same validation as
/// [`multi_pairing`]. Empty input returns `Some(true)`; invalid G2 returns `None`.
/// It has the same internal-invariant panic contract as [`multi_pairing`].
pub fn pairing_product_is_one<P: Borrow<g1::Affine>, Q: Borrow<g2::Affine>>(
    pairs: impl IntoIterator<Item = (P, Q)>,
) -> Option<bool> {
    multi_pairing(pairs).map(|value| value.is_identity())
}

#[cfg(test)]
use crate::backend::oracle;

#[cfg(test)]
mod tests {
    #[test]
    #[should_panic(expected = "validated Miller product must be nonzero")]
    fn zero_miller_product_is_an_internal_failure() {
        super::finish_pairing(super::miller::MillerOutput(crate::backend::Fq12::ZERO));
    }
}
