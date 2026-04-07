//! SHA-512 bitwise and rotation helper functions.
//!
//! Each function here corresponds directly to a named operation in FIPS 180-4 §4.1.3.
//! They operate on bare `u64` values and are used both by the reference SHA-512
//! implementation ([`crate::sha512::Sha512Circuit`]) and by the AIR trace builder to
//! populate witness columns.

use p3_field::PrimeCharacteristicRing;
use p3_koala_bear::KoalaBear;

/// Converts a `u64` scalar into a KoalaBear field element.
///
/// KoalaBear's modulus is 2³¹ − 2²⁴ + 1, so the value is reduced modulo p.  This is
/// used throughout the trace builder to store 64-bit words (and derived values) inside
/// the field-valued trace matrix.
pub(crate) fn bb(x: u64) -> KoalaBear {
    KoalaBear::from_u64(x)
}

/// SHA-512 Choose function — Ch(x, y, z).
///
/// Defined in FIPS 180-4 §4.1.3 as:
/// ```text
/// Ch(x, y, z) = (x AND y) XOR (NOT x AND z)
/// ```
/// For each bit position, the output bit equals `y` if the corresponding bit of `x` is 1,
/// and `z` otherwise.  Used in computing T1 each round.
pub(crate) fn ch(x: u64, y: u64, z: u64) -> u64 {
    (x & y) ^ ((!x) & z)
}

/// SHA-512 Majority function — Maj(x, y, z).
///
/// Defined in FIPS 180-4 §4.1.3 as:
/// ```text
/// Maj(x, y, z) = (x AND y) XOR (x AND z) XOR (y AND z)
/// ```
/// For each bit position, the output bit equals 1 if at least two of the three
/// corresponding input bits are 1 (majority vote).  Used in computing T2 each round.
pub(crate) fn maj(x: u64, y: u64, z: u64) -> u64 {
    (x & y) ^ (x & z) ^ (y & z)
}

/// SHA-512 upper-case Sigma-0 — Σ0(x).
///
/// Defined in FIPS 180-4 §4.1.3 as:
/// ```text
/// Σ0(x) = ROTR²⁸(x) XOR ROTR³⁴(x) XOR ROTR³⁹(x)
/// ```
/// Applied to the working variable `a` to produce the `sigma0` term that feeds into T2.
pub(crate) fn big_sigma0(x: u64) -> u64 {
    x.rotate_right(28) ^ x.rotate_right(34) ^ x.rotate_right(39)
}

/// SHA-512 upper-case Sigma-1 — Σ1(x).
///
/// Defined in FIPS 180-4 §4.1.3 as:
/// ```text
/// Σ1(x) = ROTR¹⁴(x) XOR ROTR¹⁸(x) XOR ROTR⁴¹(x)
/// ```
/// Applied to the working variable `e` to produce the `sigma1` term that feeds into T1.
pub(crate) fn big_sigma1(x: u64) -> u64 {
    x.rotate_right(14) ^ x.rotate_right(18) ^ x.rotate_right(41)
}

/// SHA-512 lower-case sigma-0 — σ0(x).
///
/// Defined in FIPS 180-4 §4.1.3 as:
/// ```text
/// σ0(x) = ROTR¹(x) XOR ROTR⁸(x) XOR SHR⁷(x)
/// ```
/// Used in the message schedule expansion:
/// W[i] = σ1(W[i−2]) + W[i−7] + σ0(W[i−15]) + W[i−16]  (for 16 ≤ i < 80)
pub(crate) fn small_sigma0(x: u64) -> u64 {
    x.rotate_right(1) ^ x.rotate_right(8) ^ (x >> 7)
}

/// SHA-512 lower-case sigma-1 — σ1(x).
///
/// Defined in FIPS 180-4 §4.1.3 as:
/// ```text
/// σ1(x) = ROTR¹⁹(x) XOR ROTR⁶¹(x) XOR SHR⁶(x)
/// ```
/// Used in the message schedule expansion:
/// W[i] = σ1(W[i−2]) + W[i−7] + σ0(W[i−15]) + W[i−16]  (for 16 ≤ i < 80)
pub(crate) fn small_sigma1(x: u64) -> u64 {
    x.rotate_right(19) ^ x.rotate_right(61) ^ (x >> 6)
}
