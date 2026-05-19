//! # Solana BN254 Syscalls
//!
//! ** Consensus-Critical Validator Code**
//!
//! The syscall implementations in this crate are intended to be used by the
//! Agave validator client and exist primarily for validator code. Solana
//! programs or other downstream projects should use the functions from the
//! `solana-bn254` crate in the `solana-sdk` instead.
//!
//! Developers should be extremely careful when modifying these functions, as a
//! breaking change can result in a fork in the Solana cluster. Any such change
//! requires an approved Solana SIMD. Subsequently, a new version variant must
//! be added, and the new logic must be scoped to that variant.

pub mod addition;
pub mod multiplication;
pub mod pairing;

use {
    ark_ec::AffineRepr,
    ark_serialize::CanonicalSerialize,
    ark_serialize::{CanonicalDeserialize, Compress, Validate},
    bytemuck::{Pod, Zeroable},
};

/// Size of the EC point field, in bytes.
pub const ALT_BN128_FIELD_SIZE: usize = 32;

/// Size of the extension field element (Fq2), in bytes.
pub const ALT_BN128_FQ2_SIZE: usize = ALT_BN128_FIELD_SIZE * 2;

/// Size of the EC point. `alt_bn128` point contains
/// the consistently united x and y fields as 64 bytes.
pub const ALT_BN128_G1_POINT_SIZE: usize = ALT_BN128_FIELD_SIZE * 2;

/// Elements in G2 is represented by 2 field-extension elements `(x, y)`.
pub const ALT_BN128_G2_POINT_SIZE: usize = ALT_BN128_FQ2_SIZE * 2;

/// The BN254 (BN128) group element in G1 as a POD type.
///
/// A group element in G1 consists of two field elements `(x, y)`. A `PodG1`
/// type expects a group element to be encoded as `[le(x), le(y)]` where
/// `le(..)` is the little-endian encoding of the input field element as used
/// in the `ark-bn254` crate. Note that this differs from the EIP-197 standard,
/// which specifies that the field elements are encoded as big-endian.
///
/// `PodG1` can be constructed from both big-endian (EIP-197) and little-endian
/// (ark-bn254) encodings using `from_be_bytes` and `from_le_bytes` methods,
/// respectively.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Pod, Zeroable)]
#[repr(transparent)]
pub(crate) struct PodG1(pub [u8; ALT_BN128_G1_POINT_SIZE]);

/// The BN254 (BN128) group element in G2 as a POD type.
///
/// Elements in G2 is represented by 2 field-extension elements `(x, y)`. Each
/// field-extension element itself is a degree 1 polynomial `x = x0 + x1*X`,
/// `y = y0 + y1*X`. The EIP-197 standard encodes a G2 element as
/// `[be(x1), be(x0), be(y1), be(y0)]` where `be(..)` is the big-endian
/// encoding of the input field element. The `ark-bn254` crate encodes a G2
/// element as `[le(x0), le(x1), le(y0), le(y1)]` where `le(..)` is the
/// little-endian encoding of the input field element. Notably, in addition to
/// the differences in the big-endian vs. little-endian encodings of field
/// elements, the order of the polynomial field coefficients `x0`, `x1`, `y0`,
/// and `y1` are different.
///
/// `PodG2` can be constructed from both big-endian (EIP-197) and little-endian
/// (ark-bn254) encodings using `from_be_bytes` and `from_le_bytes` methods,
/// respectively.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Pod, Zeroable)]
#[repr(transparent)]
pub(crate) struct PodG2(pub [u8; ALT_BN128_G2_POINT_SIZE]);

pub(crate) type G1 = ark_bn254::g1::G1Affine;
pub(crate) type G2 = ark_bn254::g2::G2Affine;

pub enum Endianness {
    BE,
    LE,
}

/// This function swaps the endianness of each element within the input byte array.
/// It splits the input byte array of size `ARRAY_SIZE` into chunks of `CHUNK_SIZE`
/// and reverses the byte order within each chunk.
///
/// Typical use cases:
/// - `swap_endianness::<32, 64>` for a G1 point
/// - `swap_endianness::<64, 128>` for a G2 point
/// - `swap_endianness::<32, 32>` for a scalar
pub(crate) fn swap_endianness<const CHUNK_SIZE: usize, const ARRAY_SIZE: usize>(
    mut bytes: [u8; ARRAY_SIZE],
) -> [u8; ARRAY_SIZE] {
    debug_assert!(
        ARRAY_SIZE.is_multiple_of(CHUNK_SIZE),
        "ARRAY_SIZE must be a multiple of CHUNK_SIZE"
    );

    for chunk in bytes.chunks_exact_mut(CHUNK_SIZE) {
        chunk.reverse();
    }
    bytes
}

impl PodG1 {
    /// Deserializes to an affine point in G1.
    /// Because G1 has a cofactor of 1, the subgroup check is equivalent to the
    /// on-curve check.
    pub(crate) fn into_affine(self) -> Option<G1> {
        // pre-handle point at infinity
        if self.0 == [0u8; 64] {
            return Some(G1::zero());
        }

        // The ark-serialize uncompressed format expects 64 bytes of coordinates
        // plus a 1-byte metadata flag. We append a 0 byte to indicate infinity = false.
        let mut buf = [0u8; 65];
        buf[..64].copy_from_slice(&self.0);

        // Validate::Yes performs the necessary subgroup checks
        G1::deserialize_with_mode(&buf[..], Compress::No, Validate::Yes).ok()
    }

    /// Takes in an EIP-197 (big-endian) byte encoding of a group element in G1 and constructs a
    /// `PodG1` struct that encodes the same bytes in little-endian.
    #[inline(always)]
    pub(crate) fn from_be_bytes(be_bytes: &[u8]) -> Option<Self> {
        let pod_bytes = swap_endianness::<ALT_BN128_FIELD_SIZE, ALT_BN128_G1_POINT_SIZE>(
            be_bytes.try_into().ok()?,
        );
        Some(Self(pod_bytes))
    }

    /// Takes in a little-endian byte encoding of a group element in G1 and constructs a
    /// `PodG1` struct that encodes the same bytes internally.
    #[inline(always)]
    pub(crate) fn from_le_bytes(le_bytes: &[u8]) -> Option<Self> {
        le_bytes.try_into().ok().map(Self)
    }
}

impl PodG2 {
    /// Deserializes to an affine point in G2.
    /// This function performs both the curve equation check and the subgroup check.
    pub(crate) fn into_affine(self) -> Option<G2> {
        // pre-handle point at infinity
        if self.0 == [0u8; 128] {
            return Some(G2::zero());
        }

        // The ark-serialize uncompressed format expects 128 bytes of coordinates
        // plus a 1-byte metadata flag. We append a 0 byte to indicate infinity = false.
        let mut buf = [0u8; 129];
        buf[..128].copy_from_slice(&self.0);

        // Validate::Yes performs the necessary subgroup checks
        G2::deserialize_with_mode(&buf[..], Compress::No, Validate::Yes).ok()
    }

    /// Deserializes to an affine point in G2.
    /// This function performs the curve equation check, but skips the subgroup check.
    pub(crate) fn into_affine_unchecked(self) -> Option<G2> {
        // pre-handle point at infinity
        if self.0 == [0u8; 128] {
            return Some(G2::zero());
        }

        // The `ark-serialize` uncompressed format for affine points expects the
        // x and y coordinates (128-bytes total) followed by a 1-byte metadata flag.
        // We explicitly handle point at infinity above, so we append `0` to indicate
        // `infinity = false`.
        let mut buf = [0u8; 129];
        buf[..128].copy_from_slice(&self.0);

        // Skips the expensive subgroup check
        let g2 = G2::deserialize_with_mode(&buf[..], Compress::No, Validate::No).ok()?;

        // Still check if point is on the curve
        g2.is_on_curve().then_some(g2)
    }

    /// Takes in an EIP-197 (big-endian) byte encoding of a group element in G2
    /// and constructs a `PodG2` struct that encodes the same bytes in
    /// little-endian.
    #[inline(always)]
    pub(crate) fn from_be_bytes(be_bytes: &[u8]) -> Option<Self> {
        let pod_bytes = swap_endianness::<ALT_BN128_FQ2_SIZE, ALT_BN128_G2_POINT_SIZE>(
            be_bytes.try_into().ok()?,
        );
        Some(Self(pod_bytes))
    }

    /// Takes in a little-endian byte encoding of a group element in G2 and constructs a
    /// `PodG2` struct that encodes the same bytes internally.
    #[inline(always)]
    pub(crate) fn from_le_bytes(le_bytes: &[u8]) -> Option<Self> {
        le_bytes.try_into().ok().map(Self)
    }
}

#[inline]
pub(crate) fn serialize_g1(
    point: G1,
    endianness: Endianness,
) -> Option<[u8; ALT_BN128_G1_POINT_SIZE]> {
    let mut data = [0u8; ALT_BN128_G1_POINT_SIZE];
    point
        .x
        .serialize_with_mode(&mut data[..ALT_BN128_FIELD_SIZE], Compress::No)
        .ok()?;
    point
        .y
        .serialize_with_mode(&mut data[ALT_BN128_FIELD_SIZE..], Compress::No)
        .ok()?;

    match endianness {
        Endianness::BE => Some(swap_endianness::<
            ALT_BN128_FIELD_SIZE,
            ALT_BN128_G1_POINT_SIZE,
        >(data)),
        Endianness::LE => Some(data),
    }
}

#[inline]
pub(crate) fn serialize_g2(
    point: G2,
    endianness: Endianness,
) -> Option<[u8; ALT_BN128_G2_POINT_SIZE]> {
    let mut data = [0u8; ALT_BN128_G2_POINT_SIZE];
    point
        .x
        .serialize_with_mode(&mut data[..ALT_BN128_FQ2_SIZE], Compress::No)
        .ok()?;
    point
        .y
        .serialize_with_mode(&mut data[ALT_BN128_FQ2_SIZE..], Compress::No)
        .ok()?;

    match endianness {
        Endianness::BE => {
            Some(swap_endianness::<ALT_BN128_FQ2_SIZE, ALT_BN128_G2_POINT_SIZE>(data))
        }
        Endianness::LE => Some(data),
    }
}

#[cfg(test)]
mod tests {
    use {
        crate::PodG1,
        ark_bn254::g1::G1Affine,
        ark_ec::AffineRepr,
        ark_serialize::{CanonicalSerialize, Compress},
    };

    #[test]
    fn zero_serialization_test() {
        let zero = G1Affine::zero();
        let mut result_point_data = [0u8; 64];
        zero.x
            .serialize_with_mode(&mut result_point_data[..32], Compress::No)
            .unwrap();
        zero.y
            .serialize_with_mode(&mut result_point_data[32..], Compress::No)
            .unwrap();
        assert_eq!(result_point_data, [0u8; 64]);

        let p: G1Affine = PodG1(result_point_data[..64].try_into().unwrap())
            .into_affine()
            .unwrap();
        assert_eq!(p, zero);
    }
}
