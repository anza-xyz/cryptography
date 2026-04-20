pub mod addition;
pub mod multiplication;
pub mod pairing;

use {
    ark_ec::AffineRepr,
    ark_serialize::{CanonicalDeserialize, Compress, Validate},
    bytemuck::{Pod, Zeroable},
};

pub const LE_FLAG: u64 = 0x80;

pub const ALT_BN128_FIELD_SIZE: usize = 32;
pub const ALT_BN128_FQ2_SIZE: usize = ALT_BN128_FIELD_SIZE * 2;
pub const ALT_BN128_G1_POINT_SIZE: usize = ALT_BN128_FIELD_SIZE * 2;
pub const ALT_BN128_G2_POINT_SIZE: usize = ALT_BN128_FQ2_SIZE * 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Pod, Zeroable)]
#[repr(transparent)]
pub struct PodG1(pub [u8; ALT_BN128_G1_POINT_SIZE]);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Pod, Zeroable)]
#[repr(transparent)]
pub struct PodG2(pub [u8; ALT_BN128_G2_POINT_SIZE]);

pub type G1 = ark_bn254::g1::G1Affine;
pub type G2 = ark_bn254::g2::G2Affine;

pub enum Endianness {
    BE,
    LE,
}

pub fn convert_endianness<const CHUNK_SIZE: usize, const ARRAY_SIZE: usize>(
    bytes: &[u8; ARRAY_SIZE],
) -> [u8; ARRAY_SIZE] {
    let mut result = [0u8; ARRAY_SIZE];

    let src_chunks = bytes.chunks_exact(CHUNK_SIZE);
    let dst_chunks = result.chunks_exact_mut(CHUNK_SIZE);

    for (src, dst) in src_chunks.zip(dst_chunks) {
        dst.copy_from_slice(src);
        dst.reverse();
    }

    result
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
        let g1 = G1::deserialize_with_mode(&buf[..], Compress::No, Validate::No).ok()?;

        // Ensure the point is actually on the curve
        g1.is_on_curve().then_some(g1)
    }

    /// Takes in an EIP-197 (big-endian) byte encoding of a group element in G1 and constructs a
    /// `PodG1` struct that encodes the same bytes in little-endian.
    pub(crate) fn from_be_bytes(be_bytes: &[u8]) -> Option<Self> {
        let pod_bytes = convert_endianness::<ALT_BN128_FIELD_SIZE, ALT_BN128_G1_POINT_SIZE>(
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
        let g2 = G2::deserialize_with_mode(&buf[..], Compress::No, Validate::Yes).ok()?;

        // Ensure the point is actually on the curve
        g2.is_on_curve().then_some(g2)
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
    pub(crate) fn from_be_bytes(be_bytes: &[u8]) -> Option<Self> {
        let pod_bytes = convert_endianness::<ALT_BN128_FQ2_SIZE, ALT_BN128_G2_POINT_SIZE>(
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
