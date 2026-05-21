use crate::{
    serialize_g1, serialize_g2, Endianness, PodG1, PodG2, ALT_BN128_G1_POINT_SIZE,
    ALT_BN128_G2_POINT_SIZE,
};

/// Input size for the g1 add operation.
pub const ALT_BN128_G1_ADDITION_INPUT_SIZE: usize = ALT_BN128_G1_POINT_SIZE * 2; // 128

/// Input size for the g2 add operation.
pub const ALT_BN128_G2_ADDITION_INPUT_SIZE: usize = ALT_BN128_G2_POINT_SIZE * 2; // 256

/// The enum is used to version changes to the `alt_bn128_versioned_g1_addition` function.
pub enum VersionedG1Addition {
    V0,
}

/// The enum is used to version changes to the `alt_bn128_versioned_g2_addition` function.
pub enum VersionedG2Addition {
    V0,
}

/// The implementation of the `sol_alt_bn128_group_op` syscall G1 addition operation
/// (group operation index 0x00 for BE input/output, 0x80 for LE input/output).
///
/// **Security Note**
///
/// Because the BN254 G1 group has a cofactor of 1, the subgroup check is equivalent
/// to verifying the point is on the curve. This function fully validates the input point.
///
/// **Warning**
///
/// This is consensus-critical Agave validator code. Modifying this
/// function can result in a network fork. See the [crate-level documentation](crate)
/// for strict guidelines on SIMD approvals and versioning.
pub fn alt_bn128_versioned_g1_addition(
    _version: VersionedG1Addition,
    p: &PodG1,
    q: &PodG1,
    endianness: Endianness,
) -> Option<PodG1> {
    let p = p.deserialize_affine(endianness)?;
    let q = q.deserialize_affine(endianness)?;

    serialize_g1((p + q).into(), endianness)
}

/// The implementation of the `sol_alt_bn128_group_op` syscall G2 addition operation
/// (group operation index 0x04 for BE input/output, 0x84 for LE input/output).
///
/// **Security Note**
///
/// Unlike G1, which has a cofactor of 1, the group G2 has a high cofactor.
/// This G2 addition function validates only the curve equation; it does not perform
/// a subgroup (coset) check.
///
/// **Warning**
///
/// This is consensus-critical Agave validator code. Modifying this function can
/// result in a network fork. See the [crate-level documentation](crate) for strict
/// guidelines on SIMD approvals and versioning.
pub fn alt_bn128_versioned_g2_addition(
    _version: VersionedG2Addition,
    p: &PodG2,
    q: &PodG2,
    endianness: Endianness,
) -> Option<PodG2> {
    let p = p.deserialize_affine_unchecked(endianness)?;
    let q = q.deserialize_affine_unchecked(endianness)?;

    serialize_g2((p + q).into(), endianness)
}
