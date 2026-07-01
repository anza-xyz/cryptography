use {
    crate::{
        serialize_g1, serialize_g2, Endianness, PodG1, PodG2, PodScalar, ALT_BN128_FIELD_SIZE,
        ALT_BN128_G1_POINT_SIZE, ALT_BN128_G2_POINT_SIZE,
    },
    ark_ec::{self, AffineRepr},
};

/// Input size for the g1 multiplication operation (96 bytes).
pub const ALT_BN128_G1_MULTIPLICATION_INPUT_SIZE: usize =
    ALT_BN128_G1_POINT_SIZE + ALT_BN128_FIELD_SIZE;

/// Input size for the g2 multiplication operation (160 bytes).
pub const ALT_BN128_G2_MULTIPLICATION_INPUT_SIZE: usize =
    ALT_BN128_G2_POINT_SIZE + ALT_BN128_FIELD_SIZE;

/// The enum is used to version changes to the `alt_bn128_versioned_g1_multiplication` function.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VersionedG1Multiplication {
    V0,
    /// SIMD-0222 - Fix alt-bn128-multiplication Syscall Length Check
    V1,
}

/// The enum is used to version changes to the `alt_bn128_versioned_g2_multiplication` function.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VersionedG2Multiplication {
    V0,
}

/// The implementation of the `sol_alt_bn128_group_op` syscall G1 multiplication operation
/// (group operation index 0x02 for BE input/output, 0x82 for LE input/output).
///
/// **Security Note**
///
/// Because the BN254 G1 group has a cofactor of 1, the subgroup check is equivalent
/// to verifying the point is on the curve. This function fully validates the input point.
///
/// **Warning**
///
/// This is consensus-critical Agave validator code. Modifying this function can
/// result in a network fork. See the [crate-level documentation](crate) for strict
/// guidelines on SIMD approvals and versioning.
pub fn alt_bn128_versioned_g1_multiplication(
    version: VersionedG1Multiplication,
    p: &PodG1,
    scalar: &PodScalar,
    endianness: Endianness,
) -> Option<PodG1> {
    // reject deprecated variants
    if matches!(version, VersionedG1Multiplication::V0) {
        return None;
    }

    let p = p.deserialize_affine(endianness)?;
    let scalar = scalar.deserialize_bigint(endianness)?;

    serialize_g1(p.mul_bigint(scalar).into(), endianness)
}

/// The implementation of the `sol_alt_bn128_group_op` syscall G2 multiplication operation
/// (group operation index 0x06 for BE input/output, 0x86 for LE input/output).
///
/// **Security Note**
///
/// Full subgroup (coset) validation is performed on the provided G2 point.
///
/// **Warning**
///
/// This is consensus-critical Agave validator code. Modifying this function can
/// result in a network fork. See the [crate-level documentation](crate) for strict
/// guidelines on SIMD approvals and versioning.
pub fn alt_bn128_versioned_g2_multiplication(
    _version: VersionedG2Multiplication,
    p: &PodG2,
    scalar: &PodScalar,
    endianness: Endianness,
) -> Option<PodG2> {
    let p = p.deserialize_affine(endianness)?;
    let scalar = scalar.deserialize_bigint(endianness)?;

    serialize_g2(p.mul_bigint(scalar).into(), endianness)
}
