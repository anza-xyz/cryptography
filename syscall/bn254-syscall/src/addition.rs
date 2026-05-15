use {
    crate::{
        swap_endianness, Endianness, PodG1, PodG2, ALT_BN128_FIELD_SIZE, ALT_BN128_FQ2_SIZE,
        ALT_BN128_G1_POINT_SIZE, ALT_BN128_G2_POINT_SIZE, G1, G2,
    },
    ark_serialize::{CanonicalSerialize, Compress},
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

/// The implementation of the `sol_alt_bn128_group_op` syscall
/// (group operation index 0: G1 Addition).
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
    input: &[u8],
    endianness: Endianness,
) -> Option<[u8; ALT_BN128_G1_POINT_SIZE]> {
    let is_valid_len = match endianness {
        Endianness::BE => input.len() <= ALT_BN128_G1_ADDITION_INPUT_SIZE,
        Endianness::LE => input.len() == ALT_BN128_G1_ADDITION_INPUT_SIZE,
    };

    if !is_valid_len {
        return None;
    }

    let mut padded_input = [0u8; ALT_BN128_G1_ADDITION_INPUT_SIZE];
    padded_input[..input.len()].copy_from_slice(input);

    let (p_bytes, q_bytes) = padded_input.split_at(ALT_BN128_G1_POINT_SIZE);

    let (p, q) = match endianness {
        Endianness::BE => (
            PodG1::from_be_bytes(p_bytes)?.into_affine()?,
            PodG1::from_be_bytes(q_bytes)?.into_affine()?,
        ),
        Endianness::LE => (
            PodG1::from_le_bytes(p_bytes)?.into_affine()?,
            PodG1::from_le_bytes(q_bytes)?.into_affine()?,
        ),
    };

    let result_point_affine: G1 = (p + q).into();

    let mut result_point_data = [0u8; ALT_BN128_G1_POINT_SIZE];
    result_point_affine
        .x
        .serialize_with_mode(&mut result_point_data[..ALT_BN128_FIELD_SIZE], Compress::No)
        .ok()?;
    result_point_affine
        .y
        .serialize_with_mode(&mut result_point_data[ALT_BN128_FIELD_SIZE..], Compress::No)
        .ok()?;

    match endianness {
        Endianness::BE => Some(swap_endianness::<
            ALT_BN128_FIELD_SIZE,
            ALT_BN128_G1_POINT_SIZE,
        >(result_point_data)),
        Endianness::LE => Some(result_point_data),
    }
}

/// The implementation of the `sol_alt_bn128_group_op` syscall
/// (group operation index `0 | 0x80`: G2 Addition).
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
    input: &[u8],
    endianness: Endianness,
) -> Option<[u8; ALT_BN128_G2_POINT_SIZE]> {
    if input.len() != ALT_BN128_G2_ADDITION_INPUT_SIZE {
        return None;
    }

    let (p_bytes, q_bytes) = input.split_at(ALT_BN128_G2_POINT_SIZE);

    let (p, q) = match endianness {
        Endianness::BE => (
            PodG2::from_be_bytes(p_bytes)?.into_affine_unchecked()?,
            PodG2::from_be_bytes(q_bytes)?.into_affine_unchecked()?,
        ),
        Endianness::LE => (
            PodG2::from_le_bytes(p_bytes)?.into_affine_unchecked()?,
            PodG2::from_le_bytes(q_bytes)?.into_affine_unchecked()?,
        ),
    };

    let result_point_affine: G2 = (p + q).into();

    let mut result_point_data = [0u8; ALT_BN128_G2_POINT_SIZE];
    result_point_affine
        .x
        .serialize_with_mode(&mut result_point_data[..ALT_BN128_FQ2_SIZE], Compress::No)
        .ok()?;
    result_point_affine
        .y
        .serialize_with_mode(&mut result_point_data[ALT_BN128_FQ2_SIZE..], Compress::No)
        .ok()?;

    match endianness {
        Endianness::BE => {
            Some(swap_endianness::<ALT_BN128_FQ2_SIZE, ALT_BN128_G2_POINT_SIZE>(result_point_data))
        }
        Endianness::LE => Some(result_point_data),
    }
}
