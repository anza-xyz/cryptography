use {
    crate::{
        swap_endianness, Endianness, PodG1, PodG2, ALT_BN128_FIELD_SIZE, ALT_BN128_FQ2_SIZE,
        ALT_BN128_G1_POINT_SIZE, ALT_BN128_G2_POINT_SIZE, G1, G2,
    },
    ark_ec::{self, AffineRepr},
    ark_ff::BigInteger256,
    ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress},
};

/// Input size for the g1 multiplication operation.
pub const ALT_BN128_G1_MULTIPLICATION_INPUT_SIZE: usize =
    ALT_BN128_G1_POINT_SIZE + ALT_BN128_FIELD_SIZE; // 96

/// Input size for the g2 multiplication operation.
pub const ALT_BN128_G2_MULTIPLICATION_INPUT_SIZE: usize =
    ALT_BN128_G2_POINT_SIZE + ALT_BN128_FIELD_SIZE; // 160

/// The enum is used to version changes to the `alt_bn128_versioned_g1_multiplication` function.
pub enum VersionedG1Multiplication {
    V0,
    /// SIMD-0222 - Fix alt-bn128-multiplication Syscall Length Check
    V1,
}

/// The enum is used to version changes to the `alt_bn128_versioned_g2_multiplication` function.
pub enum VersionedG2Multiplication {
    V0,
}

/// The implementation of the `sol_alt_bn128_group_op` syscall
/// (group operation index 1: G1 Multiplication).
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
    input: &[u8],
    endianness: Endianness,
) -> Option<[u8; ALT_BN128_G1_POINT_SIZE]> {
    // reject deprecated variants
    if matches!(version, VersionedG1Multiplication::V0) {
        return None;
    }

    let is_valid_len = match endianness {
        Endianness::BE => input.len() <= ALT_BN128_G1_MULTIPLICATION_INPUT_SIZE,
        Endianness::LE => input.len() == ALT_BN128_G1_MULTIPLICATION_INPUT_SIZE,
    };

    if !is_valid_len {
        return None;
    }

    let mut padded_input = [0u8; ALT_BN128_G1_MULTIPLICATION_INPUT_SIZE];
    padded_input[..input.len()].copy_from_slice(input);

    let (p_bytes, remainder) = padded_input.split_at(ALT_BN128_G1_POINT_SIZE);
    let (fr_bytes, _) = remainder.split_at(ALT_BN128_FIELD_SIZE);

    let p = match endianness {
        Endianness::BE => PodG1::from_be_bytes(p_bytes)?.into_affine()?,
        Endianness::LE => PodG1::from_le_bytes(p_bytes)?.into_affine()?,
    };

    let fr_bytes_array: [u8; ALT_BN128_FIELD_SIZE] = fr_bytes.try_into().ok()?;
    let fr_bytes_proper = match endianness {
        Endianness::BE => {
            swap_endianness::<ALT_BN128_FIELD_SIZE, ALT_BN128_FIELD_SIZE>(fr_bytes_array)
        }
        Endianness::LE => fr_bytes_array,
    };
    let fr = BigInteger256::deserialize_uncompressed_unchecked(fr_bytes_proper.as_slice()).ok()?;

    let result_point_affine: G1 = p.mul_bigint(fr).into();

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
/// (group operation index `1 | 0x80`: G2 Multiplication).
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
    input: &[u8],
    endianness: Endianness,
) -> Option<[u8; ALT_BN128_G2_POINT_SIZE]> {
    if input.len() != ALT_BN128_G2_MULTIPLICATION_INPUT_SIZE {
        return None;
    }

    let (p_bytes, fr_bytes) = input.split_at(ALT_BN128_G2_POINT_SIZE);

    let p = match endianness {
        Endianness::BE => PodG2::from_be_bytes(p_bytes)?.into_affine()?,
        Endianness::LE => PodG2::from_le_bytes(p_bytes)?.into_affine()?,
    };

    let fr_bytes_array: [u8; ALT_BN128_FIELD_SIZE] = fr_bytes.try_into().ok()?;
    let fr_bytes_proper = match endianness {
        Endianness::BE => {
            swap_endianness::<ALT_BN128_FIELD_SIZE, ALT_BN128_FIELD_SIZE>(fr_bytes_array)
        }
        Endianness::LE => fr_bytes_array,
    };
    let fr = BigInteger256::deserialize_uncompressed_unchecked(fr_bytes_proper.as_slice()).ok()?;

    let result_point_affine: G2 = p.mul_bigint(fr).into();

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
