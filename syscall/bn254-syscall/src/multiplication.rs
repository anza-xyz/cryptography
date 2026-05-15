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

/// The version enum used to version changes to the `alt_bn128_g1_multiplication` syscall.
pub enum VersionedG1Multiplication {
    V0,
    /// SIMD-0222 - Fix alt-bn128-multiplication Syscall Length Check
    V1,
}

/// The version enum used to version changes to the `alt_bn128_g2_multiplication` syscall.
pub enum VersionedG2Multiplication {
    V0,
}

/// The syscall implementation for the `alt_bn128_g1_multiplication` syscall.
///
/// This function is intended to be used by the Agave validator client and exists
/// primarily for validator code. Solana programs or other downstream projects
/// should use the functions from the `solana-bn254` crate in the solana-sdk instead.
///
/// # Warning
///
/// Developers should be extremely careful when modifying this function, as a
/// breaking change can result in a fork in the Solana cluster. Any such change
/// requires an approved Solana SIMD. Subsequently, a new `VersionedG1Multiplication`
/// variant must be added, and the new logic must be scoped to that variant.
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

    let mut padded_input = [0u8; 128];
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

/// The syscall implementation for the `alt_bn128_g2_multiplication` syscall.
///
/// This function is intended to be used by the Agave validator client and exists
/// primarily for validator code. Solana programs or other downstream projects
/// should use the functions from the `solana-bn254` crate in the solana-sdk instead.
///
/// # Warning
///
/// Developers should be extremely careful when modifying this function, as a
/// breaking change can result in a fork in the Solana cluster. Any such change
/// requires an approved Solana SIMD. Subsequently, a new `VersionedG1Multiplication`
/// variant must be added, and the new logic must be scoped to that variant.
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
