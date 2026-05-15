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

/// The version enum used to version changes to the `alt_bn128_g1_addition` syscall.
pub enum VersionedG1Addition {
    V0,
}

/// The version enum used to version changes to the `alt_bn128_g2_addition` syscall.
pub enum VersionedG2Addition {
    V0,
}

/// The syscall implementation for the `alt_bn128_g1_addition` syscall.
///
/// This function is intended to be used by the Agave validator client and exists
/// primarily for validator code. Solana programs or other downstream projects
/// should use the functions from the `solana-bn254` crate in the solana-sdk instead.
///
/// # Warning
///
/// Developers should be extremely careful when modifying this function, as a
/// breaking change can result in a fork in the Solana cluster. Any such change
/// requires an approved Solana SIMD. Subsequently, a new `VersionedG1Addition`
/// variant must be added, and the new logic must be scoped to that variant.
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

/// The syscall implementation for the `alt_bn128_g2_addition` syscall.
///
/// This function is intended to be used by the Agave validator client and exists
/// primarily for validator code. Solana programs or other downstream projects
/// should use the functions from the `solana-bn254` crate in the solana-sdk instead.
///
/// # Security Note: Unlike G1, which has cofactor 1, the group G2 has a high cofactor.
/// This G2 addition function validates only the curve equation; it does not perform
/// a subgroup (coset) check.
///
/// # Warning
///
/// Developers should be extremely careful when modifying this function, as a
/// breaking change can result in a fork in the Solana cluster. Any such change
/// requires an approved Solana SIMD. Subsequently, a new `VersionedG2Addition`
/// variant must be added, and the new logic must be scoped to that variant.
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
