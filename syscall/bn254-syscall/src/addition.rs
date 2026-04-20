use {
    crate::{
        ALT_BN128_FIELD_SIZE, ALT_BN128_FQ2_SIZE, ALT_BN128_G1_POINT_SIZE, ALT_BN128_G2_POINT_SIZE,
        Endianness, G1, G2, PodG1, PodG2, convert_endianness,
    },
    ark_serialize::{CanonicalSerialize, Compress},
};

pub const ALT_BN128_G1_ADDITION_INPUT_SIZE: usize = ALT_BN128_G1_POINT_SIZE * 2;
pub const ALT_BN128_G2_ADDITION_INPUT_SIZE: usize = ALT_BN128_G2_POINT_SIZE * 2;

pub enum VersionedG1Addition {
    V0,
}
pub enum VersionedG2Addition {
    V0,
}

pub fn alt_bn128_versioned_g1_addition(
    _version: VersionedG1Addition,
    input: &[u8],
    endianness: Endianness,
) -> Option<Vec<u8>> {
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
        Endianness::BE => Some(
            convert_endianness::<ALT_BN128_FIELD_SIZE, ALT_BN128_G1_POINT_SIZE>(&result_point_data)
                .to_vec(),
        ),
        Endianness::LE => Some(result_point_data.to_vec()),
    }
}

pub fn alt_bn128_versioned_g2_addition(
    _version: VersionedG2Addition,
    input: &[u8],
    endianness: Endianness,
) -> Option<Vec<u8>> {
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
        Endianness::BE => Some(
            convert_endianness::<ALT_BN128_FQ2_SIZE, ALT_BN128_G2_POINT_SIZE>(&result_point_data)
                .to_vec(),
        ),
        Endianness::LE => Some(result_point_data.to_vec()),
    }
}
