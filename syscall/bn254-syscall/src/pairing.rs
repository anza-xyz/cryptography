use {
    crate::{
        Endianness, PodG1, PodG2, ALT_BN128_FIELD_SIZE, ALT_BN128_G1_POINT_SIZE,
        ALT_BN128_G2_POINT_SIZE, G1, G2,
    },
    ark_bn254::{self, Config},
    ark_ec::{bn::Bn, pairing::Pairing},
    ark_ff::{BigInteger, BigInteger256, One},
    ark_serialize::CanonicalSerialize,
};

/// Pair element size.
pub const ALT_BN128_PAIRING_ELEMENT_SIZE: usize = ALT_BN128_G1_POINT_SIZE + ALT_BN128_G2_POINT_SIZE; // 192

/// Output size for pairing operation.
pub const ALT_BN128_PAIRING_OUTPUT_SIZE: usize = 32;

/// Size of a target group (Gt) element: twelve base field coefficients.
pub const ALT_BN128_GT_ELEMENT_SIZE: usize = ALT_BN128_FIELD_SIZE * 12; // 384

/// Pair element size for the pairing map operation. This is the same as
/// `ALT_BN128_PAIRING_ELEMENT_SIZE`.
pub const ALT_BN128_PAIRING_MAP_ELEMENT_SIZE: usize = ALT_BN128_PAIRING_ELEMENT_SIZE; // 192

/// Output size for the pairing map operation.
pub const ALT_BN128_PAIRING_MAP_OUTPUT_SIZE: usize = ALT_BN128_GT_ELEMENT_SIZE; // 384

/// The enum is used to version changes to the `alt_bn128_versioned_pairing` function.
pub enum VersionedPairing {
    V0,
    /// SIMD-0334 - Fix alt_bn128_pairing Syscall Length Check
    V1,
}

/// The implementation of the `sol_alt_bn128_group_op` syscall pairing operation
/// (group operation index 0x03 for BE input/output, 0x83 for LE input/output).
///
/// **Security Note**
///
/// Full subgroup (coset) validation is performed on all provided G2 points. For G1 points,
/// because the cofactor is 1, this validation is equivalent to a standard on-curve check.
///
/// **Warning**
///
/// This is consensus-critical Agave validator code. Modifying this function can
/// result in a network fork. See the [crate-level documentation](crate) for strict
/// guidelines on SIMD approvals and versioning.
pub fn alt_bn128_versioned_pairing(
    version: VersionedPairing,
    input: &[u8],
    endianness: Endianness,
) -> Option<[u8; ALT_BN128_PAIRING_OUTPUT_SIZE]> {
    // reject deprecated variants
    if matches!(version, VersionedPairing::V0) {
        return None;
    }

    let res = multi_pairing(input, &endianness)?;

    let result = if res == ark_bn254::Fq12::one() {
        BigInteger256::from(1u64)
    } else {
        BigInteger256::from(0u64)
    };

    let output = match endianness {
        Endianness::BE => result.to_bytes_be().try_into().ok()?,
        Endianness::LE => result.to_bytes_le().try_into().ok()?,
    };

    Some(output)
}

/// The enum is used to version changes to the `alt_bn128_versioned_pairing_map` function.
pub enum VersionedPairingMap {
    /// SIMD-0650 - BN254 Pairing with Target Group Output
    V0,
}

/// The implementation of the `sol_alt_bn128_group_op` syscall pairing map operation
/// (group operation index 0x07 for BE input/output, 0x87 for LE input/output).
///
/// The input layout and validation are identical to those of
/// [`alt_bn128_versioned_pairing`] (`VersionedPairing::V1`). Instead of a 32-byte
/// identity flag, the output is the target group (Gt) element
/// `e(P1, Q1) * ... * e(Pn, Qn)` after the final exponentiation.
///
/// The Gt element is an element of `Fq12`, flattened into twelve `Fq` coefficients
/// `c0, ..., c11` in canonical tower order (`Fq12.c_a.c_b.c_c` is `c_(6a + 2b + c)`):
///
/// - `Endianness::LE`: `c0, c1, ..., c11`, each coefficient in little-endian.
/// - `Endianness::BE`: `c11, c10, ..., c0`, each coefficient in big-endian. This is
///   exactly the byte-reversal of the little-endian encoding.
///
/// An empty input yields the multiplicative identity of the target group.
///
/// **Security Note**
///
/// Full subgroup (coset) validation is performed on all provided G2 points. For G1 points,
/// because the cofactor is 1, this validation is equivalent to a standard on-curve check.
///
/// **Warning**
///
/// This is consensus-critical Agave validator code. Modifying this function can
/// result in a network fork. See the [crate-level documentation](crate) for strict
/// guidelines on SIMD approvals and versioning.
pub fn alt_bn128_versioned_pairing_map(
    version: VersionedPairingMap,
    input: &[u8],
    endianness: Endianness,
) -> Option<[u8; ALT_BN128_PAIRING_MAP_OUTPUT_SIZE]> {
    match version {
        VersionedPairingMap::V0 => {}
    }

    let res = multi_pairing(input, &endianness)?;

    // `ark-serialize` writes the canonical (non-Montgomery) little-endian
    // encoding of the coefficients in tower order `c0, ..., c11`.
    let mut output = [0u8; ALT_BN128_PAIRING_MAP_OUTPUT_SIZE];
    res.serialize_uncompressed(&mut output[..]).ok()?;

    if matches!(endianness, Endianness::BE) {
        output.reverse();
    }

    Some(output)
}

/// Decodes and validates a sequence of `(G1, G2)` pairs and computes the
/// product of their pairings.
fn multi_pairing(
    input: &[u8],
    endianness: &Endianness,
) -> Option<<Bn<Config> as Pairing>::TargetField> {
    #[allow(clippy::manual_is_multiple_of)]
    if input.len() % ALT_BN128_PAIRING_ELEMENT_SIZE != 0 {
        return None;
    }

    let (chunks, _) = input.as_chunks::<ALT_BN128_PAIRING_ELEMENT_SIZE>();
    let mut vec_pairs: Vec<(G1, G2)> = Vec::with_capacity(chunks.len());

    for chunk in chunks {
        let (p_bytes, q_bytes) = chunk.split_at(ALT_BN128_G1_POINT_SIZE);

        let (g1, g2) = match endianness {
            Endianness::BE => (
                PodG1::from_be_bytes(p_bytes)?.into_affine()?,
                PodG2::from_be_bytes(q_bytes)?.into_affine()?,
            ),
            Endianness::LE => (
                PodG1::from_le_bytes(p_bytes)?.into_affine()?,
                PodG2::from_le_bytes(q_bytes)?.into_affine()?,
            ),
        };

        vec_pairs.push((g1, g2));
    }

    Some(
        <Bn<Config> as Pairing>::multi_pairing(
            vec_pairs.iter().map(|pair| pair.0),
            vec_pairs.iter().map(|pair| pair.1),
        )
        .0,
    )
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        ark_bn254::{Fq12, Fr, G1Affine, G2Affine},
        ark_ec::{AffineRepr, CurveGroup},
        ark_ff::{Field, PrimeField},
        std::ops::Mul,
    };

    fn g1_le(p: &G1Affine) -> [u8; ALT_BN128_G1_POINT_SIZE] {
        let mut bytes = [0u8; ALT_BN128_G1_POINT_SIZE];
        if !p.is_zero() {
            p.x.serialize_uncompressed(&mut bytes[..32]).unwrap();
            p.y.serialize_uncompressed(&mut bytes[32..]).unwrap();
        }
        bytes
    }

    fn g2_le(q: &G2Affine) -> [u8; ALT_BN128_G2_POINT_SIZE] {
        let mut bytes = [0u8; ALT_BN128_G2_POINT_SIZE];
        if !q.is_zero() {
            q.x.serialize_uncompressed(&mut bytes[..64]).unwrap();
            q.y.serialize_uncompressed(&mut bytes[64..]).unwrap();
        }
        bytes
    }

    /// Encodes pairs in the little-endian and the big-endian (EIP-197) layouts.
    fn encode(pairs: &[(G1Affine, G2Affine)]) -> (Vec<u8>, Vec<u8>) {
        let mut le = Vec::new();
        let mut be = Vec::new();
        for (p, q) in pairs {
            let p_le = g1_le(p);
            let q_le = g2_le(q);
            le.extend_from_slice(&p_le);
            le.extend_from_slice(&q_le);
            be.extend_from_slice(&crate::swap_endianness::<32, 64>(p_le));
            be.extend_from_slice(&crate::swap_endianness::<64, 128>(q_le));
        }
        (le, be)
    }

    fn pairing_map(input: &[u8], endianness: Endianness) -> Option<[u8; 384]> {
        alt_bn128_versioned_pairing_map(VersionedPairingMap::V0, input, endianness)
    }

    /// Independent encoding of an `Fq12` element, coefficient by coefficient.
    fn gt_le(gt: &Fq12) -> [u8; 384] {
        let mut bytes = [0u8; 384];
        let coefficients = gt.to_base_prime_field_elements().collect::<Vec<_>>();
        assert_eq!(coefficients.len(), 12);
        for (chunk, c) in bytes.chunks_exact_mut(32).zip(coefficients) {
            chunk.copy_from_slice(&c.into_bigint().to_bytes_le());
        }
        bytes
    }

    fn sample_pairs() -> Vec<(G1Affine, G2Affine)> {
        let g1 = G1Affine::generator();
        let g2 = G2Affine::generator();
        vec![
            (
                g1.mul(Fr::from(3u64)).into_affine(),
                g2.mul(Fr::from(5u64)).into_affine(),
            ),
            (
                g1.mul(Fr::from(7u64)).into_affine(),
                g2.mul(Fr::from(11u64)).into_affine(),
            ),
        ]
    }

    #[test]
    fn pairing_map_empty_input_is_identity() {
        let mut expected_le = [0u8; 384];
        expected_le[0] = 1;
        let mut expected_be = [0u8; 384];
        expected_be[383] = 1;
        assert_eq!(pairing_map(&[], Endianness::LE), Some(expected_le));
        assert_eq!(pairing_map(&[], Endianness::BE), Some(expected_be));
    }

    #[test]
    fn pairing_map_matches_arkworks() {
        let pairs = sample_pairs();
        for n in 1..=pairs.len() {
            let (le, be) = encode(&pairs[..n]);
            let expected = <Bn<Config> as Pairing>::multi_pairing(
                pairs[..n].iter().map(|pair| pair.0),
                pairs[..n].iter().map(|pair| pair.1),
            )
            .0;
            assert_ne!(expected, Fq12::one());

            let expected_le = gt_le(&expected);
            let mut expected_be = expected_le;
            expected_be.reverse();

            assert_eq!(pairing_map(&le, Endianness::LE), Some(expected_le));
            assert_eq!(pairing_map(&be, Endianness::BE), Some(expected_be));
        }
    }

    #[test]
    fn pairing_map_is_bilinear() {
        // e(3 G1, 5 G2) * e(7 G1, 11 G2) = e(G1, G2)^92 = e(92 G1, G2)
        let (le, be) = encode(&sample_pairs());
        let (single_le, single_be) = encode(&[(
            G1Affine::generator().mul(Fr::from(92u64)).into_affine(),
            G2Affine::generator(),
        )]);
        assert_eq!(
            pairing_map(&le, Endianness::LE),
            pairing_map(&single_le, Endianness::LE)
        );
        assert_eq!(
            pairing_map(&be, Endianness::BE),
            pairing_map(&single_be, Endianness::BE)
        );
    }

    #[test]
    fn pairing_map_agrees_with_pairing_check() {
        // e(a G1, G2) * e(-a G1, G2) = 1
        let p = G1Affine::generator().mul(Fr::from(42u64)).into_affine();
        let q = G2Affine::generator();
        let (le, be) = encode(&[(p, q), (-p, q)]);

        let mut identity_le = [0u8; 384];
        identity_le[0] = 1;
        let mut identity_be = identity_le;
        identity_be.reverse();
        assert_eq!(pairing_map(&le, Endianness::LE), Some(identity_le));
        assert_eq!(pairing_map(&be, Endianness::BE), Some(identity_be));

        let mut one_le = [0u8; 32];
        one_le[0] = 1;
        assert_eq!(
            alt_bn128_versioned_pairing(VersionedPairing::V1, &le, Endianness::LE),
            Some(one_le)
        );
    }

    #[test]
    fn pairing_map_point_at_infinity() {
        let mut identity_le = [0u8; 384];
        identity_le[0] = 1;

        // all-zero encodings
        let (le, _) = encode(&[
            (G1Affine::zero(), G2Affine::generator()),
            (G1Affine::generator(), G2Affine::zero()),
        ]);
        assert_eq!(pairing_map(&le, Endianness::LE), Some(identity_le));

        // infinity flag (bit 6 of the most significant byte of `y`)
        let (mut le, _) = encode(&[(G1Affine::generator(), G2Affine::generator())]);
        le[63] |= 0x40;
        assert_eq!(pairing_map(&le, Endianness::LE), Some(identity_le));

        // both flag bits set
        le[63] |= 0xc0;
        assert_eq!(pairing_map(&le, Endianness::LE), None);
    }

    #[test]
    fn pairing_map_rejects_invalid_input() {
        let (le, be) = encode(&sample_pairs());

        // length is not a multiple of the pair size
        for len in [1, 191, 193, 383] {
            assert_eq!(pairing_map(&le[..len], Endianness::LE), None);
            assert_eq!(pairing_map(&be[..len], Endianness::BE), None);
        }

        // G1 point not on the curve
        let mut bad = le.clone();
        bad[0] ^= 1;
        assert_eq!(pairing_map(&bad, Endianness::LE), None);

        // G2 point not on the curve
        let mut bad = le.clone();
        bad[64] ^= 1;
        assert_eq!(pairing_map(&bad, Endianness::LE), None);

        // field element not below the modulus
        let mut bad = be.clone();
        bad[..32].fill(0xff);
        assert_eq!(pairing_map(&bad, Endianness::BE), None);

        // G2 point on the curve but outside the prime-order subgroup
        let off_subgroup = (1u64..)
            .find_map(|x| {
                let q = G2Affine::get_point_from_x_unchecked(ark_bn254::Fq2::from(x), false)?;
                (!q.is_in_correct_subgroup_assuming_on_curve()).then_some(q)
            })
            .unwrap();
        assert!(off_subgroup.is_on_curve());
        let (bad, _) = encode(&[(G1Affine::generator(), off_subgroup)]);
        assert_eq!(pairing_map(&bad, Endianness::LE), None);
    }

    #[test]
    fn pairing_map_output_is_in_target_group() {
        let (le, _) = encode(&sample_pairs());
        let output = pairing_map(&le, Endianness::LE).unwrap();
        let gt =
            <Fq12 as ark_serialize::CanonicalDeserialize>::deserialize_uncompressed(&output[..])
                .unwrap();
        assert_eq!(gt.pow(Fr::MODULUS), Fq12::one());
    }
}
