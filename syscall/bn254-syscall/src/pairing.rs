use {
    crate::{
        Endianness, PodG1, PodG2, ALT_BN128_G1_POINT_SIZE, ALT_BN128_G2_POINT_SIZE,
        ALT_BN128_GT_ELEMENT_SIZE, G1, G2,
    },
    ark_bn254::{self, Config, Fq12},
    ark_ec::{bn::Bn, pairing::Pairing},
    ark_ff::{BigInteger, BigInteger256, One},
    ark_serialize::CanonicalSerialize,
};

/// Pair element size.
pub const ALT_BN128_PAIRING_ELEMENT_SIZE: usize = ALT_BN128_G1_POINT_SIZE + ALT_BN128_G2_POINT_SIZE; // 192

/// Output size for pairing operation.
pub const ALT_BN128_PAIRING_OUTPUT_SIZE: usize = 32;

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
    _version: VersionedPairingMap,
    input: &[u8],
    endianness: Endianness,
) -> Option<[u8; ALT_BN128_PAIRING_MAP_OUTPUT_SIZE]> {
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
fn multi_pairing(input: &[u8], endianness: &Endianness) -> Option<Fq12> {
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
        crate::{ALT_BN128_FIELD_SIZE, ALT_BN128_FQ2_SIZE},
        ark_bn254::{Fr, G1Affine, G2Affine},
        ark_ec::{AffineRepr, CurveGroup},
        ark_ff::{Field, PrimeField},
        std::ops::Mul,
    };

    fn g1_le(p: &G1Affine) -> [u8; ALT_BN128_G1_POINT_SIZE] {
        let mut bytes = [0u8; ALT_BN128_G1_POINT_SIZE];
        if !p.is_zero() {
            p.x.serialize_uncompressed(&mut bytes[..ALT_BN128_FIELD_SIZE])
                .unwrap();
            p.y.serialize_uncompressed(&mut bytes[ALT_BN128_FIELD_SIZE..])
                .unwrap();
        }
        bytes
    }

    fn g2_le(q: &G2Affine) -> [u8; ALT_BN128_G2_POINT_SIZE] {
        let mut bytes = [0u8; ALT_BN128_G2_POINT_SIZE];
        if !q.is_zero() {
            q.x.serialize_uncompressed(&mut bytes[..ALT_BN128_FQ2_SIZE])
                .unwrap();
            q.y.serialize_uncompressed(&mut bytes[ALT_BN128_FQ2_SIZE..])
                .unwrap();
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
            be.extend_from_slice(&crate::swap_endianness::<
                ALT_BN128_FIELD_SIZE,
                ALT_BN128_G1_POINT_SIZE,
            >(p_le));
            be.extend_from_slice(&crate::swap_endianness::<
                ALT_BN128_FQ2_SIZE,
                ALT_BN128_G2_POINT_SIZE,
            >(q_le));
        }
        (le, be)
    }

    fn pairing_map(
        input: &[u8],
        endianness: Endianness,
    ) -> Option<[u8; ALT_BN128_PAIRING_MAP_OUTPUT_SIZE]> {
        alt_bn128_versioned_pairing_map(VersionedPairingMap::V0, input, endianness)
    }

    fn gt_identity(endianness: Endianness) -> [u8; ALT_BN128_GT_ELEMENT_SIZE] {
        let mut bytes = [0u8; ALT_BN128_GT_ELEMENT_SIZE];
        let one_index = match endianness {
            Endianness::LE => 0,
            Endianness::BE => ALT_BN128_GT_ELEMENT_SIZE - 1,
        };
        bytes[one_index] = 1;
        bytes
    }

    /// Independent encoding of an `Fq12` element, coefficient by coefficient.
    fn gt_le(gt: &Fq12) -> [u8; ALT_BN128_GT_ELEMENT_SIZE] {
        let mut bytes = [0u8; ALT_BN128_GT_ELEMENT_SIZE];
        let coefficients = gt.to_base_prime_field_elements().collect::<Vec<_>>();
        assert_eq!(coefficients.len(), 12);
        for (chunk, c) in bytes
            .as_chunks_mut::<ALT_BN128_FIELD_SIZE>()
            .0
            .iter_mut()
            .zip(coefficients)
        {
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
        assert_eq!(
            pairing_map(&[], Endianness::LE),
            Some(gt_identity(Endianness::LE))
        );
        assert_eq!(
            pairing_map(&[], Endianness::BE),
            Some(gt_identity(Endianness::BE))
        );
    }

    #[test]
    fn pairing_map_generator_matches_fixed_vector() {
        assert_eq!(ALT_BN128_PAIRING_MAP_OUTPUT_SIZE, 384);

        // Snapshot of Bn254::pairing(G1Affine::generator(), G2Affine::generator())
        // from ark-bn254 0.5.0, with each base field coefficient encoded in LE.
        // Keep these bytes fixed to detect changes to the pairing normalization
        // or encoding when dependencies change.
        let expected_le: [u8; ALT_BN128_GT_ELEMENT_SIZE] = [
            0x95, 0x0e, 0x87, 0x9d, 0x73, 0x63, 0x1f, 0x5e, 0xb5, 0x78, 0x85, 0x89, 0xeb, 0x5f,
            0x7e, 0xf8, 0xd6, 0x3e, 0x0a, 0x28, 0xde, 0x1b, 0xa0, 0x0d, 0xfe, 0x4c, 0xa9, 0xed,
            0x3f, 0x25, 0x2b, 0x26, 0x4a, 0x8a, 0xfb, 0x8e, 0xb4, 0x34, 0x9d, 0xb4, 0x66, 0xed,
            0x18, 0x09, 0xea, 0x4d, 0x7c, 0x39, 0xbd, 0xab, 0x79, 0x38, 0x82, 0x1f, 0x1b, 0x0a,
            0x00, 0xa2, 0x95, 0xc7, 0x2c, 0x2d, 0xe0, 0x02, 0xe0, 0x1d, 0xbd, 0xfd, 0x02, 0x54,
            0x13, 0x4e, 0xfc, 0xb1, 0xec, 0x87, 0x73, 0x95, 0xd2, 0x5f, 0x93, 0x77, 0x19, 0xb3,
            0x44, 0xad, 0xb1, 0xa5, 0x8d, 0x12, 0x9b, 0xe2, 0xd6, 0xf2, 0xa9, 0x13, 0x2b, 0x16,
            0xa1, 0x6e, 0x8a, 0xb0, 0x30, 0xb1, 0x30, 0xe6, 0x9c, 0x69, 0xbd, 0x20, 0xb4, 0xc4,
            0x59, 0x86, 0xe6, 0x74, 0x4a, 0x98, 0x31, 0x4b, 0x5c, 0x1a, 0x0f, 0x50, 0xfa, 0xa9,
            0x0b, 0x04, 0xdb, 0xaf, 0x9e, 0xf8, 0xae, 0xee, 0xe3, 0xf5, 0x0b, 0xe3, 0x1c, 0x21,
            0x0b, 0x59, 0x8f, 0x47, 0x52, 0xf0, 0x73, 0x98, 0x7f, 0x9d, 0x35, 0xbe, 0x8f, 0x67,
            0x70, 0xd8, 0x3f, 0x2f, 0xfc, 0x0a, 0xf0, 0xd1, 0x8d, 0xd9, 0xd2, 0xdb, 0xcd, 0xf9,
            0x43, 0x82, 0x5a, 0xcc, 0x12, 0xa7, 0xa9, 0xdd, 0xca, 0x45, 0xe6, 0x29, 0xd9, 0x62,
            0xc6, 0xbd, 0x64, 0x90, 0x8c, 0x39, 0x30, 0xa5, 0x54, 0x1c, 0xfe, 0x29, 0x24, 0xdc,
            0xc5, 0x58, 0x0d, 0x5c, 0xef, 0x7a, 0x4b, 0xfd, 0xec, 0x90, 0xa9, 0x1b, 0x59, 0x92,
            0x6f, 0x85, 0x0d, 0x4a, 0x79, 0x23, 0xc0, 0x1a, 0x5a, 0x5d, 0xbf, 0x0f, 0x5c, 0x09,
            0x4a, 0x2b, 0x9f, 0xb9, 0xd4, 0x15, 0x82, 0x0f, 0xa6, 0xb4, 0x0c, 0x59, 0xbb, 0x9e,
            0xad, 0xe9, 0xc9, 0x53, 0x40, 0x7b, 0x0f, 0xc1, 0x1d, 0xa3, 0x50, 0xa9, 0xd8, 0x72,
            0xca, 0xd6, 0xd3, 0x14, 0x29, 0x74, 0xca, 0x38, 0x58, 0x54, 0xaf, 0xdf, 0x5f, 0x58,
            0x3c, 0x04, 0x23, 0x1a, 0xdc, 0x59, 0x57, 0xc8, 0x91, 0x4b, 0x6b, 0x20, 0xdc, 0x89,
            0x66, 0x0e, 0xd7, 0xc3, 0xbb, 0xe7, 0xc0, 0x1d, 0x97, 0x2b, 0xe2, 0xd5, 0x3e, 0xcd,
            0xb2, 0x7a, 0x1b, 0xcc, 0x16, 0xac, 0x61, 0x0d, 0xb9, 0x5a, 0xa7, 0xd2, 0x37, 0xc8,
            0xff, 0x55, 0xa8, 0x98, 0xcb, 0x88, 0x64, 0x5a, 0x0e, 0x32, 0x53, 0x0b, 0x23, 0xd7,
            0xeb, 0xf5, 0xda, 0xfd, 0xd7, 0x9b, 0x0f, 0x9c, 0x2a, 0xc4, 0xba, 0x07, 0xce, 0x18,
            0xd3, 0xd1, 0x6c, 0xf3, 0x6e, 0x47, 0x91, 0x6c, 0x4c, 0xae, 0x5d, 0x08, 0xd3, 0xaf,
            0xa8, 0x13, 0x97, 0x2c, 0x76, 0x9e, 0x85, 0x14, 0x53, 0x3e, 0x38, 0x0c, 0x94, 0x43,
            0xb3, 0xe1, 0xee, 0x5c, 0x96, 0xfa, 0x3a, 0x0a, 0x73, 0xf3, 0x01, 0xb6, 0x26, 0x45,
            0x47, 0x21, 0x52, 0x7b, 0xf9, 0x00,
        ];
        let mut expected_be = expected_le;
        expected_be.reverse();

        let (le, be) = encode(&[(G1Affine::generator(), G2Affine::generator())]);
        assert_eq!(pairing_map(&le, Endianness::LE), Some(expected_le));
        assert_eq!(pairing_map(&be, Endianness::BE), Some(expected_be));
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
        for (pairs, is_identity) in [
            (vec![], true),
            (vec![(p, q), (-p, q)], true),
            (vec![(p, q)], false),
        ] {
            let (le, be) = encode(&pairs);
            assert_eq!(
                pairing_map(&le, Endianness::LE).unwrap() == gt_identity(Endianness::LE),
                is_identity
            );
            assert_eq!(
                pairing_map(&be, Endianness::BE).unwrap() == gt_identity(Endianness::BE),
                is_identity
            );

            let mut flag_le = [0u8; ALT_BN128_PAIRING_OUTPUT_SIZE];
            flag_le[0] = u8::from(is_identity);
            let mut flag_be = flag_le;
            flag_be.reverse();
            assert_eq!(
                alt_bn128_versioned_pairing(VersionedPairing::V1, &le, Endianness::LE),
                Some(flag_le)
            );
            assert_eq!(
                alt_bn128_versioned_pairing(VersionedPairing::V1, &be, Endianness::BE),
                Some(flag_be)
            );
        }
    }

    #[test]
    fn pairing_check_rejects_deprecated_version() {
        let (le, be) = encode(&sample_pairs());
        for (input, endianness) in [
            (&[][..], Endianness::LE),
            (&[][..], Endianness::BE),
            (&le[..], Endianness::LE),
            (&be[..], Endianness::BE),
        ] {
            assert_eq!(
                alt_bn128_versioned_pairing(VersionedPairing::V0, input, endianness),
                None
            );
        }
    }

    /// Index, within a pair, of the byte that carries the flag bits of a point:
    /// the most significant byte of `y` for G1 and of `y.c1` for G2.
    fn flag_index(g2: bool, endianness: &Endianness) -> usize {
        match (g2, endianness) {
            (false, Endianness::LE) => ALT_BN128_G1_POINT_SIZE - 1, // 63
            (false, Endianness::BE) => ALT_BN128_FIELD_SIZE,        // 32
            (true, Endianness::LE) => ALT_BN128_PAIRING_ELEMENT_SIZE - 1, // 191
            (true, Endianness::BE) => ALT_BN128_G1_POINT_SIZE + ALT_BN128_FQ2_SIZE, // 128
        }
    }

    /// Range, within a pair, of the first encoded field element of a point
    /// (`x` for G1; `x.c0` in LE and `x.c1` in BE for G2).
    fn first_field_range(g2: bool) -> std::ops::Range<usize> {
        let start = if g2 { ALT_BN128_G1_POINT_SIZE } else { 0 };
        start..start + ALT_BN128_FIELD_SIZE
    }

    /// Index, within a pair, of the least significant byte of the first
    /// encoded field element of a point.
    fn first_field_lsb_index(g2: bool, endianness: &Endianness) -> usize {
        let range = first_field_range(g2);
        match endianness {
            Endianness::LE => range.start,
            Endianness::BE => range.end - 1,
        }
    }

    #[test]
    fn pairing_map_point_at_infinity() {
        // all-zero encodings
        let (le, be) = encode(&[
            (G1Affine::zero(), G2Affine::generator()),
            (G1Affine::generator(), G2Affine::zero()),
        ]);
        assert_eq!(
            pairing_map(&le, Endianness::LE),
            Some(gt_identity(Endianness::LE))
        );
        assert_eq!(
            pairing_map(&be, Endianness::BE),
            Some(gt_identity(Endianness::BE))
        );
    }

    #[test]
    fn pairing_map_flag_bits() {
        assert_eq!(flag_index(false, &Endianness::LE), 63);
        assert_eq!(flag_index(false, &Endianness::BE), 32);
        assert_eq!(flag_index(true, &Endianness::LE), 191);
        assert_eq!(flag_index(true, &Endianness::BE), 128);

        let (le, be) = encode(&[(G1Affine::generator(), G2Affine::generator())]);

        for (valid, endianness) in [(&le, Endianness::LE), (&be, Endianness::BE)] {
            let run = |input: &[u8]| match endianness {
                Endianness::LE => pairing_map(input, Endianness::LE),
                Endianness::BE => pairing_map(input, Endianness::BE),
            };
            let identity = match endianness {
                Endianness::LE => gt_identity(Endianness::LE),
                Endianness::BE => gt_identity(Endianness::BE),
            };
            let unflagged = run(valid).unwrap();
            assert_ne!(unflagged, identity);

            // flags on G1 (`y`) and on G2 (`y.c1`)
            for g2 in [false, true] {
                let flag = flag_index(g2, &endianness);

                // bit 7 alone
                let mut input = valid.clone();
                input[flag] |= 0x80;
                assert_eq!(run(&input), Some(unflagged));

                // bit 6 alone: the infinity flag
                let mut input = valid.clone();
                input[flag] |= 0x40;
                assert_eq!(run(&input), Some(identity));

                // both flag bits set
                let mut input = valid.clone();
                input[flag] |= 0xc0;
                assert_eq!(run(&input), None);

                // infinity flag on coordinates that are not on the curve
                let mut input = valid.clone();
                input[flag] |= 0x40;
                input[first_field_lsb_index(g2, &endianness)] ^= 1;
                assert_eq!(run(&input), Some(identity));

                // infinity flag with a field element not below the modulus
                let mut input = valid.clone();
                input[flag] |= 0x40;
                input[first_field_range(g2)].fill(0xff);
                assert_eq!(run(&input), None);
            }
        }
    }

    #[test]
    fn pairing_map_rejects_invalid_input() {
        let (le, be) = encode(&sample_pairs());

        // length is not a multiple of the pair size
        for len in [
            1,
            ALT_BN128_PAIRING_ELEMENT_SIZE - 1,
            ALT_BN128_PAIRING_ELEMENT_SIZE + 1,
            le.len() - 1,
        ] {
            assert_eq!(pairing_map(&le[..len], Endianness::LE), None);
            assert_eq!(pairing_map(&be[..len], Endianness::BE), None);
            assert_eq!(
                alt_bn128_versioned_pairing(VersionedPairing::V1, &le[..len], Endianness::LE),
                None
            );
            assert_eq!(
                alt_bn128_versioned_pairing(VersionedPairing::V1, &be[..len], Endianness::BE),
                None
            );
        }

        // G1 point not on the curve
        let mut bad = le.clone();
        bad[0] ^= 1;
        assert_eq!(pairing_map(&bad, Endianness::LE), None);

        // G2 point not on the curve
        let mut bad = le.clone();
        bad[ALT_BN128_G1_POINT_SIZE] ^= 1;
        assert_eq!(pairing_map(&bad, Endianness::LE), None);

        // field element not below the modulus
        let mut bad = be.clone();
        bad[..ALT_BN128_FIELD_SIZE].fill(0xff);
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
