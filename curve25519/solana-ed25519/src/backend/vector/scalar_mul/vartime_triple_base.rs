// -*- mode: rust; -*-
//
// This file is part of curve25519-dalek.
// Copyright (c) 2016-2021 isis lovecruft
// Copyright (c) 2016-2019 Henry de Valence
// See LICENSE for licensing information.

#![allow(non_snake_case)]

#[curve25519_dalek_derive::unsafe_target_feature_specialize("avx2")]
pub mod spec {

    use core::cmp::Ordering;

    #[for_target_feature("avx2")]
    use crate::backend::vector::avx2::{CachedPoint, ExtendedPoint};

    #[for_target_feature("avx2")]
    use crate::backend::vector::avx2::constants::BASEPOINT_128_ODD_LOOKUP_TABLE;
    #[cfg(feature = "precomputed-tables")]
    #[for_target_feature("avx2")]
    use crate::backend::vector::avx2::constants::BASEPOINT_ODD_LOOKUP_TABLE;

    #[cfg(not(feature = "precomputed-tables"))]
    use crate::constants;
    use crate::edwards::EdwardsPoint;
    use crate::scalar::HEEA_MAX_INDEX;
    use crate::scalar::Scalar;
    #[allow(unused_imports)]
    use crate::traits::Identity;
    use crate::window::NafLookupTable5;

    const DYNAMIC_NAF_WINDOW: usize = 5;

    // This intentionally differs from the serial backend when precomputed
    // tables are enabled. The AVX2 basepoint table is width 8, and this vector
    // path uses the larger b_lo NAF window in that configuration as a
    // backend-specific performance tradeoff.
    #[cfg(feature = "precomputed-tables")]
    const B_LO_NAF_WINDOW: usize = 8;
    #[cfg(not(feature = "precomputed-tables"))]
    const B_LO_NAF_WINDOW: usize = DYNAMIC_NAF_WINDOW;

    /// Compute \\(a_1 A_1 + a_2 A_2 + b B\\) in variable time, where \\(B\\) is the Ed25519 basepoint.
    ///
    /// This function is optimized for the case where \\(a_1\\) and \\(a_2\\) are known to be less than
    /// \\(2^{128}\\), while \\(b\\) is a full 256-bit scalar.
    ///
    /// # Precondition
    ///
    /// Callers must ensure \\(a_1\\) and \\(a_2\\) are less than \\(2^{128}\\). Use
    /// `vartime_triple_base_mul_128_128_256` for a checked wrapper that falls back
    /// to general scalar multiplication for full-width scalars.
    ///
    /// # Optimization Strategy
    ///
    /// The function decomposes the 256-bit scalar \\(b\\) as \\(b = b_{lo} + b_{hi} \cdot 2^{128}\\),
    /// where both \\(b_{lo}\\) and \\(b_{hi}\\) are 128-bit values. This allows computing:
    ///
    /// \\[
    /// a_1 A_1 + a_2 A_2 + b_{lo} B + b_{hi} B'
    /// \\]
    ///
    /// where \\(B' = B \cdot 2^{128}\\) is a precomputed constant. Now all four scalars
    /// (\\(a_1, a_2, b_{lo}, b_{hi}\\)) are 128 bits, and two of the bases (\\(B\\) and \\(B'\\))
    /// use precomputed tables.
    ///
    /// # Implementation
    ///
    /// - For \\(A_1\\) and \\(A_2\\): NAF with window width 5 (8 precomputed points each)
    /// - For \\(B\\): NAF with window width 8 when precomputed tables available (64 points), otherwise width 5
    /// - For \\(B'\\): NAF with window width 5
    ///
    /// The serial backend keeps \\(b_{lo}\\) at width 5 even when precomputed
    /// tables are enabled. This vector backend uses width 8 in that
    /// configuration as a backend-specific performance tradeoff.
    ///
    /// The algorithm shares doublings across all four scalar multiplications, processing
    /// only 128 bits instead of 256, providing approximately 2x speedup over the naive approach.
    ///
    /// This SIMD implementation uses vectorized point operations (AVX2 or AVX512-IFMA) for
    /// improved performance over the serial backend.
    pub(crate) fn mul_128_128_256_prechecked(
        a1: &Scalar,
        A1: &EdwardsPoint,
        a2: &Scalar,
        A2: &EdwardsPoint,
        b: &Scalar,
    ) -> EdwardsPoint {
        // Decompose b into b_lo (lower 128 bits) and b_hi (upper 128 bits)
        // b = b_lo + b_hi * 2^128
        let b_bytes = b.as_bytes();

        let mut b_lo_bytes = [0u8; 32];
        let mut b_hi_bytes = [0u8; 32];

        // Copy lower 16 bytes to b_lo, upper 16 bytes to b_hi
        b_lo_bytes[..16].copy_from_slice(&b_bytes[..16]);
        b_hi_bytes[..16].copy_from_slice(&b_bytes[16..]);

        let b_lo = Scalar::from_canonical_bytes_unchecked(b_lo_bytes);
        let b_hi = Scalar::from_canonical_bytes_unchecked(b_hi_bytes);

        // Compute NAF representations (all scalars are now ~128 bits)
        let a1_naf = a1.non_adjacent_form(DYNAMIC_NAF_WINDOW);
        let a2_naf = a2.non_adjacent_form(DYNAMIC_NAF_WINDOW);
        let b_lo_naf = b_lo.non_adjacent_form(B_LO_NAF_WINDOW);
        let b_hi_naf = b_hi.non_adjacent_form(DYNAMIC_NAF_WINDOW);

        // Find starting index - check all NAFs up to bit 127
        // (with potential carry to bit 128 or 129)
        let mut i: usize = HEEA_MAX_INDEX;
        for j in (0..=HEEA_MAX_INDEX).rev() {
            i = j;
            if a1_naf[i] != 0 || a2_naf[i] != 0 || b_lo_naf[i] != 0 || b_hi_naf[i] != 0 {
                break;
            }
        }

        // Create lookup tables using SIMD-optimized CachedPoint
        let table_A1 = NafLookupTable5::<CachedPoint>::from(A1);
        let table_A2 = NafLookupTable5::<CachedPoint>::from(A2);

        #[cfg(feature = "precomputed-tables")]
        let table_B = &BASEPOINT_ODD_LOOKUP_TABLE;
        #[cfg(not(feature = "precomputed-tables"))]
        let table_B = &NafLookupTable5::<CachedPoint>::from(&constants::ED25519_BASEPOINT_POINT);

        // B' = B * 2^128.
        let table_B_128 = &BASEPOINT_128_ODD_LOOKUP_TABLE;

        let mut Q = ExtendedPoint::identity();

        loop {
            Q = Q.double();

            // Add contributions from a1*A1
            match a1_naf[i].cmp(&0) {
                Ordering::Greater => {
                    Q = &Q + &table_A1.select(a1_naf[i] as usize);
                }
                Ordering::Less => {
                    Q = &Q - &table_A1.select(-a1_naf[i] as usize);
                }
                Ordering::Equal => {}
            }

            // Add contributions from a2*A2
            match a2_naf[i].cmp(&0) {
                Ordering::Greater => {
                    Q = &Q + &table_A2.select(a2_naf[i] as usize);
                }
                Ordering::Less => {
                    Q = &Q - &table_A2.select(-a2_naf[i] as usize);
                }
                Ordering::Equal => {}
            }

            // Add contributions from b_lo*B
            match b_lo_naf[i].cmp(&0) {
                Ordering::Greater => {
                    Q = &Q + &table_B.select(b_lo_naf[i] as usize);
                }
                Ordering::Less => {
                    Q = &Q - &table_B.select(-b_lo_naf[i] as usize);
                }
                Ordering::Equal => {}
            }

            // Add contributions from b_hi*B' where B' = B * 2^128
            match b_hi_naf[i].cmp(&0) {
                Ordering::Greater => {
                    Q = &Q + &table_B_128.select(b_hi_naf[i] as usize);
                }
                Ordering::Less => {
                    Q = &Q - &table_B_128.select(-b_hi_naf[i] as usize);
                }
                Ordering::Equal => {}
            }

            if i == 0 {
                break;
            }
            i -= 1;
        }

        Q.into()
    }
}

#[cfg(all(test, target_arch = "x86_64"))]
mod test {
    use super::spec_avx2;
    use crate::backend::serial;
    use crate::constants;
    use crate::scalar::Scalar;

    fn scalar_from_low_128(low: [u8; 16]) -> Scalar {
        let mut bytes = [0u8; 32];
        bytes[..16].copy_from_slice(&low);
        Scalar::from_canonical_bytes(bytes).unwrap()
    }

    #[test]
    fn avx2_triple_base_matches_serial_and_naive() {
        if !std::is_x86_feature_detected!("avx2") {
            return;
        }

        let a1 = scalar_from_low_128([
            0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22,
            0x11, 0x00,
        ]);
        let a2 = scalar_from_low_128([
            0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe, 0x0f, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a,
            0x69, 0x78,
        ]);
        let b = Scalar::from_bytes_mod_order([
            0x42, 0x91, 0x0a, 0xbe, 0xef, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
            0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
            0x10, 0x20, 0x30, 0x40,
        ]);

        let A1 = constants::ED25519_BASEPOINT_POINT * Scalar::from(31u64);
        let A2 = constants::ED25519_BASEPOINT_POINT * Scalar::from(37u64);

        let avx2 = spec_avx2::mul_128_128_256_prechecked(&a1, &A1, &a2, &A2, &b);
        let serial = serial::scalar_mul::vartime_triple_base::mul_128_128_256_prechecked(
            &a1, &A1, &a2, &A2, &b,
        );
        let expected = (a1 * A1 + a2 * A2) + b * constants::ED25519_BASEPOINT_POINT;

        assert_eq!(avx2, serial);
        assert_eq!(avx2, expected);
    }
}
