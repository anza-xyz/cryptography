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

    /// Compute \\(a_1 A_1 + a_2 A_2 + b B\\) with the optimized 128/128/256-bit path.
    ///
    /// Callers must ensure \\(a_1\\) and \\(a_2\\) are less than \\(2^{128}\\).
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
        let a1_naf = a1.non_adjacent_form(5);
        let a2_naf = a2.non_adjacent_form(5);

        #[cfg(feature = "precomputed-tables")]
        let b_lo_naf = b_lo.non_adjacent_form(8);
        #[cfg(not(feature = "precomputed-tables"))]
        let b_lo_naf = b_lo.non_adjacent_form(5);

        let b_hi_naf = b_hi.non_adjacent_form(5);

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
