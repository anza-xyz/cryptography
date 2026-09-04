// -*- mode: rust; -*-
//
// This file is part of curve25519-sol.
// Copyright (c) 2026 curve25519-sol contributors
// See LICENSE for licensing information.

#![allow(non_snake_case)]

use super::field_x8::{FieldElementX8, LANES, LaneMask, sqrt_ratio_i_x8};
use crate::backend::serial::curve_models::AffineNielsPoint;
use crate::backend::serial::u64::constants::{EDWARDS_D, EDWARDS_D2};
#[cfg(test)]
use crate::edwards::EdwardsPoint;

/// Eight extended-coordinate points \\((X : Y : Z : T)\\), one per lane.
#[derive(Copy, Clone, Debug)]
pub(crate) struct ExtendedPointX8 {
    pub(crate) X: FieldElementX8,
    pub(crate) Y: FieldElementX8,
    pub(crate) Z: FieldElementX8,
    pub(crate) T: FieldElementX8,
}

/// Eight points in completed form, the output of the addition and doubling formulas.
#[derive(Copy, Clone, Debug)]
pub(crate) struct CompletedPointX8 {
    pub(crate) X: FieldElementX8,
    pub(crate) Y: FieldElementX8,
    pub(crate) Z: FieldElementX8,
    pub(crate) T: FieldElementX8,
}

/// Eight projective points \\((X : Y : Z)\\), used on the doubling chain.
#[derive(Copy, Clone, Debug)]
pub(crate) struct ProjectivePointX8 {
    pub(crate) X: FieldElementX8,
    pub(crate) Y: FieldElementX8,
    pub(crate) Z: FieldElementX8,
}

/// Eight cached ("projective Niels") points for readdition.
#[derive(Copy, Clone, Debug)]
pub(crate) struct ProjectiveNielsX8 {
    pub(crate) Y_plus_X: FieldElementX8,
    pub(crate) Y_minus_X: FieldElementX8,
    pub(crate) Z: FieldElementX8,
    pub(crate) T2d: FieldElementX8,
}

impl ExtendedPointX8 {
    pub(crate) const IDENTITY: ExtendedPointX8 = ExtendedPointX8 {
        X: FieldElementX8::ZERO,
        Y: FieldElementX8::ONE,
        Z: FieldElementX8::ONE,
        T: FieldElementX8::ZERO,
    };

    /// Gather eight serial points into lanes.
    #[cfg(test)]
    pub(crate) fn from_lanes(points: &[EdwardsPoint; LANES]) -> ExtendedPointX8 {
        ExtendedPointX8 {
            X: FieldElementX8::from_lanes(&core::array::from_fn(|l| points[l].X)),
            Y: FieldElementX8::from_lanes(&core::array::from_fn(|l| points[l].Y)),
            Z: FieldElementX8::from_lanes(&core::array::from_fn(|l| points[l].Z)),
            T: FieldElementX8::from_lanes(&core::array::from_fn(|l| points[l].T)),
        }
    }

    /// Extract lane `l` as a serial point.
    #[cfg(test)]
    pub(crate) fn lane(&self, l: usize) -> EdwardsPoint {
        EdwardsPoint {
            X: self.X.lane(l),
            Y: self.Y.lane(l),
            Z: self.Z.lane(l),
            T: self.T.lane(l),
        }
    }

    pub(crate) fn as_projective(&self) -> ProjectivePointX8 {
        ProjectivePointX8 {
            X: self.X,
            Y: self.Y,
            Z: self.Z,
        }
    }

    pub(crate) fn to_projective_niels(self) -> ProjectiveNielsX8 {
        ProjectiveNielsX8 {
            Y_plus_X: self.Y.add(&self.X),
            Y_minus_X: self.Y.sub(&self.X),
            Z: self.Z,
            T2d: self.T.mul(&FieldElementX8::splat(EDWARDS_D2)),
        }
    }

    /// Add a cached point (mixed readdition), lane-wise.
    pub(crate) fn add(&self, other: &ProjectiveNielsX8) -> CompletedPointX8 {
        let Y_plus_X = self.Y.add(&self.X);
        let Y_minus_X = self.Y.sub(&self.X);
        let PP = Y_plus_X.mul(&other.Y_plus_X);
        let MM = Y_minus_X.mul(&other.Y_minus_X);
        let TT2d = self.T.mul(&other.T2d);
        let ZZ = self.Z.mul(&other.Z);
        let ZZ2 = ZZ.add(&ZZ);

        CompletedPointX8 {
            X: PP.sub(&MM),
            Y: PP.add(&MM),
            Z: ZZ2.add(&TT2d),
            T: ZZ2.sub(&TT2d),
        }
    }

    /// Compute \\([2^k] P\\) lane-wise by successive doublings.
    pub(crate) fn mul_by_pow_2(&self, k: u32) -> ExtendedPointX8 {
        debug_assert!(k > 0);
        let mut r: CompletedPointX8;
        let mut s = self.as_projective();
        for _ in 0..(k - 1) {
            r = s.double();
            s = r.as_projective();
        }
        s.double().as_extended()
    }

    /// `true` for lanes holding the identity: \\(X = 0\\) and \\(Y = Z\\).
    pub(crate) fn is_identity_lanes(&self) -> LaneMask {
        let x_zero = self.X.is_zero_lanes();
        let y_eq_z = self.Y.sub(&self.Z).is_zero_lanes();
        core::array::from_fn(|l| x_zero[l] && y_eq_z[l])
    }
}

impl CompletedPointX8 {
    pub(crate) fn as_projective(&self) -> ProjectivePointX8 {
        ProjectivePointX8 {
            X: self.X.mul(&self.T),
            Y: self.Y.mul(&self.Z),
            Z: self.Z.mul(&self.T),
        }
    }

    pub(crate) fn as_extended(&self) -> ExtendedPointX8 {
        ExtendedPointX8 {
            X: self.X.mul(&self.T),
            Y: self.Y.mul(&self.Z),
            Z: self.Z.mul(&self.T),
            T: self.X.mul(&self.Y),
        }
    }
}

impl ProjectivePointX8 {
    pub(crate) fn double(&self) -> CompletedPointX8 {
        let XX = self.X.square();
        let YY = self.Y.square();
        let ZZ2 = self.Z.square2();
        let X_plus_Y = self.X.add(&self.Y);
        let X_plus_Y_sq = X_plus_Y.square();
        let YY_plus_XX = YY.add(&XX);
        let YY_minus_XX = YY.sub(&XX);

        CompletedPointX8 {
            X: X_plus_Y_sq.sub(&YY_plus_XX),
            Y: YY_plus_XX,
            Z: YY_minus_XX,
            T: ZZ2.sub(&YY_minus_XX),
        }
    }
}

impl ProjectiveNielsX8 {
    /// The identity as a cached point: adding it leaves a point unchanged.
    pub(crate) const IDENTITY: ProjectiveNielsX8 = ProjectiveNielsX8 {
        Y_plus_X: FieldElementX8::ONE,
        Y_minus_X: FieldElementX8::ONE,
        Z: FieldElementX8::ONE,
        T2d: FieldElementX8::ZERO,
    };

    /// Copy a single lane from `src` into lane `l` of `self`.
    fn copy_lane(&mut self, l: usize, src: &ProjectiveNielsX8) {
        for i in 0..5 {
            self.Y_plus_X.limbs[i][l] = src.Y_plus_X.limbs[i][l];
            self.Y_minus_X.limbs[i][l] = src.Y_minus_X.limbs[i][l];
            self.Z.limbs[i][l] = src.Z.limbs[i][l];
            self.T2d.limbs[i][l] = src.T2d.limbs[i][l];
        }
    }

    /// Negate the marked lanes: swap \\(Y + X\\) with \\(Y - X\\), negate \\(2dT\\).
    fn negate_lanes(&self, negate: &LaneMask) -> ProjectiveNielsX8 {
        let neg_T2d = self.T2d.neg();
        let mut out = *self;
        for (l, neg) in negate.iter().enumerate() {
            if *neg {
                for i in 0..5 {
                    out.Y_plus_X.limbs[i][l] = self.Y_minus_X.limbs[i][l];
                    out.Y_minus_X.limbs[i][l] = self.Y_plus_X.limbs[i][l];
                    out.T2d.limbs[i][l] = neg_T2d.limbs[i][l];
                }
            }
        }
        out
    }
}

/// Per-lane `[P, 2P, ..., 8P]` for eight base points, indexed by a signed
/// radix-16 digit in \\([-8, 8]\\).
pub(crate) struct LookupTableX8(pub(crate) [ProjectiveNielsX8; 8]);

/// Assemble a per-lane table from eight keys' cached affine multiples: entry
/// `j`, lane `l` holds `[(j+1)]A_l`, with `Z` one in every lane.
pub(crate) fn table_from_affine_lanes(keys: &[&[AffineNielsPoint; 8]; LANES]) -> LookupTableX8 {
    let mut out = LookupTableX8([ProjectiveNielsX8::IDENTITY; 8]);
    for (j, entry) in out.0.iter_mut().enumerate() {
        entry.Z = FieldElementX8::ONE;
        for (l, key) in keys.iter().enumerate() {
            let a = &key[j];
            for i in 0..5 {
                entry.Y_plus_X.limbs[i][l] = a.y_plus_x.0[i];
                entry.Y_minus_X.limbs[i][l] = a.y_minus_x.0[i];
                entry.T2d.limbs[i][l] = a.xy2d.0[i];
            }
        }
    }
    out
}

impl LookupTableX8 {
    /// Build `[P, 2P, ..., 8P]` for all lanes at once.
    pub(crate) fn from_extended(P: &ExtendedPointX8) -> LookupTableX8 {
        let mut points = [P.to_projective_niels(); 8];
        for j in 0..7 {
            points[j + 1] = P.add(&points[j]).as_extended().to_projective_niels();
        }
        LookupTableX8(points)
    }

    /// Select, per lane, the entry for a signed radix-16 digit: `d > 0` yields
    /// \\([d]P\\), `d < 0` yields \\(-[|d|]P\\), and `0` yields the identity.
    pub(crate) fn select(&self, digits: &[i8; LANES]) -> ProjectiveNielsX8 {
        let mut out = ProjectiveNielsX8::IDENTITY;
        let mut negate: LaneMask = [false; LANES];
        for l in 0..LANES {
            let d = digits[l];
            if d != 0 {
                let idx = (d.unsigned_abs() as usize) - 1;
                debug_assert!(idx < 8);
                out.copy_lane(l, &self.0[idx]);
                negate[l] = d < 0;
            }
        }
        out.negate_lanes(&negate)
    }
}

/// Decompress eight encodings lane-wise with ZIP-215 semantics, as
/// `CompressedEdwardsY::decompress` does.
///
/// Lanes that are not valid curve points are reported `false` and hold the identity.
pub(crate) fn decompress_x8(encodings: &[[u8; 32]; LANES]) -> (ExtendedPointX8, LaneMask) {
    let Y = FieldElementX8::from_lanes(&core::array::from_fn(|l| {
        crate::backend::serial::u64::field::FieldElement51::from_bytes(&encodings[l])
    }));
    let Z = FieldElementX8::ONE;
    let YY = Y.square();
    let u = YY.sub(&Z); // u = y^2 - 1
    let v = YY.mul(&FieldElementX8::splat(EDWARDS_D)).add(&Z); // v = dy^2 + 1
    let (is_valid, X) = sqrt_ratio_i_x8(&u, &v);

    // sqrt_ratio returns the nonnegative root; apply the encoded sign bit.
    let sign_bits: LaneMask = core::array::from_fn(|l| encodings[l][31] >> 7 == 1);
    let X = X.negate_lanes(&sign_bits);

    let point = ExtendedPointX8 {
        T: X.mul(&Y),
        X,
        Y,
        Z,
    };

    // Park invalid lanes at the identity.
    let mut out = ExtendedPointX8::IDENTITY;
    let keep: LaneMask = is_valid;
    out.X = out.X.select_lanes(&point.X, &keep);
    out.Y = out.Y.select_lanes(&point.Y, &keep);
    out.Z = out.Z.select_lanes(&point.Z, &keep);
    out.T = out.T.select_lanes(&point.T, &keep);

    (out, is_valid)
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::constants::ED25519_BASEPOINT_POINT;
    use crate::edwards::CompressedEdwardsY;
    use crate::scalar::Scalar;
    use crate::traits::Identity;

    fn test_points(seed: u64) -> [EdwardsPoint; LANES] {
        core::array::from_fn(|l| {
            let mut bytes = [0u8; 32];
            bytes[..8].copy_from_slice(&(seed.wrapping_mul(1 + l as u64)).to_le_bytes());
            bytes[8] = 1;
            ED25519_BASEPOINT_POINT * Scalar::from_bytes_mod_order(bytes)
        })
    }

    fn assert_lanes_eq(x8: &ExtendedPointX8, expected: &[EdwardsPoint; LANES], what: &str) {
        for (l, expected) in expected.iter().enumerate() {
            assert_eq!(
                x8.lane(l).compress(),
                expected.compress(),
                "{what} lane {l}"
            );
        }
    }

    // lane-wise add, double and mul_by_pow_2 match the serial point ops
    #[test]
    fn add_double_match_serial() {
        let ps = test_points(11);
        let qs = test_points(23);
        let P = ExtendedPointX8::from_lanes(&ps);
        let Q = ExtendedPointX8::from_lanes(&qs);

        let sum = P.add(&Q.to_projective_niels()).as_extended();
        let expected_sum: [EdwardsPoint; LANES] = core::array::from_fn(|l| ps[l] + qs[l]);
        assert_lanes_eq(&sum, &expected_sum, "add");

        let doubled = P.as_projective().double().as_extended();
        let expected_dbl: [EdwardsPoint; LANES] = core::array::from_fn(|l| ps[l].double());
        assert_lanes_eq(&doubled, &expected_dbl, "double");

        let by8 = P.mul_by_pow_2(3);
        let expected_by8: [EdwardsPoint; LANES] = core::array::from_fn(|l| ps[l].mul_by_pow_2(3));
        assert_lanes_eq(&by8, &expected_by8, "mul_by_pow_2");
    }

    // a table select yields the signed multiple the digit names, per lane
    #[test]
    fn table_select_matches_serial_multiples() {
        let ps = test_points(37);
        let P = ExtendedPointX8::from_lanes(&ps);
        let table = LookupTableX8::from_extended(&P);

        // A spread of digits, including 0 and both signs.
        let digits: [i8; LANES] = [0, 1, -1, 8, -8, 3, -5, 7];
        let selected = ExtendedPointX8::IDENTITY
            .add(&table.select(&digits))
            .as_extended();

        for l in 0..LANES {
            let expected = if digits[l] == 0 {
                EdwardsPoint::identity()
            } else {
                let m = ps[l] * Scalar::from(digits[l].unsigned_abs() as u64);
                if digits[l] < 0 { -m } else { m }
            };
            assert_eq!(
                selected.lane(l).compress(),
                expected.compress(),
                "digit {} lane {l}",
                digits[l]
            );
        }
    }

    // lane-wise decompression matches the serial one, invalid lanes included
    #[test]
    fn decompress_matches_serial() {
        let ps = test_points(53);
        let mut encodings: [[u8; 32]; LANES] =
            core::array::from_fn(|l| ps[l].compress().to_bytes());

        // Lane 2: flipped sign bit. Lane 4: invalid point. Lane 6: identity.
        encodings[2][31] ^= 1 << 7;
        encodings[4] = [0x05; 32];
        encodings[6] = CompressedEdwardsY::identity().to_bytes();

        let (points, valid) = decompress_x8(&encodings);

        for l in 0..LANES {
            match CompressedEdwardsY(encodings[l]).decompress() {
                Some(expected) => {
                    assert!(valid[l], "lane {l} should be valid");
                    assert_eq!(
                        points.lane(l).compress(),
                        expected.compress(),
                        "decompress lane {l}"
                    );
                }
                None => assert!(!valid[l], "lane {l} should be invalid"),
            }
        }

        let id = points.is_identity_lanes();
        assert!(id[6], "identity lane detected");
        assert!(!id[0], "non-identity lane not flagged");
    }
}
