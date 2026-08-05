//! Short Weierstrass form utilities for Curve25519.
//!
//! This module provides a lightweight affine representation and conversion
//! utilities for moving between the Edwards and short Weierstrass models.

use core::ops::Add;

use crate::edwards::EdwardsPoint;
use crate::field::FieldElement;
use crate::traits::{Identity, IsIdentity};

/// Affine point on the short Weierstrass form of Curve25519.
///
/// Note: the SW coefficient `a` is non-zero, which means SPPARK must be
/// instantiated with a valid `a4` constant matching `sw_a()`.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum SwPoint {
    /// The point at infinity.
    Identity,
    /// An affine point with coordinates (x, y).
    Affine {
        /// x-coordinate.
        x: FieldElement,
        /// y-coordinate.
        y: FieldElement,
    },
}

impl SwPoint {
    /// Return the identity point.
    pub fn identity() -> Self {
        SwPoint::Identity
    }

    /// Convert an Edwards point into the short Weierstrass model.
    ///
    /// The Edwards and short-Weierstrass models are related by a birational
    /// map, so there are exceptional points that do not round-trip through
    /// both directions. In particular, the non-identity Edwards point
    /// `(0, -1)` maps to a short-Weierstrass affine point with `y == 0`;
    /// [`Self::to_edwards`] rejects that exceptional affine point.
    pub fn from_edwards(point: &EdwardsPoint) -> Self {
        if point.is_identity() {
            return SwPoint::Identity;
        }

        let z_inv = point.Z.invert();
        let x_affine = &point.X * &z_inv;
        let y_affine = &point.Y * &z_inv;
        let one = FieldElement::ONE;

        // Montgomery u = (1 + y) / (1 - y)
        let u = &(&one + &y_affine) * &(&one - &y_affine).invert();
        // Montgomery v = u / x, then scale to B=1 via sqrt(-486664)
        let v = &u * &x_affine.invert();
        let v = &montgomery_b_sqrt() * &v;

        let x = &u + &montgomery_a_over_three();
        let y = v;

        SwPoint::Affine { x, y }
    }

    /// Convert this point into an Edwards point, if defined.
    ///
    /// Returns `None` for affine coordinates that are not on the short-Weierstrass
    /// curve and for exceptional affine points where the birational map is
    /// undefined.
    pub fn to_edwards(&self) -> Option<EdwardsPoint> {
        match self {
            SwPoint::Identity => Some(EdwardsPoint::identity()),
            SwPoint::Affine { x, y } => {
                if !affine_coordinates_on_curve(x, y) {
                    return None;
                }
                if *y == FieldElement::ZERO {
                    return None;
                }

                let one = FieldElement::ONE;
                let u = x - &montgomery_a_over_three();
                let v = y * &montgomery_b_sqrt().invert();
                let v_inv = v.invert();

                // Edwards x = u / v
                let x_ed = &u * &v_inv;

                // Edwards y = (u - 1) / (u + 1)
                let denom = &u + &one;
                if denom == FieldElement::ZERO {
                    return None;
                }
                let denom_inv = denom.invert();
                let y_ed = &(&u - &one) * &denom_inv;

                Some(EdwardsPoint {
                    X: x_ed,
                    Y: y_ed,
                    Z: FieldElement::ONE,
                    T: &x_ed * &y_ed,
                })
            }
        }
    }

    /// Return affine coordinates as little-endian byte arrays.
    ///
    /// The point at infinity is encoded as the reserved all-zero pair.
    pub fn to_affine_le_bytes(&self) -> ([u8; 32], [u8; 32]) {
        match self {
            SwPoint::Identity => ([0u8; 32], [0u8; 32]),
            SwPoint::Affine { x, y } => (x.to_bytes(), y.to_bytes()),
        }
    }

    /// Build a point from affine little-endian byte arrays.
    ///
    /// The all-zero pair is reserved as the point-at-infinity encoding.
    pub fn from_affine_le_bytes(x: [u8; 32], y: [u8; 32]) -> Option<Self> {
        if x == [0u8; 32] && y == [0u8; 32] {
            return Some(SwPoint::Identity);
        }

        let x = FieldElement::from_bytes(&x);
        let y = FieldElement::from_bytes(&y);
        let point = SwPoint::Affine { x, y };
        if point.is_on_curve() {
            Some(point)
        } else {
            None
        }
    }

    /// Add two points in affine coordinates.
    pub fn add(&self, other: &SwPoint) -> SwPoint {
        match (self, other) {
            (SwPoint::Identity, _) => *other,
            (_, SwPoint::Identity) => *self,
            (SwPoint::Affine { x: x1, y: y1 }, SwPoint::Affine { x: x2, y: y2 }) => {
                if x1 == x2 {
                    if y1 == &(-y2) {
                        return SwPoint::Identity;
                    }
                    if y1 == y2 {
                        return double_affine(x1, y1);
                    }
                }

                let numerator = y2 - y1;
                let denominator = (x2 - x1).invert();
                let slope = &numerator * &denominator;
                let x3 = &(&slope.square() - x1) - x2;
                let y3 = &(&slope * &(x1 - &x3)) - y1;

                SwPoint::Affine { x: x3, y: y3 }
            }
        }
    }

    /// Check whether this point lies on the short Weierstrass curve.
    pub fn is_on_curve(&self) -> bool {
        match self {
            SwPoint::Identity => true,
            SwPoint::Affine { x, y } => affine_coordinates_on_curve(x, y),
        }
    }
}

impl<'a> Add<&'a SwPoint> for &SwPoint {
    type Output = SwPoint;

    fn add(self, other: &'a SwPoint) -> SwPoint {
        SwPoint::add(self, other)
    }
}

define_add_variants!(LHS = SwPoint, RHS = SwPoint, Output = SwPoint);

fn affine_coordinates_on_curve(x: &FieldElement, y: &FieldElement) -> bool {
    let y2 = y.square();
    let x2 = x.square();
    let x3 = &x2 * x;
    let rhs = &x3 + &(&sw_a() * x);
    y2 == &rhs + &sw_b()
}

fn double_affine(x: &FieldElement, y: &FieldElement) -> SwPoint {
    if *y == FieldElement::ZERO {
        return SwPoint::Identity;
    }

    let two = fe_from_u64(2);
    let three = fe_from_u64(3);
    let numerator = &(&three * &x.square()) + &sw_a();
    let denominator = (&two * y).invert();
    let slope = &numerator * &denominator;
    let x3 = &slope.square() - &(&two * x);
    let y3 = &(&slope * &(x - &x3)) - y;

    SwPoint::Affine { x: x3, y: y3 }
}

fn fe_from_u64(n: u64) -> FieldElement {
    let mut bytes = [0u8; 32];
    bytes[..8].copy_from_slice(&n.to_le_bytes());
    FieldElement::from_bytes(&bytes)
}

fn montgomery_a_over_three() -> FieldElement {
    let inv_three = fe_from_u64(3).invert();
    &montgomery_a() * &inv_three
}

/// Return the short Weierstrass curve coefficient a.
///
/// This value must match the `a4` constant provided to SPPARK templates.
pub(crate) fn sw_a() -> FieldElement {
    let one = FieldElement::ONE;
    let inv_three = fe_from_u64(3).invert();
    let a_sq = montgomery_a().square();
    &one - &(&a_sq * &inv_three)
}

/// Return the short Weierstrass curve coefficient b.
pub(crate) fn sw_b() -> FieldElement {
    let a = montgomery_a();
    let a2 = a.square();
    let a3 = &a2 * &a;
    let inv_three = fe_from_u64(3).invert();
    let inv_twenty_seven = &(&inv_three * &inv_three) * &inv_three;
    let two = fe_from_u64(2);

    &(&a3 * &(&two * &inv_twenty_seven)) - &(&a * &inv_three)
}

fn montgomery_a() -> FieldElement {
    fe_from_u64(486662)
}

fn montgomery_b_sqrt() -> FieldElement {
    FieldElement::from_bytes(&[
        0x06, 0x7e, 0x45, 0xff, 0xaa, 0x04, 0x6e, 0xcc, 0x82, 0x1a, 0x7d, 0x4b, 0xd1, 0xd3, 0xa1,
        0xc5, 0x7e, 0x4f, 0xfc, 0x03, 0xdc, 0x08, 0x7b, 0xd2, 0xbb, 0x06, 0xa0, 0x60, 0xf4, 0xed,
        0x26, 0x0f,
    ])
}

#[cfg(test)]
mod tests {
    use super::SwPoint;
    use super::{sw_a, sw_b};
    use crate::constants;
    use crate::edwards::EdwardsPoint;
    use crate::field::FieldElement;
    use crate::scalar::Scalar;
    use crate::traits::Identity;
    use rand::Rng;

    fn sw_scalar_mul(point: &SwPoint, scalar: &Scalar) -> SwPoint {
        let mut acc = SwPoint::Identity;
        let mut base = *point;
        let bytes = scalar.to_bytes();

        for i in 0..256 {
            let byte = bytes[i / 8];
            if ((byte >> (i % 8)) & 1) == 1 {
                acc = acc.add(&base);
            }
            base = base.add(&base);
        }

        acc
    }

    fn random_scalar<R: Rng + ?Sized>(rng: &mut R) -> Scalar {
        let mut wide = [0u8; 64];
        rng.fill_bytes(&mut wide);
        Scalar::from_bytes_mod_order_wide(&wide)
    }

    #[test]
    fn sw_add_operator_matches_inherent_add() {
        let p = SwPoint::from_edwards(&constants::ED25519_BASEPOINT_POINT);
        let q = SwPoint::from_edwards(&(constants::ED25519_BASEPOINT_POINT * Scalar::from(7u64)));
        let expected = p.add(&q);

        assert_eq!(
            <&SwPoint as core::ops::Add<&SwPoint>>::add(&p, &q),
            expected
        );
        assert_eq!(<SwPoint as core::ops::Add<&SwPoint>>::add(p, &q), expected);
        assert_eq!(<&SwPoint as core::ops::Add<SwPoint>>::add(&p, q), expected);
        assert_eq!(<SwPoint as core::ops::Add<SwPoint>>::add(p, q), expected);
    }

    #[test]
    fn sw_round_trip_add_matches_edwards() {
        let mut rng = rand::rng();

        for _ in 0..32 {
            let a = random_scalar(&mut rng);
            let b = random_scalar(&mut rng);
            let p = constants::ED25519_BASEPOINT_POINT * a;
            let q = constants::ED25519_BASEPOINT_POINT * b;

            let ed_sum = p + q;
            let sw_p = SwPoint::from_edwards(&p);
            let sw_q = SwPoint::from_edwards(&q);
            let sw_sum = sw_p.add(&sw_q);

            assert!(sw_sum.is_on_curve());
            let back = sw_sum.to_edwards().expect("sw->edwards should succeed");
            assert_eq!(back, ed_sum);

            let ed_double = p + p;
            let sw_double = sw_p.add(&sw_p);
            assert!(sw_double.is_on_curve());
            let back_double = sw_double.to_edwards().expect("sw->edwards should succeed");
            assert_eq!(back_double, ed_double);
        }
    }

    #[test]
    fn sw_scalar_mul_matches_edwards() {
        let mut rng = rand::rng();

        for _ in 0..32 {
            let s = random_scalar(&mut rng);
            let t = random_scalar(&mut rng);
            let p = constants::ED25519_BASEPOINT_POINT * s;

            let ed_result = p * t;
            let sw_p = SwPoint::from_edwards(&p);
            let sw_result = sw_scalar_mul(&sw_p, &t);

            assert!(sw_result.is_on_curve());
            let back = sw_result.to_edwards().expect("sw->edwards should succeed");
            assert_eq!(back, ed_result);
        }
    }

    #[test]
    fn sw_add_associativity() {
        let mut rng = rand::rng();

        for _ in 0..32 {
            let a = random_scalar(&mut rng);
            let b = random_scalar(&mut rng);
            let c = random_scalar(&mut rng);

            let p = SwPoint::from_edwards(&(constants::ED25519_BASEPOINT_POINT * a));
            let q = SwPoint::from_edwards(&(constants::ED25519_BASEPOINT_POINT * b));
            let r = SwPoint::from_edwards(&(constants::ED25519_BASEPOINT_POINT * c));

            let left = p.add(&q).add(&r);
            let right = p.add(&q.add(&r));

            assert!(left.is_on_curve());
            assert!(right.is_on_curve());
            assert_eq!(left, right);
        }
    }

    #[test]
    fn sw_scalar_mul_associativity_commutes() {
        let mut rng = rand::rng();
        let base = SwPoint::from_edwards(&constants::ED25519_BASEPOINT_POINT);

        for _ in 0..32 {
            let a = random_scalar(&mut rng);
            let b = random_scalar(&mut rng);
            let ab = a * b;

            let left = sw_scalar_mul(&base, &ab);
            let b_p = sw_scalar_mul(&base, &b);
            let a_p = sw_scalar_mul(&base, &a);
            let right1 = sw_scalar_mul(&b_p, &a);
            let right2 = sw_scalar_mul(&a_p, &b);

            assert!(left.is_on_curve());
            assert!(right1.is_on_curve());
            assert!(right2.is_on_curve());
            assert_eq!(left, right1);
            assert_eq!(left, right2);
        }
    }

    #[test]
    fn sw_constants_match_expected() {
        let expected_a = FieldElement::from_bytes(&[
            0x44, 0xa1, 0x14, 0x49, 0x98, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
            0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
            0xaa, 0xaa, 0xaa, 0x2a,
        ]);
        let expected_b = FieldElement::from_bytes(&[
            0x64, 0xc8, 0x10, 0x77, 0x9c, 0x5e, 0x0b, 0x26, 0xb4, 0x97, 0xd0, 0x5e, 0x42, 0x7b,
            0x09, 0xed, 0x25, 0xb4, 0x97, 0xd0, 0x5e, 0x42, 0x7b, 0x09, 0xed, 0x25, 0xb4, 0x97,
            0xd0, 0x5e, 0x42, 0x7b,
        ]);

        assert_eq!(sw_a(), expected_a);
        assert_eq!(sw_b(), expected_b);
    }

    #[test]
    fn sw_to_edwards_rejects_off_curve_affine_input() {
        let malformed = SwPoint::Affine {
            x: FieldElement::ZERO,
            y: FieldElement::ONE,
        };

        assert!(!malformed.is_on_curve());
        assert!(malformed.to_edwards().is_none());
    }

    #[test]
    fn sw_to_edwards_rejects_order_two_exception() {
        let order_two = EdwardsPoint {
            X: FieldElement::ZERO,
            Y: FieldElement::MINUS_ONE,
            Z: FieldElement::ONE,
            T: FieldElement::ZERO,
        };
        let sw = SwPoint::from_edwards(&order_two);

        assert!(sw.is_on_curve());
        let SwPoint::Affine { y, .. } = sw else {
            panic!("order-two point should map to affine");
        };
        assert_eq!(y, FieldElement::ZERO);
        assert!(sw.to_edwards().is_none());
    }

    #[test]
    fn sw_identity_affine_bytes_round_trip() {
        let encoded = SwPoint::Identity.to_affine_le_bytes();

        assert_eq!(encoded, ([0u8; 32], [0u8; 32]));
        assert_eq!(
            SwPoint::from_affine_le_bytes(encoded.0, encoded.1),
            Some(SwPoint::Identity)
        );
    }

    #[test]
    fn sw_affine_bytes_round_trip_valid_points() {
        let mut rng = rand::rng();

        for _ in 0..32 {
            let scalar = random_scalar(&mut rng);
            let point = constants::ED25519_BASEPOINT_POINT * scalar;
            let sw = SwPoint::from_edwards(&point);
            let encoded = sw.to_affine_le_bytes();

            assert_eq!(
                SwPoint::from_affine_le_bytes(encoded.0, encoded.1),
                Some(sw)
            );
        }
    }

    #[test]
    fn sw_affine_bytes_reject_off_curve_input() {
        let x = FieldElement::ZERO.to_bytes();
        let y = FieldElement::ONE.to_bytes();

        assert!(SwPoint::from_affine_le_bytes(x, y).is_none());
    }

    #[test]
    fn sw_identity_is_additive_neutral_element() {
        let base = SwPoint::from_edwards(&constants::ED25519_BASEPOINT_POINT);

        assert_eq!(SwPoint::identity().add(&base), base);
        assert_eq!(base.add(&SwPoint::identity()), base);
        assert_eq!(
            SwPoint::identity().to_edwards(),
            Some(EdwardsPoint::identity())
        );
    }
}
