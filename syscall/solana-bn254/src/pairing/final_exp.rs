//! BN254 final exponentiation with the Arkworks 0.5 normalization.
//!
//! With x=4965661367192848881, E=(q^12-1)/r and c=2*x*(6*x^2+3*x+1),
//! the result is f^(c*E). The easy part is (q^6-1)*(q^2+1), followed
//! by the fixed hard chain c*(q^4-q^2+1)/r. See
//! <https://github.com/arkworks-rs/algebra/blob/v0.5.0/ec/src/models/bn/mod.rs>.

use crate::backend::{Fq2, Fq6, Fq12, fq6::mul_by_xi};
use core::ops::Mul;

/// Only final exponentiation can construct this proof of order-r membership.
/// It lets Gt accept the result without repeating a subgroup check.
pub(crate) struct FinalExponentiation(Fq12);

impl FinalExponentiation {
    pub(crate) fn into_fq12(self) -> Fq12 {
        self.0
    }
}

/// Nonzero elements of the subgroup of order q^4-q^2+1.
/// This contains Gt; entry requires verification, the easy final exponent,
/// or a validated Gt.
#[derive(Clone, Copy)]
struct Cyclotomic(Fq12);

/// Five-coefficient variant derived from the Granger-Scott square below.
/// For f=(a0+a1*v+a2*v^2)+(b0+b1*v+b2*v^2)*w, retain b1 as well as
/// a1, a2, b0, b2. Related four-coefficient compression is described in
/// Karabina section 5.6: <https://eprint.iacr.org/2010/542>.
///
/// Write xi=9+u. The cyclotomic identities used here are
///   a0 = 1 + xi*(2*b1^2 + b0*b2 - 3*a1*a2),
///   (2*a0+1)*b1 = b0*a1 + xi*a2*b2.
/// Granger-Scott gives a1'=3*(b0^2+xi*a2^2)-2*a1,
/// a2'=3*(a1^2+xi*b2^2)-2*a2, b0'=6*xi*a1*b2+2*b0,
/// b2'=6*b0*a2+2*b2, and b1'=6*a0*b1+2*b1.
/// Substitute the second identity to get b1'=3*(b0*a1+xi*a2*b2)-b1.
/// Thus every retained coefficient can be squared without a0; the first
/// identity reconstructs it without division, including when b1 is zero.
#[derive(Clone, Copy)]
struct CompressedCyclotomic {
    a1: Fq2,
    a2: Fq2,
    b0: Fq2,
    b1: Fq2,
    b2: Fq2,
}

/// Returns `3*t - 2*z`.
fn minus(t: Fq2, z: Fq2) -> Fq2 {
    let difference = t - z;
    difference + difference + t
}

/// Returns `3*t + 2*z`.
fn plus(t: Fq2, z: Fq2) -> Fq2 {
    let sum = t + z;
    sum + sum + t
}

impl CompressedCyclotomic {
    fn new(value: Cyclotomic) -> Self {
        Self {
            a1: value.0.c0.c1,
            a2: value.0.c0.c2,
            b0: value.0.c1.c0,
            b1: value.0.c1.c1,
            b2: value.0.c1.c2,
        }
    }

    fn square(self) -> Self {
        let p = self.b0 * self.a2;
        let q = self.a1 * self.b2;
        let xi_a2 = mul_by_xi(self.a2);
        let xi_p = mul_by_xi(p);
        let xi_q = mul_by_xi(q);
        // Expand and cancel p=b0*a2 and q=a1*b2:
        // u=b0^2+xi*a2^2, v=a1^2+xi*b2^2,
        // cross=b0*a1+xi*a2*b2.
        let u = (self.b0 + self.a2) * (self.b0 + xi_a2) - p - xi_p;
        let v = (self.a1 + self.b2) * (self.a1 + mul_by_xi(self.b2)) - q - xi_q;
        let cross = (self.b0 + self.b2) * (self.a1 + xi_a2) - q - xi_p;
        Self {
            a1: minus(u, self.a1),
            a2: minus(v, self.a2),
            b0: plus(xi_q + xi_q, self.b0),
            b1: cross + cross + cross - self.b1,
            b2: plus(p + p, self.b2),
        }
    }

    fn decompress(self) -> Cyclotomic {
        let b1_squared = self.b1.square();
        let a1_a2 = self.a1 * self.a2;
        let inner = b1_squared + b1_squared + self.b0 * self.b2 - (a1_a2 + a1_a2 + a1_a2);
        let a0 = Fq2::ONE + mul_by_xi(inner);
        Cyclotomic(Fq12::new(
            Fq6::new(a0, self.a1, self.a2),
            Fq6::new(self.b0, self.b1, self.b2),
        ))
    }
}

impl Cyclotomic {
    /// For nonzero f, f^(q^4)*f = f^(q^2) iff f^(q^4-q^2+1) = 1.
    /// Zero also satisfies the undivided equality, so reject it explicitly.
    fn verified(value: Fq12) -> Option<Self> {
        (value != Fq12::ZERO && value.frobenius(4) * value == value.frobenius(2))
            .then_some(Self(value))
    }

    fn easy_part(value: Fq12) -> Option<Self> {
        let norm_one = value.conjugate() * value.inverse()?;
        Some(Self(norm_one.frobenius(2) * norm_one))
    }

    fn inverse(self) -> Self {
        Self(self.0.conjugate())
    }

    fn frobenius(self, power: usize) -> Self {
        Self(self.0.frobenius(power))
    }

    /// Granger-Scott squaring, valid only in the cyclotomic subgroup.
    /// <https://eprint.iacr.org/2009/565>
    fn square(self) -> Self {
        fn fp4_square(a: Fq2, b: Fq2) -> (Fq2, Fq2) {
            let ab = a * b;
            ((a + b) * (a + mul_by_xi(b)) - ab - mul_by_xi(ab), ab + ab)
        }
        let a = self.0.c0;
        let b = self.0.c1;
        let (t0, t1) = fp4_square(a.c0, b.c1);
        let (t2, t3) = fp4_square(b.c0, a.c2);
        let (t4, t5) = fp4_square(a.c1, b.c2);
        Self(Fq12::new(
            Fq6::new(minus(t0, a.c0), minus(t2, a.c1), minus(t4, a.c2)),
            Fq6::new(plus(mul_by_xi(t5), b.c0), plus(t1, b.c1), plus(t3, b.c2)),
        ))
    }

    fn square_run(self, count: u8) -> Self {
        let mut compressed = CompressedCyclotomic::new(self);
        for _ in 0..count {
            compressed = compressed.square();
        }
        compressed.decompress()
    }

    fn exp_by_neg_x(self) -> Self {
        // The 62-square, 17-multiply chain generated with addchain v0.4.0 in
        // gnark-crypto v0.12.1 (also used by Firedancer's fd_bn254_fp12_pow_x):
        // https://github.com/Consensys/gnark-crypto/blob/v0.12.1/ecc/bn254/internal/fptower/e12_pairing.go
        // Evaluate it at f^-1 and compress the longer square runs.
        let base = self.inverse();
        let mut t3 = base.square();
        let mut t5 = t3.square();
        let result = t5.square();
        let mut t0 = result.square();
        let mut t2 = t0 * base;
        t0 = t2 * t3;
        let mut t1 = t0 * base;
        let mut t4 = t2 * result;
        let t6 = t2.square();
        t1 = t1 * t0;
        t0 = t1 * t3;
        t5 = (t5 * t6.square_run(6) * t4).square_run(7);
        t4 = (t4 * t5).square_run(8) * t0;
        t3 = (t3 * t4).square_run(6);
        t2 = (t2 * t3).square_run(8) * t0;
        t2 = t2.square_run(6) * t0;
        t2 = t2.square_run(10);
        t1 = (t1 * t2).square_run(6);
        result * (t0 * t1)
    }
}

impl Mul for Cyclotomic {
    type Output = Self;
    fn mul(self, rhs: Self) -> Self {
        Self(self.0 * rhs.0)
    }
}

pub(crate) fn final_exponentiation(value: Fq12) -> Option<FinalExponentiation> {
    if value == Fq12::ONE {
        return Some(FinalExponentiation(Fq12::ONE));
    }
    let r = Cyclotomic::easy_part(value)?;
    // Fuentes-Castaneda et al. chain, in the Arkworks normalization.
    // Faster Hashing to G2, Section 4.1:
    // https://cacr.uwaterloo.ca/techreports/2011/cacr2011-26.pdf
    // Its exponent is
    // q^3*(12*x^3+6*x^2+4*x-1) + q^2*(12*x^3+6*x^2+6*x)
    // + q*(12*x^3+6*x^2+4*x) + (12*x^3+12*x^2+6*x+1).
    let y0 = r.exp_by_neg_x();
    let y1 = y0.square();
    let y2 = y1.square();
    let y3 = y2 * y1;
    let y4 = y3.exp_by_neg_x();
    let y5 = y4.square();
    let y6 = y5.exp_by_neg_x().inverse();
    let y7 = y6 * y4;
    let y8 = y7 * y3.inverse();
    let y9 = y8 * y1;
    let y10 = y8 * y4;
    let y11 = y10 * r;
    let y13 = y9.frobenius(1) * y11;
    let y14 = y8.frobenius(2) * y13;
    let result = (r.inverse() * y9).frobenius(3) * y14;
    Some(FinalExponentiation(result.0))
}

/// For nonzero f, q-r = 6*x^2 gives f^r = 1 iff f^q = f^(6*x^2).
/// Verify cyclotomic membership before using its specialized square and
/// inverse formulas. This cannot reject Gt because r divides q^4-q^2+1;
/// no exponent is reduced modulo r while checking membership.
pub(crate) fn is_in_target_group(value: Fq12) -> bool {
    let Some(f) = Cyclotomic::verified(value) else {
        return false;
    };
    let x2 = f.exp_by_neg_x().exp_by_neg_x();
    let two_x2 = x2.square();
    let six_x2 = two_x2.square() * two_x2;
    f.frobenius(1).0 == six_x2.0
}

/// Gt proves membership in the cyclotomic subgroup because r divides q^4-q^2+1.
#[inline]
pub(crate) fn square_gt(value: &crate::gt::Gt) -> Fq12 {
    Cyclotomic(value.to_fq12()).square().0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{backend::oracle::*, curve::g2::BN_X};
    use ark_bn254::{Bn254, Fq as ArkFq, Fq12 as ArkFq12, Fr as ArkFr};
    use ark_ec::pairing::{MillerLoopOutput, Pairing};
    use ark_ff::{AdditiveGroup, BigInteger, Field as _, PrimeField};
    use num_bigint::BigUint;
    use rand::{SeedableRng, rngs::StdRng};

    fn exponents() -> (BigUint, BigUint) {
        let q = BigUint::from_bytes_le(&ArkFq::MODULUS.to_bytes_le());
        let r = BigUint::from_bytes_le(&ArkFr::MODULUS.to_bytes_le());
        let x = BigUint::from(BN_X);
        let c = 2u8 * &x * (6u8 * x.pow(2) + 3u8 * &x + 1u8);
        let easy = (q.pow(6) - 1u8) * (q.pow(2) + 1u8);
        assert_eq!((&q * &q) % 6u8, BigUint::from(1u8));
        (easy, ((q.pow(12) - 1u8) / r) * c)
    }

    #[test]
    fn final_exponent_matches_generic_integer_power_and_arkworks() {
        assert!(final_exponentiation(Fq12::ZERO).is_none());
        let (_, exponent) = exponents();
        let mut rng = StdRng::seed_from_u64(0x7061_6972_6665_7631);
        for input in [ArkFq12::ONE, -ArkFq12::ONE]
            .into_iter()
            .chain((0..32).map(|_| random12(&mut rng)))
        {
            let expected = input.pow(exponent.to_u64_digits());
            assert_eq!(
                expected,
                Bn254::final_exponentiation(MillerLoopOutput(input))
                    .unwrap()
                    .0
            );
            let actual = final_exponentiation(ours12(input)).unwrap().into_fq12();
            check12(actual, expected);
            assert_eq!(expected.pow(ArkFr::MODULUS.0), ArkFq12::ONE);
            assert!(crate::gt::Gt::from_fq12(actual).is_some());
        }
    }

    #[test]
    fn cyclotomic_operations_match_generic_field_arithmetic() {
        let (easy, _) = exponents();
        assert!(Cyclotomic::easy_part(Fq12::ZERO).is_none());
        let mut rng = StdRng::seed_from_u64(0x6379_636c_6f5f_7631);
        for input in [ArkFq12::ONE]
            .into_iter()
            .chain((0..32).map(|_| random12(&mut rng)))
        {
            let mut expected = input.pow(easy.to_u64_digits());
            let mut actual = Cyclotomic::easy_part(ours12(input)).unwrap();
            check12(actual.0, expected);
            check12(actual.inverse().0, expected.inverse().unwrap());
            check12(
                actual.exp_by_neg_x().0,
                expected.pow([BN_X]).inverse().unwrap(),
            );
            for power in 0..12 {
                let mut image = expected;
                image.frobenius_map_in_place(power);
                check12(actual.frobenius(power).0, image);
            }
            for _ in 0..32 {
                actual = actual.square();
                expected.square_in_place();
                check12(actual.0, expected);
            }
        }
    }

    #[test]
    fn fixed_parameter_chains_match_generic_powers_beyond_gt() {
        let (easy, _) = exponents();
        let q = BigUint::from_bytes_le(&ArkFq::MODULUS.to_bytes_le());
        let cyclotomic_order = q.pow(4) - q.pow(2) + 1u8;
        let mut saw_non_gt = false;
        let mut rng = StdRng::seed_from_u64(0x626e_785f_6368_6e31);
        for input in [ArkFq12::ONE]
            .into_iter()
            .chain((0..64).map(|_| random12(&mut rng)))
        {
            let mut expected = input.pow(easy.to_u64_digits());
            assert_eq!(expected.pow(cyclotomic_order.to_u64_digits()), ArkFq12::ONE);
            saw_non_gt |= expected.pow(ArkFr::MODULUS.0) != ArkFq12::ONE;
            let mut actual = Cyclotomic::easy_part(ours12(input)).unwrap();
            check12(actual.0, expected);
            for _ in 0..4 {
                actual = actual.exp_by_neg_x();
                expected = expected.inverse().unwrap().pow([BN_X]);
                check12(actual.0, expected);
            }
        }
        assert!(saw_non_gt);
    }

    #[test]
    fn compressed_cyclotomic_squares_match_generic_field_arithmetic() {
        let (easy, _) = exponents();
        let q = BigUint::from_bytes_le(&ArkFq::MODULUS.to_bytes_le());
        let cyclotomic_order = q.pow(4) - q.pow(2) + 1u8;
        let mut rng = StdRng::seed_from_u64(0x636f_6d70_7371_7631);
        let mut inputs = std::vec![ArkFq12::ONE, -ArkFq12::ONE];
        // Sparse and boundary inputs supplement the random ones. They are
        // projected with Arkworks exponentiation rather than our easy part.
        let mut boundary = ArkFq12::ZERO;
        for (i, coefficient) in [
            &mut boundary.c0.c0,
            &mut boundary.c0.c1,
            &mut boundary.c0.c2,
            &mut boundary.c1.c0,
            &mut boundary.c1.c1,
            &mut boundary.c1.c2,
        ]
        .into_iter()
        .enumerate()
        {
            *coefficient = ark_bn254::Fq2::new(-ArkFq::ONE, -ArkFq::ONE);
            let mut sparse = ArkFq12::ONE;
            let coordinates = [
                &mut sparse.c0.c0,
                &mut sparse.c0.c1,
                &mut sparse.c0.c2,
                &mut sparse.c1.c0,
                &mut sparse.c1.c1,
                &mut sparse.c1.c2,
            ];
            *coordinates.into_iter().nth(i).unwrap() = *coefficient;
            inputs.push(sparse);
        }
        inputs.push(boundary);
        inputs.extend((0..64).map(|_| random12(&mut rng)));
        let mut saw_non_gt = false;
        for input in inputs {
            let mut expected = input.pow(easy.to_u64_digits());
            assert_eq!(expected.pow(cyclotomic_order.to_u64_digits()), ArkFq12::ONE);
            saw_non_gt |= expected.pow(ArkFr::MODULUS.0) != ArkFq12::ONE;
            let value = Cyclotomic(ours12(expected));
            for count in [3, 4, 5] {
                check12(value.square_run(count).0, expected.pow([1u64 << count]));
            }
            let mut compressed = CompressedCyclotomic::new(value);
            for _ in 0..32 {
                // Check the derivation's identities with Arkworks arithmetic.
                let a = expected.c0;
                let b = expected.c1;
                let xi = ark_bn254::Fq2::new(ArkFq::from(9), ArkFq::ONE);
                assert_eq!(
                    (a.c0 + a.c0 + ark_bn254::Fq2::ONE) * b.c1,
                    b.c0 * a.c1 + xi * a.c2 * b.c2
                );
                assert_eq!(
                    a.c0,
                    ark_bn254::Fq2::ONE
                        + xi * (b.c1.square().double() + b.c0 * b.c2
                            - (a.c1 * a.c2) * ark_bn254::Fq2::from(3))
                );
                check2(compressed.a1, expected.c0.c1);
                check2(compressed.a2, expected.c0.c2);
                check2(compressed.b0, expected.c1.c0);
                check2(compressed.b1, expected.c1.c1);
                check2(compressed.b2, expected.c1.c2);
                check12(compressed.decompress().0, expected);
                compressed = compressed.square();
                expected.square_in_place();
            }
            check12(compressed.decompress().0, expected);
        }
        assert!(saw_non_gt);
    }
}

#[cfg(test)]
mod subgroup_tests {
    use super::*;
    use crate::backend::Field as _;
    use crate::{backend::oracle::*, curve::g2::BN_X, gt::Gt};
    use ark_bn254::{Fq as ArkFq, Fq2 as ArkFq2, Fq6 as ArkFq6, Fq12 as ArkFq12, Fr as ArkFr};
    use ark_ff::{AdditiveGroup, BigInteger, Field as _, PrimeField};
    use num_bigint::BigUint;
    use rand::{SeedableRng, rngs::StdRng};

    fn parameters() -> (BigUint, BigUint, BigUint) {
        let q = BigUint::from_bytes_le(&ArkFq::MODULUS.to_bytes_le());
        let r = BigUint::from_bytes_le(&ArkFr::MODULUS.to_bytes_le());
        let phi = q.pow(4) - q.pow(2) + 1u8;
        (q, r, phi)
    }

    #[test]
    fn exact_bn_integer_identities() {
        let (q, r, phi) = parameters();
        let x = BigUint::from(BN_X);
        assert_eq!(
            q,
            36u8 * x.pow(4) + 36u8 * x.pow(3) + 24u8 * x.pow(2) + 6u8 * &x + 1u8
        );
        assert_eq!(
            r,
            36u8 * x.pow(4) + 36u8 * x.pow(3) + 18u8 * x.pow(2) + 6u8 * &x + 1u8
        );
        assert_eq!(&q - &r, 6u8 * x.pow(2));
        assert_eq!(&phi % &r, BigUint::from(0u8));
        assert_eq!((q.pow(2) + 1u8) * &phi, q.pow(6) + 1u8);
        assert_eq!(crate::backend::Fq::MODULUS.0, ArkFq::MODULUS.0);
        assert_eq!(crate::backend::Fr::MODULUS.0, ArkFr::MODULUS.0);
    }

    fn check(value: ArkFq12, phi: &BigUint) -> (bool, bool) {
        let nonzero = value != ArkFq12::ZERO;
        let expected_gt = nonzero && value.pow(ArkFr::MODULUS.0) == ArkFq12::ONE;
        let expected_cyclo = nonzero && value.pow(phi.to_u64_digits()) == ArkFq12::ONE;
        let input = ours12(value);
        assert_eq!(is_in_target_group(input), expected_gt);
        assert_eq!(Gt::from_fq12(input).is_some(), expected_gt);
        let verified = Cyclotomic::verified(input);
        assert_eq!(verified.is_some(), expected_cyclo);
        if let Some(f) = verified {
            // Compare every specialized stage with full-field Arkworks arithmetic.
            // In particular these checks also run on cyclotomic non-Gt elements.
            let negative_x = f.exp_by_neg_x();
            check12(negative_x.0, value.pow([BN_X]).inverse().unwrap());
            let x2 = negative_x.exp_by_neg_x();
            let x2_integer = BigUint::from(BN_X).pow(2);
            check12(x2.0, value.pow(x2_integer.to_u64_digits()));
            let two_x2 = x2.square();
            let six_x2 = two_x2.square() * two_x2;
            check12(six_x2.0, value.pow((6u8 * x2_integer).to_u64_digits()));
            check12(f.frobenius(1).0, value.pow(ArkFq::MODULUS.0));
        }
        (expected_gt, expected_cyclo)
    }

    #[test]
    fn predicate_and_chain_match_independent_field_powers() {
        let (q, r, phi) = parameters();
        let easy = (q.pow(6) - 1u8) * (q.pow(2) + 1u8);
        let target = (q.pow(12) - 1u8) / &r;
        for (value, expected) in [
            (ArkFq12::ZERO, (false, false)),
            (ArkFq12::ONE, (true, true)),
            (-ArkFq12::ONE, (false, false)),
        ] {
            assert_eq!(check(value, &phi), expected);
        }
        // All basis elements and their negatives, including proper subfields.
        for index in 0..12 {
            let mut coefficients = [ArkFq::ZERO; 12];
            coefficients[index] = ArkFq::ONE;
            let c: [ArkFq2; 6] =
                core::array::from_fn(|i| ArkFq2::new(coefficients[2 * i], coefficients[2 * i + 1]));
            let value = ArkFq12::new(ArkFq6::new(c[0], c[1], c[2]), ArkFq6::new(c[3], c[4], c[5]));
            check(value, &phi);
            check(-value, &phi);
        }
        // Every raw Montgomery coefficient q-1.
        let raw_boundary = -ArkFq::ONE * ArkFq::from(2).pow([256]).inverse().unwrap();
        let b = ArkFq2::new(raw_boundary, raw_boundary);
        let b = ArkFq6::new(b, b, b);
        check(ArkFq12::new(b, b), &phi);

        let mut rng = StdRng::seed_from_u64(0x7375_6267_7270_7631);
        for _ in 0..512 {
            check(random12(&mut rng), &phi);
        }
        for _ in 0..64 {
            let value = random12(&mut rng);
            let norm_one = ArkFq12::new(value.c0, -value.c1) * value.inverse().unwrap();
            assert_eq!(check(norm_one, &phi), (false, false));
            let cyclo = value.pow(easy.to_u64_digits());
            assert_eq!(check(cyclo, &phi), (false, true));
            let gt = value.pow(target.to_u64_digits());
            assert_ne!(gt, ArkFq12::ONE);
            assert_eq!(check(gt, &phi), (true, true));
            assert_eq!(check(-gt, &phi), (false, false));
        }
    }
}
