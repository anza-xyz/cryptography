//! Sparse optimal-Ate Miller loop for BN254's D twist.
//!
//! Line formulas use homogeneous (X/Z, Y/Z) coordinates, distinct from the
//! Jacobian representation used by general G2 arithmetic. See
//! <https://eprint.iacr.org/2013/722> and the Arkworks 0.5 BN implementation:
//! <https://github.com/arkworks-rs/algebra/blob/v0.5.0/ec/src/models/bn/g2.rs>.
//! Moving the doubling line's factor of three to G1 and omitting the last
//! correction-point update follow Firedancer's pairing loop:
//! <https://github.com/firedancer-io/firedancer/blob/20c3fa1ff2dab737ec075c3e3e302ba778fd98fe/src/ballet/bn254/fd_bn254_pairing.c>.

use crate::{
    backend::{Backend, Fq, Fq2, Fq12, MontgomeryBackend, U256},
    curve::g2::{BN_X, CURVE_B, PSI_X, PSI_Y},
    g1, g2,
};

use super::PairingError;
use core::borrow::Borrow;

type B = Backend<Fq>;

const BATCH_SIZE: usize = 32;
// Signed binary expansion of 6*x+2, least significant digit first.
const ATE_DIGITS: [i8; 65] = [
    0, 0, 0, 1, 0, 1, 0, -1, 0, 0, -1, 0, 0, 0, 1, 0, 0, -1, 0, -1, 0, 0, 0, 1, 0, -1, 0, 0, 0, 0,
    -1, 0, 0, 1, 0, -1, 0, 0, 1, 0, 0, 0, 0, 0, -1, 0, 0, -1, 0, 1, 0, -1, 0, 0, 0, -1, 0, -1, 0,
    0, 0, 1, 0, 1, 1,
];

const _: () = {
    let mut value = 0i128;
    let mut i = ATE_DIGITS.len();
    while i > 0 {
        i -= 1;
        assert!(matches!(ATE_DIGITS[i], -1..=1));
        value = 2 * value + ATE_DIGITS[i] as i128;
    }
    assert!(value == 6 * BN_X as i128 + 2);
    assert!(ATE_DIGITS[ATE_DIGITS.len() - 1] == 1);
    assert!(ATE_DIGITS[ATE_DIGITS.len() - 2] != 0);
};

#[inline]
fn twice(value: Fq2) -> Fq2 {
    value + value
}

#[inline]
fn three(value: Fq2) -> Fq2 {
    twice(value) + value
}

#[inline]
fn mul_by_fq(value: Fq2, scalar: &U256) -> Fq2 {
    Fq2 {
        c0: B::mul(&value.c0, scalar),
        c1: B::mul(&value.c1, scalar),
    }
}

// The D-twist embedding gives y*P.y + x*P.x*w + constant*v*w.
struct Line {
    y: Fq2,
    x: Fq2,
    constant: Fq2,
}

impl Line {
    #[inline]
    fn evaluate(&self, p: &(U256, U256)) -> [Fq2; 3] {
        [
            mul_by_fq(self.y, &p.1),
            mul_by_fq(self.x, &p.0),
            self.constant,
        ]
    }

    #[cfg(test)]
    fn apply(&self, f: Fq12, p: &(U256, U256)) -> Fq12 {
        let c = self.evaluate(p);
        f.mul_by_034(&c[0], &c[1], &c[2])
    }
}

// A tangent line keeps X^2 unscaled so its factor of three can be applied
// to the base-field G1 coordinate instead of both Fq2 coefficients.
struct DoubleLine {
    y: Fq2,
    x_squared: Fq2,
    constant: Fq2,
}

impl DoubleLine {
    #[inline]
    fn evaluate(&self, p: &(U256, U256)) -> [Fq2; 3] {
        let triple_x = B::add(&B::add(&p.0, &p.0), &p.0);
        [
            mul_by_fq(self.y, &p.1),
            mul_by_fq(self.x_squared, &triple_x),
            self.constant,
        ]
    }

    #[cfg(test)]
    fn apply(&self, f: Fq12, p: &(U256, U256)) -> Fq12 {
        let c = self.evaluate(p);
        f.mul_by_034(&c[0], &c[1], &c[2])
    }

    #[cfg(test)]
    fn for_geometry(&self) -> Line {
        Line {
            y: self.y,
            x: three(self.x_squared),
            constant: self.constant,
        }
    }
}

#[derive(Clone, Copy)]
struct Homogeneous {
    x: Fq2,
    y: Fq2,
    z: Fq2,
}

impl Homogeneous {
    fn new(q: (Fq2, Fq2)) -> Self {
        Self {
            x: q.0,
            y: q.1,
            z: Fq2::ONE,
        }
    }

    /// Doubles a nonidentity order-r point and returns its tangent line.
    /// Such points have nonzero y because r is odd.
    fn double(&mut self) -> DoubleLine {
        let xy_half = (self.x * self.y).halve();
        let yy = self.y.square();
        let zz = self.z.square();
        let e = CURVE_B * three(zz);
        let e3 = three(e);
        let g = (yy + e3).halve();
        let h = (self.y + self.z).square() - yy - zz;
        let xx = self.x.square();
        self.x = xy_half * (yy - e3);
        self.y = g.square() - three(e.square());
        self.z = yy * h;
        DoubleLine {
            y: -h,
            x_squared: xx,
            constant: e - yy,
        }
    }

    /// Adds a finite affine point distinct from this point and its negative.
    /// The fixed Miller schedule satisfies these conditions for every nonzero
    /// order-r input; the scalar schedule proof is checked in the tests.
    fn add(&mut self, q: (Fq2, Fq2)) -> Line {
        let theta = self.y - q.1 * self.z;
        let lambda = self.x - q.0 * self.z;
        let theta2 = theta.square();
        let lambda2 = lambda.square();
        let lambda3 = lambda * lambda2;
        let f = self.z * theta2;
        let g = self.x * lambda2;
        let h = lambda3 + f - twice(g);
        self.x = lambda * h;
        self.y = theta * (g - h) - lambda3 * self.y;
        self.z = self.z * lambda3;
        Line {
            y: lambda,
            x: -theta,
            constant: theta * q.0 - lambda * q.1,
        }
    }

    /// Computes the mixed-addition line when the resulting point is unused.
    /// Has the same distinct-point preconditions as `add`.
    fn line_to(&self, q: (Fq2, Fq2)) -> Line {
        let theta = self.y - q.1 * self.z;
        let lambda = self.x - q.0 * self.z;
        Line {
            y: lambda,
            x: -theta,
            constant: theta * q.0 - lambda * q.1,
        }
    }
}

fn characteristic(q: (Fq2, Fq2)) -> (Fq2, Fq2) {
    (q.0.conjugate() * PSI_X, q.1.conjugate() * PSI_Y)
}

#[derive(Clone, Copy)]
struct Entry {
    // Own the active inputs so a decoder can produce one pair at a time.
    p: g1::Affine,
    q: g2::Affine,
    r: Homogeneous,
}

impl Entry {
    // Unused slots are never evaluated as points.
    const EMPTY: Self = Self {
        p: g1::Affine::IDENTITY,
        q: g2::Affine::IDENTITY,
        r: Homogeneous {
            x: Fq2::ZERO,
            y: Fq2::ZERO,
            z: Fq2::ZERO,
        },
    };

    fn new(p: g1::Affine, q: g2::Affine) -> Self {
        Self {
            p,
            q,
            r: Homogeneous::new(q.to_montgomery()),
        }
    }
}

/// A Miller-loop product; it does not yet establish target-group membership.
pub(super) struct MillerOutput(pub(super) Fq12);

pub(super) fn multi_miller_loop<P: Borrow<g1::Affine>, Q: Borrow<g2::Affine>, E>(
    pairs: impl IntoIterator<Item = Result<(P, Q), E>>,
) -> Result<MillerOutput, PairingError<E>> {
    let mut pairs = pairs.into_iter().fuse().peekable();
    let Some(pair) = pairs.next() else {
        return Ok(MillerOutput(Fq12::ONE));
    };
    let (p, q) = pair.map_err(PairingError::Input)?;
    // Keep single-pair calls outside the full Miller workspace.
    // Membership must still be established before skipping either identity.
    if pairs.peek().is_none() {
        if !q.borrow().is_in_correct_subgroup() {
            return Err(PairingError::InvalidG2);
        }
        if p.borrow().is_identity() || q.borrow().is_identity() {
            return Ok(MillerOutput(Fq12::ONE));
        }
        return Ok(MillerOutput(miller_batch(&mut [Entry::new(
            *p.borrow(),
            *q.borrow(),
        )])));
    }
    multi_miller_loop_batched(core::iter::once(Ok((p, q))).chain(pairs))
}

fn multi_miller_loop_batched<P: Borrow<g1::Affine>, Q: Borrow<g2::Affine>, E>(
    pairs: impl Iterator<Item = Result<(P, Q), E>>,
) -> Result<MillerOutput, PairingError<E>> {
    let mut product = None;
    let mut batch = [Entry::EMPTY; BATCH_SIZE];
    let mut len = 0;
    for pair in pairs {
        let (p, q) = pair.map_err(PairingError::Input)?;
        let (p, q) = (p.borrow(), q.borrow());
        // Validate Q even when P is identity. The fixed chain uses a common
        // denominator, so each check already avoids normalization inverses.
        if !q.is_in_correct_subgroup() {
            return Err(PairingError::InvalidG2);
        }
        if p.is_identity() || q.is_identity() {
            continue;
        }
        batch[len] = Entry::new(*p, *q);
        len += 1;
        if len == BATCH_SIZE {
            let next = miller_batch(&mut batch);
            product = Some(match product {
                Some(previous) => previous * next,
                None => next,
            });
            len = 0;
        }
    }
    if len != 0 {
        let next = miller_batch(&mut batch[..len]);
        product = Some(match product {
            Some(previous) => previous * next,
            None => next,
        });
    }
    Ok(MillerOutput(product.unwrap_or(Fq12::ONE)))
}

#[inline]
fn apply_line_pair(f: Fq12, a: [Fq2; 3], b: [Fq2; 3]) -> Fq12 {
    f.mul_by_01234(&Fq12::product_034(&a, &b))
}

fn miller_batch(entries: &mut [Entry]) -> Fq12 {
    let mut f = Fq12::ONE;
    for (step, &digit) in ATE_DIGITS.iter().rev().skip(1).enumerate() {
        if step != 0 {
            f = f.square();
        }
        if digit == 0 {
            // Independent tangent lines commute, so adjacent entries can
            // share a sparse-sparse multiplication.
            for chunk in entries.chunks_mut(2) {
                let first = chunk[0].r.double().evaluate(&chunk[0].p.to_montgomery());
                if chunk.len() == 2 {
                    let second = chunk[1].r.double().evaluate(&chunk[1].p.to_montgomery());
                    f = apply_line_pair(f, first, second);
                } else {
                    f = f.mul_by_034(&first[0], &first[1], &first[2]);
                }
            }
        } else {
            // Point updates remain in their original per-entry order.
            for (entry_index, entry) in entries.iter_mut().enumerate() {
                let p = entry.p.to_montgomery();
                let first = entry.r.double().evaluate(&p);
                let (qx, qy) = entry.q.to_montgomery();
                let q = if digit == 1 { (qx, qy) } else { (qx, -qy) };
                let second = entry.r.add(q).evaluate(&p);
                if step == 0 && entry_index == 0 {
                    // The first digit is nonzero. Assign its two-line product
                    // directly instead of multiplying it by the identity.
                    let c = Fq12::product_034(&first, &second);
                    f = Fq12::new(
                        crate::backend::Fq6::new(c[0], c[1], c[2]),
                        crate::backend::Fq6::new(c[3], c[4], Fq2::ZERO),
                    );
                } else {
                    f = apply_line_pair(f, first, second);
                }
            }
        }
    }
    for entry in entries.iter_mut() {
        let q1 = characteristic(entry.q.to_montgomery());
        let q2 = characteristic(q1);
        let p = entry.p.to_montgomery();
        let first = entry.r.add(q1).evaluate(&p);
        let second = entry.r.line_to((q2.0, -q2.1)).evaluate(&p);
        f = apply_line_pair(f, first, second);
    }
    f
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pairing::oracle::*;
    use ark_bn254::{
        Fq as ArkFq, Fq2 as ArkFq2, Fq6 as ArkFq6, Fq12 as ArkFq12, Fr as ArkFr, G2Affine,
    };
    use ark_ec::{AffineRepr, CurveGroup};
    use ark_ff::{AdditiveGroup, BigInteger, Field as _, PrimeField};
    use num_bigint::BigUint;
    use rand::{RngExt, SeedableRng, rngs::StdRng};
    use std::sync::LazyLock;

    fn ark2(value: Fq2) -> ArkFq2 {
        static INV_RADIX: LazyLock<ArkFq> =
            LazyLock::new(|| ArkFq::from(2).pow([256]).inverse().unwrap());
        let (a, b) = value.to_montgomery();
        ArkFq2::new(
            ArkFq::from_bigint(ark_ff::BigInt(a.0)).unwrap() * *INV_RADIX,
            ArkFq::from_bigint(ark_ff::BigInt(b.0)).unwrap() * *INV_RADIX,
        )
    }

    #[test]
    fn schedule_and_constants_have_no_exceptional_steps() {
        assert_eq!(core::mem::size_of::<Entry>(), 384);
        assert!(core::mem::size_of::<[Entry; BATCH_SIZE]>() <= 12288);
        let order = BigUint::from_bytes_le(&ArkFr::MODULUS.to_bytes_le());
        let q = BigUint::from_bytes_le(&ArkFq::MODULUS.to_bytes_le());
        let mut scalar = BigUint::from(1u8);
        for &digit in ATE_DIGITS.iter().rev().skip(1) {
            // Prime odd order makes every nonzero point safe to double.
            assert!(scalar > BigUint::from(0u8) && scalar < order);
            scalar *= 2u8;
            assert!(scalar > BigUint::from(1u8) && scalar < &order - 1u8);
            match digit {
                1 => scalar += 1u8,
                -1 => scalar -= 1u8,
                0 => {}
                _ => unreachable!(),
            }
        }
        assert_eq!(scalar, BigUint::from(BN_X) * 6u8 + 2u8);
        let q1 = &q % &order;
        let negative_q2 = &order - ((&q * &q) % &order);
        for addend in [q1, negative_q2] {
            assert_ne!(scalar, addend);
            assert_ne!(scalar, &order - &addend);
            scalar = (scalar + addend) % &order;
            assert_ne!(scalar, BigUint::from(0u8));
        }
    }

    fn check_state(actual: &Homogeneous, expected: G2Affine) {
        assert!(!expected.infinity);
        let z = ark2(actual.z);
        assert_ne!(z, ArkFq2::ZERO);
        check2(actual.x, expected.x * z);
        check2(actual.y, expected.y * z);
    }

    fn check_line(line: &Line, at: G2Affine, slope: ArkFq2) {
        // Affine line: y - slope*x + (slope*at.x-at.y).
        // Projective formulas may multiply all coefficients by a nonzero scale.
        let scale = ark2(line.y);
        assert_ne!(scale, ArkFq2::ZERO);
        check2(line.x, -slope * scale);
        check2(line.constant, (slope * at.x - at.y) * scale);
    }

    #[test]
    fn homogeneous_steps_and_lines_match_affine_geometry() {
        let mut rng = StdRng::seed_from_u64(0x6d69_6c6c_6572_7631);
        for _ in 0..16 {
            let q = G2Affine::generator()
                .mul_bigint(rng.random::<[u64; 4]>())
                .into_affine();
            let scale = random2(&mut rng);
            assert_ne!(scale, ArkFq2::ZERO);
            let mut state = Homogeneous {
                x: ours2(q.x * scale),
                y: ours2(q.y * scale),
                z: ours2(scale),
            };
            let mut point = q;
            for &digit in ATE_DIGITS.iter().rev().skip(1) {
                let slope =
                    ArkFq2::from(3) * point.x.square() * (point.y + point.y).inverse().unwrap();
                check_line(&state.double().for_geometry(), point, slope);
                point = (point.into_group() + point).into_affine();
                check_state(&state, point);
                if digit != 0 {
                    let addend = if digit == 1 { q } else { -q };
                    let slope = (point.y - addend.y) * (point.x - addend.x).inverse().unwrap();
                    check_line(
                        &state.line_to((ours2(addend.x), ours2(addend.y))),
                        point,
                        slope,
                    );
                    check_line(&state.add((ours2(addend.x), ours2(addend.y))), point, slope);
                    point = (point.into_group() + addend).into_affine();
                    check_state(&state, point);
                }
            }
            let q1 = q.mul_bigint(ArkFq::MODULUS).into_affine();
            let q2 = q1.mul_bigint(ArkFq::MODULUS).into_affine();
            let actual_q1 = characteristic((ours2(q.x), ours2(q.y)));
            let actual_q2 = characteristic(actual_q1);
            check2(actual_q1.0, q1.x);
            check2(actual_q1.1, q1.y);
            check2(actual_q2.0, q2.x);
            check2(actual_q2.1, q2.y);
            for addend in [q1, -q2] {
                let slope = (point.y - addend.y) * (point.x - addend.x).inverse().unwrap();
                check_line(
                    &state.line_to((ours2(addend.x), ours2(addend.y))),
                    point,
                    slope,
                );
                check_line(&state.add((ours2(addend.x), ours2(addend.y))), point, slope);
                point = (point.into_group() + addend).into_affine();
                check_state(&state, point);
            }
        }
    }

    #[test]
    fn line_evaluation_matches_independent_dense_product() {
        let mut rng = StdRng::seed_from_u64(0x6c69_6e65_5f65_7631);
        for _ in 0..128 {
            let y = random2(&mut rng);
            let x = random2(&mut rng);
            let c = random2(&mut rng);
            let px = ArkFq::from(rng.random::<u64>());
            let py = ArkFq::from(rng.random::<u64>());
            let accumulator = random12(&mut rng);
            let dense = ArkFq12::new(
                ArkFq6::new(
                    ArkFq2::new(y.c0 * py, y.c1 * py),
                    ArkFq2::ZERO,
                    ArkFq2::ZERO,
                ),
                ArkFq6::new(ArkFq2::new(x.c0 * px, x.c1 * px), c, ArkFq2::ZERO),
            );
            let line = Line {
                y: ours2(y),
                x: ours2(x),
                constant: ours2(c),
            };
            check12(
                line.apply(ours12(accumulator), &(raw(px), raw(py))),
                accumulator * dense,
            );
            let mut tangent = dense;
            tangent.c1.c0 *= ArkFq2::from(3u64);
            let tangent_line = DoubleLine {
                y: ours2(y),
                x_squared: ours2(x),
                constant: ours2(c),
            };
            check12(
                tangent_line.apply(ours12(accumulator), &(raw(px), raw(py))),
                accumulator * tangent,
            );
        }
    }
    #[test]
    fn paired_sparse_products_match_dense_arkworks_multiplication() {
        let dense = |c: [ArkFq2; 3]| {
            ArkFq12::new(
                ArkFq6::new(c[0], ArkFq2::ZERO, ArkFq2::ZERO),
                ArkFq6::new(c[1], c[2], ArkFq2::ZERO),
            )
        };
        let mut rng = StdRng::seed_from_u64(0x7370_6172_7365_5f32);
        for i in 0..128 {
            let mut a = core::array::from_fn(|_| random2(&mut rng));
            let mut b = core::array::from_fn(|_| random2(&mut rng));
            if i < 2 {
                a = [ArkFq2::ZERO; 3];
            }
            if i == 1 {
                a[0] = ArkFq2::ONE;
            }
            if i == 2 {
                b = [ArkFq2::ZERO; 3];
            }
            let expected = dense(a) * dense(b);
            let c = Fq12::product_034(&a.map(ours2), &b.map(ours2));
            let product = Fq12::new(
                crate::backend::Fq6::new(c[0], c[1], c[2]),
                crate::backend::Fq6::new(c[3], c[4], Fq2::ZERO),
            );
            check12(product, expected);
            let accumulator = random12(&mut rng);
            check12(ours12(accumulator).mul_by_01234(&c), accumulator * expected);
        }
    }
}
