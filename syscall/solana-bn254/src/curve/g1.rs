//! BN254 G1 arithmetic for public data.
//!
//! Coordinates use canonical Fq Montgomery residues with radix `2^256`.
//! Multiplication accepts a raw 256-bit integer, not a Montgomery Fr element.
//! Execution is variable-time, as permitted by the crate's public-data contract.

use crate::backend::{Backend, Fq, MontgomeryBackend, U256};
use core::ops::{Add, Neg};

use super::glv;

type B = Backend<Fq>;

const GLV_WINDOW_WIDTH: u32 = 4;
const GLV_WINDOW_TABLE_SIZE: usize = 1 << (GLV_WINDOW_WIDTH - 2);

// 2^256 mod q: the Montgomery representation of one.
const ONE: U256 = U256::new([
    0xd35d438dc58f0d9d,
    0x0a78eb28f5c70b3d,
    0x666ea36f7879462c,
    0x0e0a77c19a07df2f,
]);

#[inline(always)]
fn twice(value: &U256) -> U256 {
    B::add(value, value)
}

/// A validated affine G1 point, with canonical Montgomery Fq coordinates.
///
/// The identity is represented by `(0, 0)`, which is not a finite curve point.
/// Private coordinates ensure that arithmetic only receives validated points.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Affine {
    x: U256,
    y: U256,
}

impl Affine {
    pub const IDENTITY: Self = Self {
        x: U256::zero(),
        y: U256::zero(),
    };

    /// Validates canonical Montgomery coordinates, accepting `(0, 0)` as identity.
    /// G1 has cofactor one, so the curve equation also establishes subgroup membership.
    pub fn from_montgomery(x: U256, y: U256) -> Option<Self> {
        if !B::is_reduced(&x) || !B::is_reduced(&y) {
            return None;
        }
        let point = Self { x, y };
        (point.is_identity() || point.is_on_curve()).then_some(point)
    }

    /// Returns the canonical Montgomery coordinates, or `(0, 0)` for identity.
    #[inline]
    pub fn to_montgomery(&self) -> (U256, U256) {
        (self.x, self.y)
    }

    #[inline]
    pub fn is_identity(&self) -> bool {
        *self == Self::IDENTITY
    }

    fn is_on_curve(&self) -> bool {
        let three = B::add(&twice(&ONE), &ONE);
        B::sqr(&self.y) == B::add(&B::mul(&B::sqr(&self.x), &self.x), &three)
    }

    /// Decodes 32-byte little-endian x and y coordinates using the Solana
    /// syscall encoding. All-zero bytes mean identity. The high two y bits
    /// are flags: bit 7 is accepted without changing y, bit 6 means identity,
    /// and both set is invalid. Coordinate canonicality is always checked.
    pub fn from_le_bytes(bytes: &[u8; 64]) -> Option<Self> {
        Self::from_bytes::<false>(bytes)
    }

    fn from_bytes<const BIG_ENDIAN: bool>(bytes: &[u8; 64]) -> Option<Self> {
        if *bytes == [0; 64] {
            return Some(Self::IDENTITY);
        }
        let read = |offset: usize| {
            U256::new(core::array::from_fn(|i| {
                let limb = if BIG_ENDIAN { 3 - i } else { i };
                let chunk = bytes[offset + 8 * limb..offset + 8 * limb + 8]
                    .try_into()
                    .unwrap();
                if BIG_ENDIAN {
                    u64::from_be_bytes(chunk)
                } else {
                    u64::from_le_bytes(chunk)
                }
            }))
        };
        let x = read(0);
        let mut y = read(32);
        let flags = y.0[3] >> 62;
        y.0[3] &= (1 << 62) - 1;
        if flags == 3 || !B::is_reduced(&x) || !B::is_reduced(&y) {
            return None;
        }
        if flags == 1 {
            return Some(Self::IDENTITY);
        }
        let point = Self {
            x: B::to_mont(&x),
            y: B::to_mont(&y),
        };
        // A sign flag on otherwise zero bytes must not turn an off-curve
        // (0, 0) into the special all-zero identity encoding.
        point.is_on_curve().then_some(point)
    }

    /// Decodes the same point encoding with each coordinate in big-endian order.
    pub fn from_be_bytes(bytes: &[u8; 64]) -> Option<Self> {
        Self::from_bytes::<true>(bytes)
    }

    /// Encodes canonical little-endian coordinates, with all zeros for identity.
    /// Output coordinates contain no flags.
    pub fn to_le_bytes(&self) -> [u8; 64] {
        self.encode_bytes::<false>()
    }

    fn encode_bytes<const BIG_ENDIAN: bool>(&self) -> [u8; 64] {
        let mut bytes = [0; 64];
        let words = [self.x, self.y];
        for (word, coordinate) in words.iter().zip(bytes.as_chunks_mut::<32>().0) {
            let limbs = B::from_mont(word).0;
            for (i, chunk) in coordinate.as_chunks_mut::<8>().0.iter_mut().enumerate() {
                let limb = limbs[if BIG_ENDIAN { 3 - i } else { i }];
                let encoded = if BIG_ENDIAN {
                    limb.to_be_bytes()
                } else {
                    limb.to_le_bytes()
                };
                chunk.copy_from_slice(&encoded);
            }
        }
        bytes
    }

    /// Encodes canonical big-endian coordinates, with all zeros for identity.
    pub fn to_be_bytes(&self) -> [u8; 64] {
        self.encode_bytes::<true>()
    }

    /// Multiplies by an ordinary unsigned integer, accepting all 256 bits.
    /// The scalar is not restricted to values below the group order.
    pub fn mul_scalar(&self, scalar: &U256) -> Self {
        if self.is_identity() {
            return *self;
        }
        // G1 has cofactor one, so choosing a signed representative modulo r
        // preserves multiplication for every validated point. Small raw scalars
        // bypass this setup; wide scalars may become small after reduction.
        let was_wide = scalar.0[2] != 0 || scalar.0[3] != 0;
        let normalized;
        let (scalar, negative) = if was_wide {
            let (magnitude, negative) = super::scalar::center_scalar(scalar);
            normalized = magnitude;
            (&normalized, negative)
        } else {
            (scalar, false)
        };
        // Centering also exposes r and r±1. Return their trivial results
        // before entering a scalar loop, preserving the representative's sign.
        match scalar.0 {
            [0, 0, 0, 0] => return Self::IDENTITY,
            [1, 0, 0, 0] => return if negative { -*self } else { *self },
            _ => {}
        }
        // Small magnitudes avoid recoding and table setup. Larger magnitudes,
        // including raw 128-bit inputs, compare the actual signed schedule.
        if scalar.0[1] != 0 || scalar.0[2] != 0 || scalar.0[3] != 0 {
            let split = glv::decompose(scalar);
            // Dense inputs of at least 96 bits can amortize an odd-multiple
            // table. Keep the existing selector for shorter/sparse integers.
            if (scalar.0[3] | scalar.0[2] | (scalar.0[1] >> 31)) != 0
                && scalar.0.iter().map(|word| word.count_ones()).sum::<u32>() > 32
            {
                // Wider tables paid off on long dense inputs in G07, while
                // width 4 retained the better shorter-input setup cost.
                let windowed = if scalar.0[3] != 0 {
                    self.mul_glv_window::<5, 8>(&split)
                } else {
                    self.mul_glv_window::<GLV_WINDOW_WIDTH, GLV_WINDOW_TABLE_SIZE>(&split)
                };
                if let Some(result) = windowed {
                    return if negative { -result } else { result };
                }
            }
            if let Some(digits) = split.prepare::<7, 11, 40>(scalar) {
                let result = self.mul_glv(&digits);
                return if negative { -result } else { result };
            }
        }
        let mut result = Projective::IDENTITY;
        let mut started = false;
        // Skip whole zero limbs for short public integers. The existing
        // started flag still skips leading zero bits in the highest limb.
        for limb in scalar.0.iter().rev().skip_while(|&&word| word == 0) {
            for bit in (0..64).rev() {
                let set = limb & (1u64 << bit) != 0;
                if started {
                    result.double();
                    if set {
                        result.add_mixed(self);
                    }
                } else if set {
                    result = Projective::from_affine(self);
                    started = true;
                }
            }
        }
        let result = result.to_affine();
        if negative { -result } else { result }
    }

    // Joint signed multiplication, including all table work in this call.
    // The caller supplies a nonzero signed schedule, including component signs.
    fn mul_glv(&self, digits: &glv::JointDigits) -> Self {
        let image = Self {
            x: B::mul(&self.x, &glv::BETA_MONT),
            y: self.y,
        };
        // Give all four entries the common denominator H=phi(P).x-P.x.
        // Their numerators lie on the isomorphic a=0 curve with coefficient
        // b*H^6. The addition/doubling formulas need no b, so they can use
        // these private temporaries directly. Fold H into the final Z before
        // returning to the original curve. Related global-Z table technique:
        // https://github.com/bitcoin-core/secp256k1/blob/master/src/ecmult_impl.h
        let h = B::sub(&image.x, &self.x);
        let (table, denominator) = if h == U256::zero() {
            let combined = Self {
                x: B::neg(&B::add(&self.x, &image.x)),
                y: B::neg(&self.y),
            };
            ([*self, image + -*self, image, combined], ONE)
        } else {
            let hh = B::sqr(&h);
            let x = B::mul(&self.x, &hh);
            let image_x = B::mul(&image.x, &hh);
            let y = B::mul(&self.y, &B::mul(&hh, &h));
            let r = twice(&self.y);
            let difference_x = B::sub(&B::sub(&B::sqr(&r), &x), &image_x);
            let difference_y = B::add(&B::mul(&r, &B::sub(&x, &difference_x)), &y);
            (
                [
                    Self { x, y },
                    Self {
                        x: difference_x,
                        y: difference_y,
                    },
                    Self { x: image_x, y },
                    Self {
                        x: B::neg(&B::add(&x, &image_x)),
                        y: B::neg(&y),
                    },
                ],
                h,
            )
        };
        // Positive indices 1..=4 encode P, phi(P)-P, phi(P), P+phi(P).
        let (last, rest) = digits.as_slice().split_last().expect("nonzero GLV scalar");
        let select = |digit: i8| {
            let point = table[usize::from(digit.unsigned_abs()) - 1];
            if digit < 0 { -point } else { point }
        };
        let mut result = Projective::from_affine(&select(*last));
        for &digit in rest.iter().rev() {
            result.double();
            if digit != 0 {
                result.add_mixed(&select(digit));
            }
        }
        result.z = B::mul(&result.z, &denominator);
        result.to_affine()
    }
}

impl Add for Affine {
    type Output = Self;

    fn add(self, rhs: Self) -> Self {
        if self.is_identity() {
            return rhs;
        }
        if rhs.is_identity() {
            return self;
        }
        let (numerator, denominator) = if self.x == rhs.x {
            if self.y != rhs.y || self.y == U256::zero() {
                return Self::IDENTITY;
            }
            let square = B::sqr(&self.x);
            (B::add(&twice(&square), &square), twice(&self.y))
        } else {
            (B::sub(&rhs.y, &self.y), B::sub(&rhs.x, &self.x))
        };
        let slope = B::mul(
            &numerator,
            &B::inv(&denominator).expect("nonzero slope denominator"),
        );
        let x = B::sub(&B::sub(&B::sqr(&slope), &self.x), &rhs.x);
        let y = B::sub(&B::mul(&slope, &B::sub(&self.x, &x)), &self.y);
        Self { x, y }
    }
}

impl Neg for Affine {
    type Output = Self;

    fn neg(self) -> Self {
        Self {
            x: self.x,
            y: B::neg(&self.y),
        }
    }
}

/// Jacobian coordinates: affine x = X/Z^2, y = Y/Z^3. Z=0 denotes identity.
/// Each coordinate, including Z, remains a canonical Montgomery Fq residue.
#[derive(Clone, Copy)]
struct Projective {
    x: U256,
    y: U256,
    z: U256,
}

impl Projective {
    const IDENTITY: Self = Self {
        x: ONE,
        y: ONE,
        z: U256::zero(),
    };

    fn from_affine(p: &Affine) -> Self {
        if p.is_identity() {
            Self::IDENTITY
        } else {
            Self {
                x: p.x,
                y: p.y,
                z: ONE,
            }
        }
    }

    fn to_affine(self) -> Affine {
        if self.z == U256::zero() {
            return Affine::IDENTITY;
        }
        if self.z == ONE {
            return Affine {
                x: self.x,
                y: self.y,
            };
        }
        let inverse = B::inv(&self.z).expect("nonzero projective denominator");
        let square = B::sqr(&inverse);
        Affine {
            x: B::mul(&self.x, &square),
            y: B::mul(&self.y, &B::mul(&square, &inverse)),
        }
    }

    fn double(&mut self) {
        if self.z == U256::zero() || self.y == U256::zero() {
            *self = Self::IDENTITY;
            return;
        }
        // Jacobian doubling for a=0: A=X^2, B=Y^2, C=B^2,
        // D=4XB, E=3A, X'=E^2-2D, Y'=E(D-X')-8C, Z'=2YZ.
        let a = B::sqr(&self.x);
        let b = B::sqr(&self.y);
        let c = B::sqr(&b);
        let d = twice(&twice(&B::mul(&self.x, &b)));
        let e = B::add(&twice(&a), &a);
        let x = B::sub(&B::sqr(&e), &twice(&d));
        let y = B::sub(&B::mul(&e, &B::sub(&d, &x)), &twice(&twice(&twice(&c))));
        let z = twice(&B::mul(&self.y, &self.z));
        *self = Self { x, y, z };
    }

    fn add_mixed(&mut self, rhs: &Affine) {
        if rhs.is_identity() {
            return;
        }
        if self.z == U256::zero() {
            *self = Self::from_affine(rhs);
            return;
        }
        // Lift the affine operand to our denominator: U=x2*Z^2, S=y2*Z^3.
        // H=U-X, r=S-Y. H=0 distinguishes doubling from opposite points.
        let zz = B::sqr(&self.z);
        let u = B::mul(&rhs.x, &zz);
        let s = B::mul(&rhs.y, &B::mul(&zz, &self.z));
        let h = B::sub(&u, &self.x);
        let r = B::sub(&s, &self.y);
        if h == U256::zero() {
            if r == U256::zero() {
                self.double();
            } else {
                *self = Self::IDENTITY;
            }
            return;
        }
        // Use Z'=ZH, X'=r^2-H^3-2XH^2,
        // Y'=r(XH^2-X')-YH^3. All backend operations return canonical residues.
        let hh = B::sqr(&h);
        let hhh = B::mul(&h, &hh);
        let v = B::mul(&self.x, &hh);
        let x = B::sub(&B::sub(&B::sqr(&r), &hhh), &twice(&v));
        let y = B::sub(&B::mul(&r, &B::sub(&v, &x)), &B::mul(&self.y, &hhh));
        let z = B::mul(&self.z, &h);
        *self = Self { x, y, z };
    }
}

impl Affine {
    // Entries are numerators on an isomorphic a=0 curve. Their common
    // denominator must be multiplied into the final Jacobian Z before any
    // point is returned through the public API. No subgroup assumption here.
    // Related global-Z table construction:
    // https://github.com/bitcoin-core/secp256k1/blob/master/src/ecmult_impl.h
    fn odd_table<const N: usize>(&self) -> Option<([Self; N], U256)> {
        assert!(N > 0);
        if self.is_identity() {
            return None;
        }
        let mut double = Projective::from_affine(self);
        double.double();
        let c = double.z;
        if c == U256::zero() {
            return None;
        }
        // On the isomorphic curve with coefficient b*C^6, 2P has affine
        // coordinates (double.x,double.y). Repeated mixed addition avoids
        // inverting C; this construction does not use subgroup eigenvalues.
        let cc = B::sqr(&c);
        let ccc = B::mul(&cc, &c);
        let step = Self {
            x: double.x,
            y: double.y,
        };
        let mut current = Projective {
            x: B::mul(&self.x, &cc),
            y: B::mul(&self.y, &ccc),
            z: ONE,
        };
        let mut points = [Projective::IDENTITY; N];
        points[0] = current;
        for point in &mut points[1..] {
            current.add_mixed(&step);
            *point = current;
        }
        let (table, d) = Projective::common_denominator(&points);
        Some((table, B::mul(&c, &d)))
    }

    // Ordinary width-W NAF for both signed GLV components. Table preparation
    // and the final denominator correction are included in every call.
    fn mul_glv_window<const W: u32, const N: usize>(
        &self,
        split: &glv::SplitScalar,
    ) -> Option<Self> {
        assert!((3..=5).contains(&W) && N == 1usize << (W - 2));
        if self.is_identity() || split.k1 | split.k2 == 0 {
            return Some(Self::IDENTITY);
        }
        let left = super::window::from_u128::<W>(split.k1);
        let right = super::window::from_u128::<W>(split.k2);
        let (table, denominator) = self.odd_table::<N>()?;
        // The x-only endomorphism commutes with this common scaling. Unlike
        // Frobenius, it does not conjugate a possible Fq2 denominator.
        let images = if split.k2 == 0 {
            [Self::IDENTITY; N]
        } else {
            table.map(|p| {
                let image = Self {
                    x: B::mul(&p.x, &glv::BETA_MONT),
                    y: p.y,
                };
                if split.k2_negative { -image } else { image }
            })
        };
        let select = |entries: &[Self; N], digit: i8| {
            let point = entries[usize::from(digit.unsigned_abs()) / 2];
            if digit < 0 { -point } else { point }
        };
        let mut result = Projective::IDENTITY;
        for i in (0..left.len.max(right.len)).rev() {
            result.double();
            if left.digits[i] != 0 {
                result.add_mixed(&select(&table, left.digits[i]));
            }
            if right.digits[i] != 0 {
                result.add_mixed(&select(&images, right.digits[i]));
            }
        }
        result.z = B::mul(&result.z, &denominator);
        Some(result.to_affine())
    }
}

impl Projective {
    // Return private affine numerators sharing D=product(nonzero Z_i).
    // Prefix/suffix products form D/Z_i without an inverse; identity entries
    // are skipped. Outputs are for the isomorphic curve with coefficient b*D^6.
    fn common_denominator<const N: usize>(points: &[Self; N]) -> ([Affine; N], U256) {
        let mut prefix = [ONE; N];
        let mut denominator = ONE;
        for (i, point) in points.iter().enumerate() {
            prefix[i] = denominator;
            if point.z != U256::zero() {
                denominator = B::mul(&denominator, &point.z);
            }
        }
        let mut suffix = ONE;
        let mut table = [Affine::IDENTITY; N];
        for i in (0..N).rev() {
            let point = points[i];
            if point.z == U256::zero() {
                continue;
            }
            let factor = B::mul(&prefix[i], &suffix);
            suffix = B::mul(&suffix, &point.z);
            let square = B::sqr(&factor);
            let cube = B::mul(&square, &factor);
            table[i] = Affine {
                x: B::mul(&point.x, &square),
                y: B::mul(&point.y, &cube),
            };
        }
        (table, denominator)
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn odd_tables_match_independent_odd_multiples() {
        use rand::{RngExt, SeedableRng, rngs::StdRng};

        fn check<const N: usize>(p: G1Affine) {
            let radix = ArkFq::from(2u64).pow([256u64]);
            let ours = |q: G1Affine| {
                if q.infinity {
                    Affine::IDENTITY
                } else {
                    let raw = |v: ArkFq| U256::new((v * radix).into_bigint().0);
                    Affine::from_montgomery(raw(q.x), raw(q.y)).unwrap()
                }
            };
            if p.infinity {
                assert!(ours(p).odd_table::<N>().is_none());
                return;
            }
            let (entries, denominator) = ours(p).odd_table::<N>().unwrap();
            assert_ne!(denominator, U256::zero());
            for (i, entry) in entries.into_iter().enumerate() {
                let actual = if entry.is_identity() {
                    Affine::IDENTITY
                } else {
                    Projective {
                        x: entry.x,
                        y: entry.y,
                        z: denominator,
                    }
                    .to_affine()
                };
                let expected = p.mul_bigint([(2 * i + 1) as u64]).into_affine();
                assert_eq!(actual, ours(expected));
            }
        }
        let mut rng = StdRng::seed_from_u64(0x6731_5f6f_6464_7462);
        for i in 0..19 {
            let p = match i {
                0 => G1Affine::identity(),
                1 => G1Affine::generator(),
                2 => -G1Affine::generator(),
                _ => G1Affine::generator()
                    .mul_bigint(rng.random::<[u64; 4]>())
                    .into_affine(),
            };
            check::<2>(p);
            check::<4>(p);
            check::<8>(p);
        }
    }

    use super::*;
    use ark_bn254::{Fq as ArkFq, G1Affine};
    use ark_ec::{AffineRepr, CurveGroup};
    use ark_ff::{BigInt, Field as _, PrimeField};

    #[test]
    fn endomorphism_and_joint_multiplication_match_binary_oracle() {
        use ark_bn254::g1::Config;
        use ark_ec::scalar_mul::glv::GLVConfig;
        let radix = ArkFq::from(2u64).pow([256u64]);
        let raw = |v: ArkFq| U256::new((v * radix).into_bigint().0);
        let ours = |p: G1Affine| {
            if p.infinity {
                Affine::IDENTITY
            } else {
                Affine::from_montgomery(raw(p.x), raw(p.y)).unwrap()
            }
        };
        assert_eq!(glv::BETA_MONT, raw(Config::ENDO_COEFFS[0]));
        // Includes r-1, r, r+1, the maximum raw scalar, and four reciprocal
        // quotient boundaries with negative second components.
        let scalars = [
            [
                0x0000000000000001,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
            ],
            [
                0x0000000000000002,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
            ],
            [
                0xffffffffffffffff,
                0xffffffffffffffff,
                0x0000000000000000,
                0x0000000000000000,
            ],
            [
                0x0000000000000001,
                0x0000000000000000,
                0x0000000000000001,
                0x0000000000000000,
            ],
            [
                0x43e1f593f0000000,
                0x2833e84879b97091,
                0xb85045b68181585d,
                0x30644e72e131a029,
            ],
            [
                0x43e1f593f0000001,
                0x2833e84879b97091,
                0xb85045b68181585d,
                0x30644e72e131a029,
            ],
            [
                0x43e1f593f0000002,
                0x2833e84879b97091,
                0xb85045b68181585d,
                0x30644e72e131a029,
            ],
            [
                0xffffffffffffffff,
                0xffffffffffffffff,
                0xffffffffffffffff,
                0xffffffffffffffff,
            ],
            [
                0x01624731e1195570,
                0x3ba491482db4da14,
                0x59e26bcea0d48bac,
                0x0000000000000000,
            ],
            [
                0x02c48e63c232aadf,
                0x774922905b69b428,
                0xb3c4d79d41a91758,
                0x0000000000000000,
            ],
            [
                0x0426d595a34c004e,
                0xb2edb3d8891e8e3c,
                0x0da7436be27da304,
                0x0000000000000001,
            ],
            [
                0x05891cc7846555bd,
                0xee924520b6d36850,
                0x6789af3a83522eb0,
                0x0000000000000001,
            ],
        ];
        for n in 1..=8u64 {
            let p = G1Affine::generator().mul_bigint([n]).into_affine();
            let point = ours(p);
            let phi = Affine {
                x: B::mul(&point.x, &glv::BETA_MONT),
                y: point.y,
            };
            // Arkworks' affine mul_bigint uses binary double-and-add, not GLV.
            assert_eq!(
                phi,
                ours(p.mul_bigint(Config::LAMBDA.into_bigint()).into_affine())
            );
            for limbs in scalars {
                let scalar = U256::new(limbs);
                let expected = ours(p.mul_bigint(limbs).into_affine());
                let split = glv::decompose(&scalar);
                assert_eq!(point.mul_glv(&split.joint_digits()), expected);
                assert_eq!(point.mul_scalar(&scalar), expected);
            }
        }
    }

    #[test]
    fn joint_components_with_both_signs_match_binary_oracle() {
        use ark_bn254::g1::Config;
        use ark_ec::scalar_mul::glv::GLVConfig;
        use rand::{RngExt, SeedableRng, rngs::StdRng};

        let beta = Config::ENDO_COEFFS[0];
        assert_ne!(beta, ArkFq::from(1u64));
        assert_eq!(beta.square() + beta + ArkFq::from(1u64), ArkFq::from(0u64));
        let radix = ArkFq::from(2u64).pow([256u64]);
        let ours = |p: G1Affine| {
            if p.infinity {
                Affine::IDENTITY
            } else {
                let raw = |v: ArkFq| U256::new((v * radix).into_bigint().0);
                Affine::from_montgomery(raw(p.x), raw(p.y)).unwrap()
            }
        };
        let mut rng = StdRng::seed_from_u64(0x6731_5f6a_6f69_6e74);
        let points: [G1Affine; 19] = core::array::from_fn(|i| match i {
            0 => G1Affine::identity(),
            1 => G1Affine::generator(),
            2 => -G1Affine::generator(),
            _ => G1Affine::generator()
                .mul_bigint(rng.random::<[u64; 4]>())
                .into_affine(),
        });
        let magnitudes = [0u128, 1, 2, 3, u64::MAX as u128, 1 << 127, u128::MAX];
        for p in points {
            // Affine mul_bigint uses independent binary multiplication.
            let phi = p.mul_bigint(Config::LAMBDA.into_bigint()).into_affine();
            for k1 in magnitudes {
                for k2 in magnitudes {
                    if k1 == 0 && k2 == 0 {
                        continue;
                    }
                    let left = p.mul_bigint([k1 as u64, (k1 >> 64) as u64]);
                    let right = phi.mul_bigint([k2 as u64, (k2 >> 64) as u64]);
                    for k2_negative in [false, true] {
                        let split = glv::SplitScalar {
                            k1,
                            k2,
                            k2_negative,
                        };
                        let expected =
                            (left + if k2_negative { -right } else { right }).into_affine();
                        // (1, 1) directly exercises the joint table entry.
                        let expected = ours(expected);
                        assert_eq!(ours(p).mul_glv(&split.joint_digits()), expected);
                        assert_eq!(ours(p).mul_glv_window::<3, 2>(&split), Some(expected));
                        assert_eq!(ours(p).mul_glv_window::<4, 4>(&split), Some(expected));
                        assert_eq!(ours(p).mul_glv_window::<5, 8>(&split), Some(expected));
                    }
                }
            }
        }
    }

    #[test]
    fn scaled_jacobian_addition_and_doubling_match_arkworks() {
        let radix = ArkFq::from(2u64).pow([256u64]);
        let raw = |v: ArkFq| U256::new((v * radix).into_bigint().0);
        let affine = |p: G1Affine| {
            if p.infinity {
                Affine::IDENTITY
            } else {
                Affine::from_montgomery(raw(p.x), raw(p.y)).unwrap()
            }
        };
        let check = |p: Projective, expected: G1Affine| {
            let integer = |value: U256| {
                ArkFq::from_bigint(BigInt(value.0)).unwrap() * radix.inverse().unwrap()
            };
            let (x, y, z) = (integer(p.x), integer(p.y), integer(p.z));
            assert_eq!(
                y.square(),
                x.square() * x + ArkFq::from(3u64) * z.pow([6u64])
            );
            assert_eq!(p.to_affine(), affine(expected));
        };
        for n in 1..=8u64 {
            let p = G1Affine::generator().mul_bigint([n]).into_affine();
            let q = p.mul_bigint([3u64]).into_affine();
            for z in [
                ArkFq::from(1),
                ArkFq::from(2),
                -ArkFq::from(1),
                ArkFq::from(2).pow([128u64]) + ArkFq::from(1),
            ] {
                let scaled = Projective {
                    x: raw(p.x * z.square()),
                    y: raw(p.y * z.square() * z),
                    z: raw(z),
                };
                check(scaled, p);
                let mut doubled = scaled;
                doubled.double();
                check(doubled, (p + p).into_affine());
                for rhs in [p, -p, q, G1Affine::identity()] {
                    let mut sum = scaled;
                    sum.add_mixed(&affine(rhs));
                    check(sum, (p + rhs).into_affine());
                }
                let mut identity = Projective::IDENTITY;
                identity.add_mixed(&affine(p));
                check(identity, p);
            }
        }
        let mut identity = Projective::IDENTITY;
        identity.double();
        check(identity, G1Affine::identity());
    }
}
