//! BN254 twist-curve arithmetic for public data.
//!
//! Coordinates are canonical Montgomery Fq2 elements, with coefficient radix
//! 2^256. A point validated on the curve need not belong to the G2 subgroup.
//! Raw multiplication is correct on the entire twist curve. The checked
//! multiplication entry point validates subgroup membership before reducing scalars.

use super::glv;
use crate::backend::{Backend, Fq, Fq2, MontgomeryBackend, U256};
use core::ops::{Add, Neg};

type B = Backend<Fq>;

const RAW_WINDOW_WIDTH: u32 = 3;
const RAW_WINDOW_TABLE_SIZE: usize = 1 << (RAW_WINDOW_WIDTH - 2);

const GLV_WINDOW_WIDTH: u32 = 4;
const GLV_WINDOW_TABLE_SIZE: usize = 1 << (GLV_WINDOW_WIDTH - 2);

// beta^2 * 2^256 mod q. This conjugate endomorphism has the same scalar
// eigenvalue as the G1 endomorphism, allowing the shared decomposition.
const BETA_SQUARED_MONT: U256 = U256::new([
    0x71930c11d782e155,
    0xa6bb947cffbe3323,
    0xaa303344d4741444,
    0x2c3b3f0d26594943,
]);

// xi = 9+u; b = 3/xi; psi coefficients are xi^((q-1)/3), xi^((q-1)/2).
pub(crate) const CURVE_B: Fq2 = Fq2 {
    c0: U256::new([
        0x3bf938e377b802a8,
        0x020b1b273633535d,
        0x26b7edf049755260,
        0x2514c6324384a86d,
    ]),
    c1: U256::new([
        0x38e7ecccd1dcff67,
        0x65f0b37d93ce0d3e,
        0xd749d0dd22ac00aa,
        0x0141b9ce4a688d4d,
    ]),
};
pub(crate) const PSI_X: Fq2 = Fq2 {
    c0: U256::new([
        0xb5773b104563ab30,
        0x347f91c8a9aa6454,
        0x7a007127242e0991,
        0x1956bcd8118214ec,
    ]),
    c1: U256::new([
        0x6e849f1ea0aa4757,
        0xaa1c7b6d89f89141,
        0xb6e713cdfae0ca3a,
        0x26694fbb4e82ebc3,
    ]),
};
pub(crate) const PSI_Y: Fq2 = Fq2 {
    c0: U256::new([
        0xe4bbdd0c2936b629,
        0xbb30f162e133bacb,
        0x31a9d1b6f9645366,
        0x253570bea500f8dd,
    ]),
    c1: U256::new([
        0xa1d77ce45ffe77c7,
        0x07affd117826d1db,
        0x6d16bd27bb7edc6b,
        0x2c87200285defecc,
    ]),
};
pub(crate) const BN_X: u64 = 4965661367192848881;

// Fixed signed chain for BN_X. Starting at P, each step doubles by the given
// count and adds the indicated multiple of P. The chain uses 62 doublings
// and 17 mixed additions. P and 3P share a common denominator. These
// ordinary-integer chains are valid on the entire twist.
const BN_X_CHAIN: [(u8, i8); 17] = [
    (3, 1),
    (3, -3),
    (5, -3),
    (4, 3),
    (3, 1),
    (3, 1),
    (3, 3),
    (4, -3),
    (4, 1),
    (4, 3),
    (3, -3),
    (4, -3),
    (3, 1),
    (4, 1),
    (3, -3),
    (5, -1),
    (4, 1),
];

const _: () = {
    let mut scalar = 1i128;
    let mut i = 0;
    while i < BN_X_CHAIN.len() {
        let (doublings, digit) = BN_X_CHAIN[i];
        assert!(doublings > 0 && doublings < 64);
        assert!(matches!(digit, -3 | -1 | 1 | 3));
        scalar = (scalar << doublings) + digit as i128;
        assert!(scalar > 0 && scalar <= BN_X as i128);
        i += 1;
    }
    assert!(scalar == BN_X as i128);
};

// Retain the 17/30 doubling/mixed-addition dispatch weights. These approximate
// latency rather than current product counts (doubling now uses 16 products
// and two extra subtractions). Final normalization is shared by both schedules.
fn binary_cost(scalar: &U256) -> u32 {
    let bits = if scalar.0[3] != 0 {
        256 - scalar.0[3].leading_zeros()
    } else if scalar.0[2] != 0 {
        192 - scalar.0[2].leading_zeros()
    } else if scalar.0[1] != 0 {
        128 - scalar.0[1].leading_zeros()
    } else {
        64 - scalar.0[0].leading_zeros()
    };
    if bits == 0 {
        return 0;
    }
    let ones: u32 = scalar.0.iter().map(|limb| limb.count_ones()).sum();
    // Both counts are at most 255, so the result is at most 11,985.
    17 * (bits - 1) + 30 * (ones - 1)
}

#[inline]
fn scale_small<const N: u64>(value: Fq2) -> Fq2 {
    Fq2 {
        c0: B::scale_small::<N>(&value.c0),
        c1: B::scale_small::<N>(&value.c1),
    }
}

#[inline]
fn twice(value: Fq2) -> Fq2 {
    value + value
}

/// An affine point validated on the BN254 twist curve, including identity.
///
/// This type also represents points outside the prime-order G2 subgroup, as
/// required by the G2 addition syscall. Call is_in_correct_subgroup before
/// using a point where subgroup membership is required.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Affine {
    x: Fq2,
    y: Fq2,
}

impl Affine {
    pub const IDENTITY: Self = Self {
        x: Fq2::ZERO,
        y: Fq2::ZERO,
    };

    /// Checks the curve equation, accepting (0,0) as identity.
    /// Does not check subgroup membership.
    pub fn from_montgomery(x: Fq2, y: Fq2) -> Option<Self> {
        let point = Self { x, y };
        (point.is_identity() || point.is_on_curve()).then_some(point)
    }
    #[inline]
    pub fn to_montgomery(&self) -> (Fq2, Fq2) {
        (self.x, self.y)
    }
    #[inline]
    pub fn is_identity(&self) -> bool {
        *self == Self::IDENTITY
    }
    fn is_on_curve(&self) -> bool {
        self.y.square() == self.x.square() * self.x + CURVE_B
    }

    /// Decodes x.c0, x.c1, y.c0, y.c1 as 32-byte little-endian integers.
    /// Checks canonicality and the curve equation, but not subgroup membership.
    /// The high two bits of y.c1 are syscall flags: 0x80 is ignored, 0x40
    /// denotes identity, and 0xc0 is invalid. All coefficients must be canonical
    /// even for flagged identity. All-zero bytes also encode identity.
    pub fn from_le_bytes(bytes: &[u8; 128]) -> Option<Self> {
        Self::from_bytes::<false>(bytes)
    }

    fn from_bytes<const BIG_ENDIAN: bool>(bytes: &[u8; 128]) -> Option<Self> {
        if *bytes == [0; 128] {
            return Some(Self::IDENTITY);
        }
        let mut words: [U256; 4] = core::array::from_fn(|c| {
            // BE encodes each Fq2 coordinate as c1 followed by c0.
            let coefficient = if BIG_ENDIAN { c ^ 1 } else { c };
            U256::new(core::array::from_fn(|i| {
                let limb = if BIG_ENDIAN { 3 - i } else { i };
                let offset = 32 * coefficient + 8 * limb;
                let chunk = bytes[offset..offset + 8].try_into().unwrap();
                if BIG_ENDIAN {
                    u64::from_be_bytes(chunk)
                } else {
                    u64::from_le_bytes(chunk)
                }
            }))
        });
        let flags = words[3].0[3] >> 62;
        words[3].0[3] &= (1 << 62) - 1;
        if flags == 3 || words.iter().any(|v| !B::is_reduced(v)) {
            return None;
        }
        if flags == 1 {
            return Some(Self::IDENTITY);
        }
        let [x0, x1, y0, y1] = words.map(|v| B::to_mont(&v));
        let point = Self {
            x: Fq2 { c0: x0, c1: x1 },
            y: Fq2 { c0: y0, c1: y1 },
        };
        // A sign flag on zero coordinates is not the all-zero identity encoding.
        point.is_on_curve().then_some(point)
    }

    /// Decodes big-endian x.c1, x.c0, y.c1, y.c0; checks only the curve.
    pub fn from_be_bytes(bytes: &[u8; 128]) -> Option<Self> {
        Self::from_bytes::<true>(bytes)
    }

    /// Encodes canonical coordinates in little-endian coefficient order.
    /// Identity encodes as all zeros; output carries no flags.
    pub fn to_le_bytes(&self) -> [u8; 128] {
        self.encode_bytes::<false>()
    }

    fn encode_bytes<const BIG_ENDIAN: bool>(&self) -> [u8; 128] {
        let mut bytes = [0; 128];
        let words = if BIG_ENDIAN {
            [self.x.c1, self.x.c0, self.y.c1, self.y.c0]
        } else {
            [self.x.c0, self.x.c1, self.y.c0, self.y.c1]
        };
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
    /// Encodes canonical big-endian x.c1, x.c0, y.c1, y.c0.
    pub fn to_be_bytes(&self) -> [u8; 128] {
        self.encode_bytes::<true>()
    }

    /// Tests membership in the prime-order subgroup, accepting identity.
    pub fn is_in_correct_subgroup(&self) -> bool {
        if self.is_identity() {
            return true;
        }
        // For this BN parameter, subgroup membership is equivalent to
        // [x+1]P + psi([x]P) + psi^2([x]P) = psi^3([2x]P).
        // This uses one 63-bit multiplication on the full twist; it must not
        // assume subgroup membership. The cofactor condition is checked below.
        // See https://eprint.iacr.org/2022/348, Theorem 1 and Example 1.
        self.subgroup_relation(self.mul_by_bn_x())
    }

    fn subgroup_relation(&self, xp: Projective) -> bool {
        let mut lhs = xp;
        lhs.add_mixed(self);
        let mut image = xp.frobenius();
        lhs.add(&image);
        image = image.frobenius();
        lhs.add(&image);
        let mut rhs = image.frobenius();
        rhs.double();
        lhs.matches(&rhs)
    }

    /// Multiplies by an ordinary 256-bit integer on the entire twist curve.
    /// Does not reduce the scalar modulo r or assume subgroup membership.
    pub fn mul_scalar(&self, scalar: &U256) -> Self {
        if self.is_identity() {
            return *self;
        }
        match scalar.0 {
            [0, 0, 0, 0] => return Self::IDENTITY,
            [1, 0, 0, 0] => return *self,
            _ => {}
        }
        // Ordinary integer windows do not reduce modulo the subgroup
        // order. Short/sparse integers keep the existing binary path.
        if (scalar.0[3] | scalar.0[2] | (scalar.0[1] >> 31)) != 0
            && scalar.0.iter().map(|word| word.count_ones()).sum::<u32>() > 32
        {
            // Binary transitions distinguish random dense integers from long
            // runs of ones, whose signed representation needs very few adds.
            // Keep their small table; wider tables repay setup only for the
            // denser signed schedules measured at these length cutoffs.
            let transitions: u32 = scalar
                .0
                .iter()
                .enumerate()
                .map(|(i, word)| {
                    let next = scalar.0.get(i + 1).copied().unwrap_or(0);
                    (word ^ ((word >> 1) | (next << 63))).count_ones()
                })
                .sum();
            let windowed = if transitions <= 32 {
                self.mul_raw_window::<RAW_WINDOW_WIDTH, RAW_WINDOW_TABLE_SIZE>(scalar)
            } else if scalar.0[3] != 0 {
                self.mul_raw_window::<5, 8>(scalar)
            } else {
                self.mul_raw_window::<4, 4>(scalar)
            };
            if let Some(result) = windowed {
                return result;
            }
        }
        self.mul_projective(&scalar.0).to_affine()
    }

    /// Checks subgroup membership, then multiplies by any unsigned 256-bit integer.
    /// Returns None for points outside G2, including when the scalar is zero.
    /// Use mul_scalar for raw-integer multiplication on the entire twist.
    pub fn mul_scalar_checked(&self, scalar: &U256) -> Option<Self> {
        if !self.is_in_correct_subgroup() {
            return None;
        }
        if self.is_identity() {
            return Some(*self);
        }
        // Only subgroup points allow replacing the ordinary integer by a
        // signed representative modulo r. Small raw scalars need no reduction.
        let (mut magnitude, mut negative) = (*scalar, false);
        if scalar.0[2] != 0 || scalar.0[3] != 0 {
            let (centered, sign) = super::scalar::center_scalar(scalar);
            // Centering can turn a sparse scalar into a dense one. Retain the
            // raw integer unless the estimated binary schedule is cheaper.
            if binary_cost(&centered) < binary_cost(scalar) {
                magnitude = centered;
                negative = sign;
            }
        }
        let result = if magnitude.0[1] | magnitude.0[2] | magnitude.0[3] == 0 {
            match magnitude.0[0] {
                0 => Self::IDENTITY,
                1 => *self,
                word => self.mul_projective(&[word]).to_affine(),
            }
        } else {
            self.mul_subgroup_scalar(&magnitude)
        };
        Some(if negative { -result } else { result })
    }

    // Called only after membership validation, for scalars wider than 64 bits.
    fn mul_subgroup_scalar(&self, scalar: &U256) -> Self {
        // Frobenius decomposition is valid only after the checked entry
        // point has established subgroup membership. Short/sparse values
        // retain the current selector and its smaller setup cost.
        if (scalar.0[2] | scalar.0[3]) != 0
            && scalar.0.iter().map(|word| word.count_ones()).sum::<u32>() > 32
        {
            return self.mul_gs_joint_pairs(scalar);
        }
        let split = glv::decompose(scalar);
        // Dense inputs of at least 96 bits can amortize an odd-multiple
        // table. Keep the existing selector for shorter/sparse integers.
        if (scalar.0[3] | scalar.0[2] | (scalar.0[1] >> 31)) != 0
            && scalar.0.iter().map(|word| word.count_ones()).sum::<u32>() > 32
            && let Some(result) =
                self.mul_glv_window::<GLV_WINDOW_WIDTH, GLV_WINDOW_TABLE_SIZE>(&split)
        {
            return result;
        }
        if let Some(digits) = split.prepare::<17, 30, 100>(scalar) {
            return self.mul_glv(&digits);
        }
        self.mul_projective(&scalar.0).to_affine()
    }

    fn endomorphism(&self) -> Self {
        Self {
            x: Fq2 {
                c0: B::mul(&self.x.c0, &BETA_SQUARED_MONT),
                c1: B::mul(&self.x.c1, &BETA_SQUARED_MONT),
            },
            y: self.y,
        }
    }

    // Private numerators on the common-denominator isomorphic curve.
    fn glv_table(&self) -> ([Self; 4], Fq2) {
        let image = self.endomorphism();
        // Give all four entries the common denominator H=phi(P).x-P.x.
        // Their numerators lie on the isomorphic a=0 curve with coefficient
        // b*H^6. The addition/doubling formulas need no b, so they can use
        // these private temporaries directly. Fold H into the final Z before
        // returning to the original curve. Related global-Z table technique:
        // https://github.com/bitcoin-core/secp256k1/blob/master/src/ecmult_impl.h
        let h = image.x - self.x;
        let (table, denominator) = if h == Fq2::ZERO {
            let combined = Self {
                x: -(self.x + image.x),
                y: -self.y,
            };
            ([*self, image + -*self, image, combined], Fq2::ONE)
        } else {
            let hh = h.square();
            let x = self.x * hh;
            let image_x = image.x * hh;
            let y = self.y * (hh * h);
            let r = twice(self.y);
            let difference_x = r.square() - x - image_x;
            let difference_y = r * (x - difference_x) + y;
            (
                [
                    Self { x, y },
                    Self {
                        x: difference_x,
                        y: difference_y,
                    },
                    Self { x: image_x, y },
                    Self {
                        x: -(x + image_x),
                        y: -y,
                    },
                ],
                h,
            )
        };
        (table, denominator)
    }

    // Joint signed multiplication k1*P + signed(k2)*phi(P). The checked
    // entry point supplies subgroup points and a prepared signed schedule.
    fn mul_glv(&self, digits: &glv::JointDigits) -> Self {
        if self.is_identity() || digits.as_slice().is_empty() {
            return Self::IDENTITY;
        }
        let (table, denominator) = self.glv_table();
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
        result.z = result.z * denominator;
        result.to_affine()
    }

    // Ordinary-integer multiplication; subgroup membership is not assumed.
    fn mul_by_bn_x(&self) -> Projective {
        // Put P and 3P over the triple's denominator on an isomorphic a=0
        // curve, retaining mixed additions throughout the fixed chain. As in
        // odd_table, fold the denominator into Z before using Frobenius maps
        // on the original twist. No inversion or subgroup assumption is needed.
        let mut triple = Projective::from_affine(self);
        triple.double();
        triple.add_mixed(self);
        let (point, triple, denominator) = if triple.z == Fq2::ZERO {
            (*self, Self::IDENTITY, Fq2::ONE)
        } else {
            let zz = triple.z.square();
            (
                Self {
                    x: self.x * zz,
                    y: self.y * (zz * triple.z),
                },
                Self {
                    x: triple.x,
                    y: triple.y,
                },
                triple.z,
            )
        };
        let mut result = point.mul_by_bn_x_with_triple(triple);
        result.z = result.z * denominator;
        result
    }

    fn mul_by_bn_x_with_triple(&self, triple: Self) -> Projective {
        let negative = -*self;
        let negative_triple = -triple;
        let mut result = Projective::from_affine(self);
        for (doublings, digit) in BN_X_CHAIN {
            for _ in 0..doublings {
                result.double();
            }
            let addend = match digit {
                -3 => &negative_triple,
                -1 => &negative,
                1 => self,
                3 => &triple,
                _ => unreachable!("fixed chain digit"),
            };
            result.add_mixed(addend);
        }
        result
    }

    fn mul_projective<const N: usize>(&self, scalar: &[u64; N]) -> Projective {
        if self.is_identity() {
            return Projective::IDENTITY;
        }
        let mut result = Projective::IDENTITY;
        let mut started = false;
        for limb in scalar.iter().rev() {
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
        result
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
            if self.y != rhs.y || self.y == Fq2::ZERO {
                return Self::IDENTITY;
            }
            let square = self.x.square();
            (twice(square) + square, twice(self.y))
        } else {
            (rhs.y - self.y, rhs.x - self.x)
        };
        let slope = numerator * denominator.inverse().expect("nonzero slope denominator");
        let x = slope.square() - self.x - rhs.x;
        Self {
            x,
            y: slope * (self.x - x) - self.y,
        }
    }
}
impl Neg for Affine {
    type Output = Self;
    fn neg(self) -> Self {
        Self {
            x: self.x,
            y: -self.y,
        }
    }
}

// Jacobian x=X/Z^2, y=Y/Z^3; Z=0 is identity. All Fq2 coefficients stay reduced.
#[derive(Clone, Copy)]
struct Projective {
    x: Fq2,
    y: Fq2,
    z: Fq2,
}
impl Projective {
    const IDENTITY: Self = Self {
        x: Fq2::ONE,
        y: Fq2::ONE,
        z: Fq2::ZERO,
    };
    fn from_affine(p: &Affine) -> Self {
        if p.is_identity() {
            Self::IDENTITY
        } else {
            Self {
                x: p.x,
                y: p.y,
                z: Fq2::ONE,
            }
        }
    }
    fn matches(&self, rhs: &Self) -> bool {
        if self.z == Fq2::ZERO || rhs.z == Fq2::ZERO {
            return self.z == Fq2::ZERO && rhs.z == Fq2::ZERO;
        }
        let zz = self.z.square();
        let rhs_zz = rhs.z.square();
        self.x * rhs_zz == rhs.x * zz && self.y * (rhs_zz * rhs.z) == rhs.y * (zz * self.z)
    }
    fn frobenius(&self) -> Self {
        // Conjugating Z as well preserves Jacobian scaling. The twist
        // coefficients apply to X and Y, and all Fq2 values stay reduced.
        Self {
            x: self.x.conjugate() * PSI_X,
            y: self.y.conjugate() * PSI_Y,
            z: self.z.conjugate(),
        }
    }
    fn to_affine(self) -> Affine {
        if self.z == Fq2::ZERO {
            return Affine::IDENTITY;
        }
        if self.z == Fq2::ONE {
            return Affine {
                x: self.x,
                y: self.y,
            };
        }
        let inverse = self.z.inverse().expect("nonzero projective denominator");
        let square = inverse.square();
        Affine {
            x: self.x * square,
            y: self.y * (square * inverse),
        }
    }
    fn double(&mut self) {
        if self.z == Fq2::ZERO || self.y == Fq2::ZERO {
            *self = Self::IDENTITY;
            return;
        }
        #[cfg(all(
            target_arch = "x86_64",
            target_feature = "avx512f",
            target_feature = "avx512dq",
            target_feature = "avx512ifma"
        ))]
        self.double_ifma();
        #[cfg(not(all(
            target_arch = "x86_64",
            target_feature = "avx512f",
            target_feature = "avx512dq",
            target_feature = "avx512ifma"
        )))]
        {
            let a = self.x.square();
            let b = self.y.square();
            let c = b.square();
            // (X+B)^2-A-C = 2XB. Fq2 squaring uses two base-field products,
            // while multiplication uses three; all intermediates stay canonical.
            let d = twice((self.x + b).square() - a - c);
            let e = scale_small::<3>(a);
            let x = e.square() - twice(d);
            let y = e * (d - x) - scale_small::<8>(c);
            let z = twice(self.y * self.z);
            *self = Self { x, y, z };
        }
    }
    fn add(&mut self, rhs: &Self) {
        if rhs.z == Fq2::ZERO {
            return;
        }
        if self.z == Fq2::ZERO {
            *self = *rhs;
            return;
        }
        let zz = self.z.square();
        let rhs_zz = rhs.z.square();
        let u = self.x * rhs_zz;
        let rhs_u = rhs.x * zz;
        let s = self.y * (rhs_zz * rhs.z);
        let rhs_s = rhs.y * (zz * self.z);
        let h = rhs_u - u;
        let r = rhs_s - s;
        if h == Fq2::ZERO {
            if r == Fq2::ZERO {
                self.double();
            } else {
                *self = Self::IDENTITY;
            }
            return;
        }
        let hh = h.square();
        let hhh = h * hh;
        let v = u * hh;
        let x = r.square() - hhh - twice(v);
        let y = r * (v - x) - s * hhh;
        let z = self.z * rhs.z * h;
        *self = Self { x, y, z };
    }
    fn add_mixed(&mut self, rhs: &Affine) {
        if rhs.is_identity() {
            return;
        }
        if self.z == Fq2::ZERO {
            *self = Self::from_affine(rhs);
            return;
        }
        let zz = self.z.square();
        let u = rhs.x * zz;
        let s = rhs.y * (zz * self.z);
        let h = u - self.x;
        let r = s - self.y;
        if h == Fq2::ZERO {
            if r == Fq2::ZERO {
                self.double();
            } else {
                *self = Self::IDENTITY;
            }
            return;
        }
        let hh = h.square();
        let hhh = h * hh;
        let v = self.x * hh;
        let x = r.square() - hhh - twice(v);
        let y = r * (v - x) - self.y * hhh;
        let z = self.z * h;
        *self = Self { x, y, z };
    }
}

impl Affine {
    // Entries are numerators on an isomorphic a=0 curve. Their common
    // denominator must be multiplied into the final Jacobian Z before any
    // point is returned through the public API. No subgroup assumption here.
    // Related global-Z table construction:
    // https://github.com/bitcoin-core/secp256k1/blob/master/src/ecmult_impl.h
    fn odd_table<const N: usize>(&self) -> Option<([Self; N], Fq2)> {
        assert!(N > 0);
        if self.is_identity() {
            return None;
        }
        let mut double = Projective::from_affine(self);
        double.double();
        let c = double.z;
        if c == Fq2::ZERO {
            return None;
        }
        // On the isomorphic curve with coefficient b*C^6, 2P has affine
        // coordinates (double.x,double.y). Repeated mixed addition avoids
        // inverting C; this construction does not use subgroup eigenvalues.
        let cc = c.square();
        let ccc = cc * c;
        let step = Self {
            x: double.x,
            y: double.y,
        };
        let mut current = Projective {
            x: self.x * cc,
            y: self.y * ccc,
            z: Fq2::ONE,
        };
        let mut points = [Projective::IDENTITY; N];
        points[0] = current;
        for point in &mut points[1..] {
            current.add_mixed(&step);
            *point = current;
        }
        let (table, d) = Projective::common_denominator(&points);
        Some((table, c * d))
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
                let image = p.endomorphism();
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
        result.z = result.z * denominator;
        Some(result.to_affine())
    }
}

impl Projective {
    // Return private affine numerators sharing D=product(nonzero Z_i).
    // Prefix/suffix products form D/Z_i without an inverse; identity entries
    // are skipped. Outputs are for the isomorphic curve with coefficient b*D^6.
    fn common_denominator<const N: usize>(points: &[Self; N]) -> ([Affine; N], Fq2) {
        let mut prefix = [Fq2::ONE; N];
        let mut denominator = Fq2::ONE;
        for (i, point) in points.iter().enumerate() {
            prefix[i] = denominator;
            if point.z != Fq2::ZERO {
                denominator = denominator * point.z;
            }
        }
        let mut suffix = Fq2::ONE;
        let mut table = [Affine::IDENTITY; N];
        for i in (0..N).rev() {
            let point = points[i];
            if point.z == Fq2::ZERO {
                continue;
            }
            let factor = prefix[i] * suffix;
            suffix = suffix * point.z;
            let square = factor.square();
            let cube = square * factor;
            table[i] = Affine {
                x: point.x * square,
                y: point.y * cube,
            };
        }
        (table, denominator)
    }
}

impl Affine {
    // Ordinary unsigned multiplication on the entire twist. Neither the
    // recoder nor the table construction assumes prime-order membership.
    fn mul_raw_window<const W: u32, const N: usize>(&self, scalar: &U256) -> Option<Self> {
        assert!((3..=5).contains(&W) && N == 1usize << (W - 2));
        if self.is_identity() || *scalar == U256::zero() {
            return Some(Self::IDENTITY);
        }
        let digits = super::window::from_u256::<W>(scalar);
        let (table, denominator) = self.odd_table::<N>()?;
        let mut result = Projective::IDENTITY;
        for &digit in digits.digits[..digits.len].iter().rev() {
            result.double();
            if digit != 0 {
                let point = table[usize::from(digit.unsigned_abs()) / 2];
                result.add_mixed(&if digit < 0 { -point } else { point });
            }
        }
        result.z = result.z * denominator;
        Some(result.to_affine())
    }
}

impl Affine {
    fn mul_gs_joint_pairs(&self, scalar: &U256) -> Self {
        if self.is_identity() {
            return *self;
        }
        let [k0, k1, k2, k3] = super::gs::decompose(scalar);
        // lambda_p^2 = 1 + lambda_glv mod r for the existing conjugate
        // endomorphism. Thus the transformed components are below 2^68.
        // The identity and the actual map coefficients require oracle tests.
        let a = k0 + k2;
        let b = k1 + k3;
        let psi = Self {
            x: self.x.conjugate() * PSI_X,
            y: self.y.conjugate() * PSI_Y,
        };
        let pair = |point: Self, left: i128, right: i128| {
            let split = glv::SplitScalar {
                k1: left.unsigned_abs(),
                k2: right.unsigned_abs(),
                k2_negative: (left < 0) ^ (right < 0),
            };
            let base = if left < 0 { -point } else { point };
            let (table, denominator) = base.glv_table();
            (split.joint_digits(), table, denominator)
        };
        let (left, mut left_table, left_z) = pair(*self, a, k2);
        let (right, mut right_table, right_z) = pair(psi, b, k3);
        let scale = |table: &mut [Self; 4], z: Fq2| {
            let zz = z.square();
            let zzz = zz * z;
            for point in table {
                point.x = point.x * zz;
                point.y = point.y * zzz;
            }
        };
        scale(&mut left_table, right_z);
        scale(&mut right_table, left_z);
        let (left, right) = (left.as_slice(), right.as_slice());
        let select = |table: &[Self; 4], digit: i8| {
            let point = table[usize::from(digit.unsigned_abs()) - 1];
            if digit < 0 { -point } else { point }
        };
        let mut result = Projective::IDENTITY;
        for i in (0..left.len().max(right.len())).rev() {
            result.double();
            let l = left.get(i).copied().unwrap_or(0);
            let r = right.get(i).copied().unwrap_or(0);
            if l != 0 {
                result.add_mixed(&select(&left_table, l));
            }
            if r != 0 {
                result.add_mixed(&select(&right_table, r));
            }
        }
        result.z = result.z * left_z * right_z;
        result.to_affine()
    }
}

impl Projective {
    #[cfg(all(
        target_arch = "x86_64",
        target_feature = "avx512f",
        target_feature = "avx512dq",
        target_feature = "avx512ifma",
    ))]
    fn double_ifma(&mut self) {
        use crate::backend::avx512::fq::{fq2_three_squares, fq2_two_squares_and_product};
        // Caller has handled identity/Y=0. All field inputs are canonical;
        // the required target features are enforced by the enclosing cfg.
        let [a, b, yz] = unsafe { fq2_two_squares_and_product([self.x, self.y], self.y, self.z) };
        let e = scale_small::<3>(a);
        let [c, d_square, f] = unsafe { fq2_three_squares([b, self.x + b, e]) };
        let d = twice(d_square - a - c);
        let x = f - twice(d);
        let y = e * (d - x) - scale_small::<8>(c);
        *self = Self { x, y, z: twice(yz) };
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn gs_maps_and_multiplication_match_independent_binary_oracle() {
        use ark_ec::scalar_mul::glv::GLVConfig;
        let lambda_p = Fr::from(BN_X).square() * Fr::from(6u64);
        let lambda_glv = ark_bn254::g2::Config::LAMBDA.square();
        assert_eq!(lambda_p.pow([4u64]), lambda_glv);
        assert_eq!(lambda_p.square(), Fr::from(1u64) + lambda_glv);

        let mut scalars = std::vec![
            [0; 4],
            [1, 0, 0, 0],
            [u64::MAX; 4],
            [u64::MAX, u64::MAX, 0, 0],
            Fr::MODULUS.0,
        ];
        for offset in [-1i64, 1] {
            let mut scalar = Fr::MODULUS.0;
            scalar[0] = (scalar[0] as i128 + offset as i128) as u64;
            scalars.push(scalar);
        }
        for bit in [63usize, 64, 65, 66, 67, 127, 128, 129, 191, 192, 254, 255] {
            let mut scalar = [0; 4];
            scalar[bit / 64] = 1 << (bit % 64);
            scalars.push(scalar);
        }
        let mut rng = StdRng::seed_from_u64(0x6773_5f67_325f_6d75);
        scalars.extend((0..128).map(|_| rng.random::<[u64; 4]>()));
        for i in 0..11 {
            let p = match i {
                0 => G2Affine::identity(),
                1 => G2Affine::generator(),
                2 => -G2Affine::generator(),
                _ => G2Affine::generator()
                    .mul_bigint(rng.random::<[u64; 4]>())
                    .into_affine(),
            };
            let ours = affine(p);
            let psi = Affine {
                x: ours.x.conjugate() * PSI_X,
                y: ours.y.conjugate() * PSI_Y,
            };
            assert_eq!(psi, affine(p.mul_bigint(ArkFq::MODULUS.0).into_affine()));
            assert_eq!(
                ours.endomorphism(),
                affine(p.mul_bigint(lambda_glv.into_bigint()).into_affine())
            );
            for scalar in &scalars {
                let expected = affine(p.mul_bigint(*scalar).into_affine());
                assert_eq!(ours.mul_gs_joint_pairs(&U256::new(*scalar)), expected);
            }
        }
    }

    #[test]
    fn raw_windows_match_binary_multiplication_on_the_entire_twist() {
        let mut rng = StdRng::seed_from_u64(0x7261_775f_776e_6166);
        let mut points = std::vec![G2Affine::identity(), G2Affine::generator()];
        for _ in 0..16 {
            points.push(on_curve(&mut rng));
        }
        use ark_ec::short_weierstrass::SWCurveConfig;
        if let Some(y) = ark_bn254::g2::Config::COEFF_B.sqrt() {
            points.push(G2Affine::new_unchecked(ArkFq2::from(0u64), y));
        }
        let mut scalars = std::vec![
            U256::zero(),
            U256::new([1, 0, 0, 0]),
            U256::new([2, 0, 0, 0]),
            U256::new([3, 0, 0, 0]),
            U256::new([u64::MAX; 4]),
            U256::new(Fr::MODULUS.0),
        ];
        for bit in [63usize, 64, 95, 96, 127, 128, 191, 192, 254, 255] {
            let mut scalar = [0; 4];
            scalar[bit / 64] = 1 << (bit % 64);
            scalars.push(U256::new(scalar));
        }
        scalars.extend((0..32).map(|_| U256::new(rng.random::<[u64; 4]>())));
        for p in points {
            for scalar in &scalars {
                // Ark's Affine mul_bigint uses ordinary double-and-add.
                let expected = affine(p.mul_bigint(scalar.0).into_affine());
                for actual in [
                    affine(p).mul_raw_window::<3, 2>(scalar),
                    affine(p).mul_raw_window::<4, 4>(scalar),
                    affine(p).mul_raw_window::<5, 8>(scalar),
                ] {
                    match actual {
                        Some(actual) => assert_eq!(actual, expected),
                        None => assert_eq!(p.y, ArkFq2::from(0u64)),
                    }
                }
            }
        }
    }

    #[test]
    fn common_denominator_skips_identity_and_preserves_scaled_points() {
        let p = G2Affine::generator();
        let q = p.mul_bigint([17u64]).into_affine();
        let points = [
            Projective::IDENTITY,
            scaled(p, ArkFq2::new(ArkFq::from(2u64), ArkFq::from(3u64))),
            Projective::IDENTITY,
            scaled(q, ArkFq2::new(ArkFq::from(5u64), ArkFq::from(7u64))),
        ];
        let (entries, denominator) = Projective::common_denominator(&points);
        let expected = [G2Affine::identity(), p, G2Affine::identity(), q];
        for (entry, expected) in entries.into_iter().zip(expected) {
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
            assert_eq!(actual, affine(expected));
        }
        let (entries, denominator) = Projective::common_denominator(&[Projective::IDENTITY; 4]);
        assert_eq!(entries, [Affine::IDENTITY; 4]);
        assert_eq!(denominator, Fq2::ONE);
    }

    #[test]
    fn odd_tables_match_odd_multiples_on_the_entire_twist() {
        fn check<const N: usize>(p: G2Affine) {
            let table = affine(p).odd_table::<N>();
            if p.infinity || p.y == ArkFq2::from(0u64) {
                assert!(table.is_none());
                return;
            }
            let (entries, denominator) = table.unwrap();
            assert_ne!(denominator, Fq2::ZERO);
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
                // Affine mul_bigint is ordinary binary multiplication, including
                // outside the subgroup. No GLV scalar reduction is used here.
                let expected = p.mul_bigint([(2 * i + 1) as u64]).into_affine();
                assert_eq!(actual, affine(expected));
            }
        }
        let mut points = std::vec![
            G2Affine::identity(),
            G2Affine::generator(),
            -G2Affine::generator()
        ];
        let mut rng = StdRng::seed_from_u64(0x6732_5f6f_6464_7462);
        for _ in 0..64 {
            let p = on_curve(&mut rng);
            points.extend([p, -p]);
        }
        use ark_ec::short_weierstrass::SWCurveConfig;
        if let Some(y) = ark_bn254::g2::Config::COEFF_B.sqrt() {
            let p = G2Affine::new_unchecked(ArkFq2::from(0u64), y);
            points.extend([p, -p]);
        }
        for p in points {
            check::<2>(p);
            check::<4>(p);
            check::<8>(p);
        }
    }

    use super::*;
    use ark_bn254::{Fq as ArkFq, Fq2 as ArkFq2, Fr, G2Affine};
    use ark_ec::{AffineRepr, CurveGroup, models::CurveConfig};
    use ark_ff::{BigInteger, Field, PrimeField};
    use num_bigint::BigUint;
    use rand::{RngExt, SeedableRng, rngs::StdRng};

    fn fq2(value: ArkFq2) -> Fq2 {
        let radix = ArkFq::from(2u64).pow([256]);
        let raw = |x: ArkFq| U256::new((x * radix).into_bigint().0);
        Fq2::from_montgomery(raw(value.c0), raw(value.c1)).unwrap()
    }
    fn affine(p: G2Affine) -> Affine {
        if p.infinity {
            Affine::IDENTITY
        } else {
            Affine::from_montgomery(fq2(p.x), fq2(p.y)).unwrap()
        }
    }

    #[test]
    fn constants_match_independent_field_definitions() {
        let q = BigUint::from_bytes_le(&ArkFq::MODULUS.to_bytes_le());
        let r = BigUint::from_bytes_le(&Fr::MODULUS.to_bytes_le());
        let x = BigUint::from(BN_X);
        let lambda = &x * &x * 6u8;
        assert_eq!(&q - &r, lambda);
        let t = &lambda + 1u8;
        assert_eq!(&lambda * &lambda + &q - &t * &lambda, r);
        let xi = ArkFq2::new(ArkFq::from(9u64), ArkFq::from(1u64));
        assert_eq!(CURVE_B, fq2(ArkFq2::from(3u64) * xi.inverse().unwrap()));
        assert_eq!(PSI_X, fq2(xi.pow(((&q - 1u8) / 3u8).to_u64_digits())));
        assert_eq!(PSI_Y, fq2(xi.pow(((&q - 1u8) / 2u8).to_u64_digits())));
    }

    #[test]
    fn scaled_jacobian_formulas_and_affine_comparison() {
        let z_values = [
            ArkFq2::from(1u64),
            ArkFq2::from(2u64),
            -ArkFq2::from(1u64),
            ArkFq2::new(ArkFq::from(17u64), -ArkFq::from(3u64)),
        ];
        for n in 1..=8u64 {
            let p = G2Affine::generator().mul_bigint([n]).into_affine();
            let q = p.mul_bigint([3u64]).into_affine();
            for z in z_values {
                let scaled = Projective {
                    x: fq2(p.x * z.square()),
                    y: fq2(p.y * z.square() * z),
                    z: fq2(z),
                };
                assert_eq!(scaled.to_affine(), affine(p));
                assert!(scaled.matches(&Projective::from_affine(&affine(p))));
                assert!(!scaled.matches(&Projective::from_affine(&affine(-p))));
                assert!(!scaled.matches(&Projective::IDENTITY));
                let mut doubled = scaled;
                doubled.double();
                assert_eq!(doubled.to_affine(), affine((p + p).into_affine()));
                for rhs in [p, -p, q, G2Affine::identity()] {
                    let mut sum = scaled;
                    sum.add_mixed(&affine(rhs));
                    assert_eq!(sum.to_affine(), affine((p + rhs).into_affine()));
                }
            }
        }
        let mut zero = Projective::IDENTITY;
        zero.double();
        assert!(zero.matches(&Projective::IDENTITY));
        assert!(!zero.matches(&Projective::from_affine(&affine(G2Affine::generator()))));
        zero.add_mixed(&affine(G2Affine::generator()));
        assert_eq!(zero.to_affine(), affine(G2Affine::generator()));
    }

    #[test]
    fn scaled_doubling_matches_affine_oracle_on_entire_twist() {
        // This oracle uses affine tangent formulas over Arkworks fields,
        // independently of both libraries' projective doubling implementations.
        let affine_double = |p: G2Affine| {
            if p.infinity || p.y == ArkFq2::from(0u64) {
                return G2Affine::identity();
            }
            let slope = ArkFq2::from(3u64) * p.x.square() * (p.y + p.y).inverse().unwrap();
            let x = slope.square() - p.x - p.x;
            G2Affine::new_unchecked(x, slope * (p.x - x) - p.y)
        };
        let inverse_radix = ArkFq::from(2u64).pow([256]).inverse().unwrap();
        let decode = |v: Fq2| {
            let (c0, c1) = v.to_montgomery();
            // from_bigint also independently checks every raw output is canonical.
            let coefficient =
                |v: U256| ArkFq::from_bigint(ark_ff::BigInt(v.0)).unwrap() * inverse_radix;
            ArkFq2::new(coefficient(c0), coefficient(c1))
        };
        let normalize = |p: Projective| {
            let (x, y, z) = (decode(p.x), decode(p.y), decode(p.z));
            if z == ArkFq2::from(0u64) {
                G2Affine::identity()
            } else {
                let inverse = z.inverse().unwrap();
                G2Affine::new_unchecked(x * inverse.square(), y * inverse.square() * inverse)
            }
        };
        let mut rng = StdRng::seed_from_u64(0x6732_5f64_626c_7631);
        for i in 0..64 {
            let p = match i {
                0 => G2Affine::identity(),
                1 => G2Affine::generator(),
                2 => -G2Affine::generator(),
                _ => on_curve(&mut rng),
            };
            let torsion = p.mul_bigint(Fr::MODULUS).into_affine();
            let subgroup = G2Affine::generator()
                .mul_bigint(rng.random::<[u64; 4]>())
                .into_affine();
            let random_scale = ArkFq2::new(
                ArkFq::from_le_bytes_mod_order(&rng.random::<[u8; 32]>()),
                ArkFq::from_le_bytes_mod_order(&rng.random::<[u8; 32]>()),
            );
            assert_ne!(random_scale, ArkFq2::from(0u64));
            for p in [p, torsion, subgroup] {
                for z in [
                    ArkFq2::from(1u64),
                    -ArkFq2::from(1u64),
                    ArkFq2::new(-ArkFq::from(1u64), -ArkFq::from(1u64)),
                    ArkFq2::new(ArkFq::from(17u64), -ArkFq::from(3u64)),
                    random_scale,
                ] {
                    let mut actual = scaled(p, z);
                    let mut expected = p;
                    for step in 0..8 {
                        actual.double();
                        expected = affine_double(expected);
                        assert_eq!(normalize(actual), expected, "case={i}, step={step}");
                    }
                }
            }
        }
        // Preserve both early exits. The Y=0 fixture checks the existing guard
        // directly; it is not claimed to be an on-curve nonidentity point.
        for mut p in [
            Projective {
                x: Fq2::ONE,
                y: Fq2::ONE,
                z: Fq2::ZERO,
            },
            Projective {
                x: Fq2::ONE,
                y: Fq2::ZERO,
                z: Fq2::ONE,
            },
        ] {
            p.double();
            assert_eq!(
                (p.x, p.y, p.z),
                (
                    Projective::IDENTITY.x,
                    Projective::IDENTITY.y,
                    Projective::IDENTITY.z
                )
            );
        }
    }

    #[test]
    fn subgroup_criterion_has_no_cofactor_kernel() {
        let q = BigUint::from_bytes_le(&ArkFq::MODULUS.to_bytes_le());
        let r = BigUint::from_bytes_le(&Fr::MODULUS.to_bytes_le());
        let x = BigUint::from(BN_X);
        let t = &x * &x * 6u8 + 1u8;
        let h = ark_bn254::g2::Config::COFACTOR
            .iter()
            .rev()
            .fold(BigUint::from(0u8), |acc, limb| (acc << 64) + limb);
        assert_eq!(
            q,
            x.pow(4) * 36u8 + x.pow(3) * 36u8 + x.pow(2) * 24u8 + &x * 6u8 + 1u8
        );
        assert_eq!(r, &q + 1u8 - &t);
        assert_eq!(h, &q * 2u8 - &r);
        assert_ne!(BN_X % 21961, 5422);

        // f(T)=(x+1)+x*T+x*T^2-2*x*T^3 vanishes at T=q modulo r.
        assert_eq!(
            (&x + 1u8 + &x * &q + &x * q.pow(2)) % &r,
            (&x * q.pow(3) * 2u8) % &r,
        );
        // Reduce f modulo T^2-t*T+q to a+b*T. Multiplying by its
        // conjugate a+b*(t-T) shows f(psi)P=0 implies [norm]P=0.
        let a = &x + 1u8 + &x * &q * (&t * 2u8 - 1u8);
        let b = &x * (&q * 2u8 + &t + 1u8 - t.pow(2) * 2u8);
        let norm = a.pow(2) + &a * &b * &t + b.pow(2) * &q;
        let mut left = norm;
        let mut right = &h * &r;
        while right != BigUint::from(0u8) {
            let remainder = &left % &right;
            left = right;
            right = remainder;
        }
        // A point satisfying the condition has order dividing r, with
        // no possible cofactor component. This uses the actual BN254 seed.
        assert_eq!(left, r);
    }

    fn on_curve(rng: &mut StdRng) -> G2Affine {
        let mut field = || loop {
            let mut limbs = rng.random::<[u64; 4]>();
            limbs[3] &= (1 << 62) - 1;
            if let Some(value) = ArkFq::from_bigint(ark_ff::BigInt(limbs)) {
                break value;
            }
        };
        loop {
            if let Some(p) =
                G2Affine::get_point_from_x_unchecked(ArkFq2::new(field(), field()), false)
            {
                return p;
            }
        }
    }

    fn scaled(p: G2Affine, z: ArkFq2) -> Projective {
        if p.infinity {
            Projective::IDENTITY
        } else {
            Projective {
                x: fq2(p.x * z.square()),
                y: fq2(p.y * z.square() * z),
                z: fq2(z),
            }
        }
    }

    #[test]
    fn fixed_bn_chain_matches_binary_oracle_on_entire_twist() {
        let check = |p: G2Affine| {
            let input = affine(p);
            let actual = input.mul_by_bn_x();
            let expected = p.mul_bigint([BN_X]).into_affine();
            assert_eq!(actual.to_affine(), affine(expected));
            assert!(actual.matches(&input.mul_projective(&[BN_X])));
        };
        for p in [
            G2Affine::identity(),
            G2Affine::generator(),
            -G2Affine::generator(),
        ] {
            check(p);
        }
        let mut rng = StdRng::seed_from_u64(0x6732_5f63_6861_696e);
        for _ in 0..64 {
            let arbitrary = on_curve(&mut rng);
            let torsion = arbitrary.mul_bigint(Fr::MODULUS).into_affine();
            let subgroup = arbitrary
                .mul_bigint(ark_bn254::g2::Config::COFACTOR)
                .into_affine();
            assert!(!torsion.infinity);
            assert!(subgroup.mul_bigint(Fr::MODULUS).into_affine().infinity);
            for p in [
                arbitrary,
                -arbitrary,
                torsion,
                -torsion,
                subgroup,
                -subgroup,
                (subgroup + torsion).into_affine(),
            ] {
                check(p);
            }
        }
    }

    #[test]
    fn projective_addition_and_equality_on_entire_twist() {
        let mut rng = StdRng::seed_from_u64(0x6732_5f70_726a_6164);
        let scales = [
            ArkFq2::from(1u64),
            -ArkFq2::from(1u64),
            ArkFq2::new(ArkFq::from(17u64), -ArkFq::from(3u64)),
        ];
        for _ in 0..32 {
            let p = on_curve(&mut rng);
            let q = on_curve(&mut rng);
            for z in scales {
                let a = scaled(p, z);
                assert!(!a.matches(&Projective::IDENTITY));
                assert!(!Projective::IDENTITY.matches(&a));
                for w in scales {
                    assert!(a.matches(&scaled(p, w)));
                    assert!(!a.matches(&scaled(-p, w)));
                    for rhs in [p, -p, q, G2Affine::identity()] {
                        let b = scaled(rhs, w);
                        let mut sum = a;
                        sum.add(&b);
                        let expected = affine((p + rhs).into_affine());
                        assert_eq!(sum.to_affine(), expected);
                        assert!(sum.matches(&Projective::from_affine(&expected)));
                    }
                }
                let mut zero = Projective::IDENTITY;
                zero.add(&a);
                assert_eq!(zero.to_affine(), affine(p));
            }
        }
        let mut zero = Projective::IDENTITY;
        zero.add(&Projective::IDENTITY);
        assert!(zero.matches(&Projective::IDENTITY));
    }

    #[test]
    fn projective_frobenius_matches_field_powers_and_characteristic_equation() {
        let q = BigUint::from_bytes_le(&ArkFq::MODULUS.to_bytes_le());
        let xi = ArkFq2::new(ArkFq::from(9u64), ArkFq::from(1u64));
        let cx = xi.pow(((&q - 1u8) / 3u8).to_u64_digits());
        let cy = xi.pow(((&q - 1u8) / 2u8).to_u64_digits());
        let t = BigUint::from(BN_X).pow(2) * 6u8 + 1u8;
        let image = |p: G2Affine| {
            if p.infinity {
                p
            } else {
                G2Affine::new_unchecked(
                    p.x.pow(q.to_u64_digits()) * cx,
                    p.y.pow(q.to_u64_digits()) * cy,
                )
            }
        };
        let mut rng = StdRng::seed_from_u64(0x6732_5f70_7369_7631);
        let points = [
            G2Affine::identity(),
            G2Affine::generator(),
            -G2Affine::generator(),
        ]
        .into_iter()
        .chain((0..32).map(|_| on_curve(&mut rng)));
        for p in points {
            let psi = image(p);
            assert!(psi.is_on_curve());
            assert_eq!(
                (image(psi) + p.mul_bigint(ArkFq::MODULUS)).into_affine(),
                psi.mul_bigint(t.to_u64_digits()).into_affine(),
            );
            for z in [
                ArkFq2::from(1u64),
                ArkFq2::new(ArkFq::from(17u64), -ArkFq::from(3u64)),
            ] {
                let mut actual = scaled(p, z);
                let mut expected = p;
                for _ in 0..3 {
                    actual = actual.frobenius();
                    expected = image(expected);
                    assert_eq!(actual.to_affine(), affine(expected));
                }
            }
        }
    }

    #[test]
    fn conjugate_endomorphism_matches_independent_g2_eigenvalue() {
        use ark_ec::scalar_mul::glv::GLVConfig;
        let beta = ark_bn254::g2::Config::ENDO_COEFFS[0];
        let lambda = ark_bn254::g2::Config::LAMBDA.square();
        assert_eq!(lambda, ark_bn254::g1::Config::LAMBDA);
        assert_eq!(beta.c1, ArkFq::from(0u64));
        assert_ne!(beta, ArkFq2::from(1u64));
        assert_eq!(
            beta.square() + beta + ArkFq2::from(1u64),
            ArkFq2::from(0u64)
        );
        assert_eq!(
            fq2(beta.square()),
            Fq2 {
                c0: BETA_SQUARED_MONT,
                c1: U256::zero()
            },
        );
        let mut rng = StdRng::seed_from_u64(0x6732_5f67_6c76_656e);
        for i in 0..64 {
            let p = match i {
                0 => G2Affine::identity(),
                1 => G2Affine::generator(),
                2 => -G2Affine::generator(),
                _ => G2Affine::generator()
                    .mul_bigint(rng.random::<[u64; 4]>())
                    .into_affine(),
            };
            // Affine mul_bigint uses independent binary multiplication, with
            // no subgroup-specific scalar decomposition or endomorphism.
            let expected = p.mul_bigint(lambda.into_bigint()).into_affine();
            assert_eq!(affine(p).endomorphism(), affine(expected));
        }
    }

    #[test]
    fn glv_joint_components_with_both_signs_match_binary_oracle() {
        use ark_ec::scalar_mul::glv::GLVConfig;
        let lambda = ark_bn254::g2::Config::LAMBDA.square();
        let mut rng = StdRng::seed_from_u64(0x6732_5f67_6c76_7367);
        let magnitudes = [0u128, 1, 2, 3, u64::MAX as u128, 1 << 127, u128::MAX];
        for i in 0..11 {
            let p = match i {
                0 => G2Affine::identity(),
                1 => G2Affine::generator(),
                2 => -G2Affine::generator(),
                _ => G2Affine::generator()
                    .mul_bigint(rng.random::<[u64; 4]>())
                    .into_affine(),
            };
            let image = p.mul_bigint(lambda.into_bigint()).into_affine();
            for k1 in magnitudes {
                for k2 in magnitudes {
                    let left = p.mul_bigint([k1 as u64, (k1 >> 64) as u64]);
                    let right = image.mul_bigint([k2 as u64, (k2 >> 64) as u64]);
                    for k2_negative in [false, true] {
                        let split = glv::SplitScalar {
                            k1,
                            k2,
                            k2_negative,
                        };
                        let expected =
                            (left + if k2_negative { -right } else { right }).into_affine();
                        let expected = affine(expected);
                        assert_eq!(affine(p).mul_glv(&split.joint_digits()), expected);
                        assert_eq!(affine(p).mul_glv_window::<3, 2>(&split), Some(expected));
                        assert_eq!(affine(p).mul_glv_window::<4, 4>(&split), Some(expected));
                        assert_eq!(affine(p).mul_glv_window::<5, 8>(&split), Some(expected));
                    }
                }
            }
        }
    }

    #[test]
    fn glv_table_both_signs_match_full_twist_addition() {
        use ark_ec::scalar_mul::glv::GLVConfig;
        let gamma = ark_bn254::g2::Config::ENDO_COEFFS[0].square();
        let check = |p: G2Affine| {
            let image = if p.infinity {
                p
            } else {
                G2Affine::new_unchecked(p.x * gamma, p.y)
            };
            assert!(image.is_on_curve());
            for k2_negative in [false, true] {
                let split = glv::SplitScalar {
                    k1: 1,
                    k2: 1,
                    k2_negative,
                };
                let expected = (p + if k2_negative { -image } else { image }).into_affine();
                let expected = affine(expected);
                assert_eq!(affine(p).mul_glv(&split.joint_digits()), expected);
                assert_eq!(affine(p).mul_glv_window::<3, 2>(&split), Some(expected));
                assert_eq!(affine(p).mul_glv_window::<4, 4>(&split), Some(expected));
                assert_eq!(affine(p).mul_glv_window::<5, 8>(&split), Some(expected));
            }
        };
        for p in [
            G2Affine::identity(),
            G2Affine::generator(),
            -G2Affine::generator(),
        ] {
            check(p);
        }
        let mut rng = StdRng::seed_from_u64(0x6732_5f74_6162_6c65);
        for _ in 0..64 {
            let p = on_curve(&mut rng);
            check(p);
            check(-p);
        }
        // Exercise the repeated-root horizontal-line case if x=0 is on this twist.
        use ark_ec::short_weierstrass::SWCurveConfig;
        if let Some(y) = ark_bn254::g2::Config::COEFF_B.sqrt() {
            let p = G2Affine::new_unchecked(ArkFq2::from(0u64), y);
            check(p);
            check(-p);
        }
    }

    #[test]
    fn checked_glv_at_negative_component_quotient_boundaries() {
        // These rare negative components are missed by uniform random scalars.
        let boundaries = [
            [
                0x01624731e1195570,
                0x3ba491482db4da14,
                0x59e26bcea0d48bac,
                0,
            ],
            [
                0x02c48e63c232aadf,
                0x774922905b69b428,
                0xb3c4d79d41a91758,
                0,
            ],
            [
                0x0426d595a34c004e,
                0xb2edb3d8891e8e3c,
                0x0da7436be27da304,
                1,
            ],
        ];
        let mut rng = StdRng::seed_from_u64(0x6732_5f67_6c76_6264);
        for limbs in boundaries {
            assert!(glv::decompose(&U256::new(limbs)).k2_negative);
            for low in [limbs[0] - 1, limbs[0], limbs[0] + 1] {
                let scalar = U256::new([low, limbs[1], limbs[2], limbs[3]]);
                for i in 0..8 {
                    let p = match i {
                        0 => G2Affine::generator(),
                        1 => -G2Affine::generator(),
                        _ => G2Affine::generator()
                            .mul_bigint(rng.random::<[u64; 4]>())
                            .into_affine(),
                    };
                    let expected = p.mul_bigint(scalar.0).into_affine();
                    assert_eq!(
                        affine(p).mul_scalar_checked(&scalar),
                        Some(affine(expected))
                    );
                }
            }
        }
    }
}
