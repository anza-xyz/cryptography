//! P-256 base field arithmetic.
//!
//! [`FieldElement`] represents an element of GF(p) where
//! `p = 2^256 - 2^224 + 2^192 + 2^96 - 1` (the P-256 field prime).
//! Internally elements are stored in Montgomery form; use
//! [`from_be_bytes`][FieldElement::from_be_bytes] and
//! [`to_be_bytes`][FieldElement::to_be_bytes] to convert from/to canonical
//! big-endian representation.

use core::ops::{Add, Mul, Neg, Sub};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FieldElement {
    limbs: [u64; 4],
}

const MODULUS: [u64; 4] = [
    0xffff_ffff_ffff_ffff,
    0x0000_0000_ffff_ffff,
    0x0000_0000_0000_0000,
    0xffff_ffff_0000_0001,
];

const R2: [u64; 4] = [
    0x0000_0000_0000_0003,
    0xffff_fffb_ffff_ffff,
    0xffff_ffff_ffff_fffe,
    0x0000_0004_ffff_fffd,
];

const P_PLUS_ONE_DIV_4: [u8; 32] = [
    0x3f, 0xff, 0xff, 0xff, 0xc0, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

impl FieldElement {
    pub const ZERO: Self = Self { limbs: [0; 4] };
    pub const ONE: Self = Self {
        limbs: [
            0x0000_0000_0000_0001,
            0xffff_ffff_0000_0000,
            0xffff_ffff_ffff_ffff,
            0x0000_0000_ffff_fffe,
        ],
    };

    #[inline]
    pub fn from_u64(value: u64) -> Self {
        Self::from_canonical_limbs([value, 0, 0, 0]).expect("u64 is canonical")
    }

    #[inline]
    pub fn from_be_bytes(bytes: [u8; 32]) -> Option<Self> {
        Self::from_canonical_limbs(limbs_from_be_bytes(bytes))
    }

    #[inline]
    pub fn to_be_bytes(self) -> [u8; 32] {
        be_bytes_from_limbs(from_montgomery(self.limbs))
    }

    #[inline]
    pub fn is_zero(self) -> bool {
        self == Self::ZERO
    }

    #[inline]
    pub fn square(self) -> Self {
        Self {
            limbs: montgomery_square(self.limbs),
        }
    }

    #[inline]
    pub fn invert(self) -> Option<Self> {
        if self.is_zero() {
            return None;
        }

        Some(Self {
            limbs: montgomery_mul(invert_canonical(from_montgomery(self.limbs)), R2),
        })
    }

    #[inline]
    pub(crate) fn sqrt(self) -> Option<Self> {
        let candidate = self.pow(P_PLUS_ONE_DIV_4);
        (candidate.square() == self).then_some(candidate)
    }

    #[inline]
    fn pow(self, exponent: [u8; 32]) -> Self {
        let mut out = Self::ONE;

        for byte in exponent {
            for bit in (0..8).rev() {
                out = out.square();
                if ((byte >> bit) & 1) == 1 {
                    out = out * self;
                }
            }
        }

        out
    }

    #[inline]
    pub fn montgomery_limbs(self) -> [u64; 4] {
        self.limbs
    }

    #[inline]
    pub(crate) const fn from_montgomery_limbs(limbs: [u64; 4]) -> Self {
        Self { limbs }
    }

    #[inline]
    fn from_canonical_limbs(limbs: [u64; 4]) -> Option<Self> {
        if ge_limbs(limbs, MODULUS) {
            None
        } else {
            Some(Self {
                limbs: montgomery_mul(limbs, R2),
            })
        }
    }
}

impl Add for FieldElement {
    type Output = Self;

    #[inline]
    fn add(self, rhs: Self) -> Self::Output {
        let (sum, carry) = add_limbs(self.limbs, rhs.limbs);
        Self {
            limbs: reduce_sum(sum, carry),
        }
    }
}

impl Sub for FieldElement {
    type Output = Self;

    #[inline]
    fn sub(self, rhs: Self) -> Self::Output {
        let (difference, borrow) = sub_limbs(self.limbs, rhs.limbs);
        let (corrected, _) = add_limbs(difference, MODULUS);

        Self {
            limbs: if borrow == 0 { difference } else { corrected },
        }
    }
}

impl Mul for FieldElement {
    type Output = Self;

    #[inline]
    fn mul(self, rhs: Self) -> Self::Output {
        Self {
            limbs: montgomery_mul(self.limbs, rhs.limbs),
        }
    }
}

impl Neg for FieldElement {
    type Output = Self;

    #[inline]
    fn neg(self) -> Self::Output {
        if self.is_zero() {
            self
        } else {
            Self::ZERO - self
        }
    }
}

#[inline(always)]
fn add_limbs(a: [u64; 4], b: [u64; 4]) -> ([u64; 4], u64) {
    let mut out = [0; 4];
    let mut carry = 0u64;

    for i in 0..4 {
        let (sum, carry1) = a[i].overflowing_add(b[i]);
        let (sum, carry2) = sum.overflowing_add(carry);
        out[i] = sum;
        carry = u64::from(carry1 | carry2);
    }

    (out, carry)
}

#[inline(always)]
fn sub_limbs(a: [u64; 4], b: [u64; 4]) -> ([u64; 4], u64) {
    let mut out = [0; 4];
    let mut borrow = 0u64;

    for i in 0..4 {
        let (difference, borrow1) = a[i].overflowing_sub(b[i]);
        let (difference, borrow2) = difference.overflowing_sub(borrow);
        out[i] = difference;
        borrow = u64::from(borrow1 | borrow2);
    }

    (out, borrow)
}

#[inline(always)]
fn reduce_sum(sum: [u64; 4], carry: u64) -> [u64; 4] {
    let (reduced, borrow) = sub_limbs(sum, MODULUS);

    if carry != 0 || borrow == 0 {
        reduced
    } else {
        sum
    }
}

#[inline(always)]
fn ge_limbs(a: [u64; 4], b: [u64; 4]) -> bool {
    sub_limbs(a, b).1 == 0
}

#[inline(always)]
fn is_one_limbs(a: [u64; 4]) -> bool {
    a == [1, 0, 0, 0]
}

#[inline(always)]
fn is_even_limbs(a: [u64; 4]) -> bool {
    (a[0] & 1) == 0
}

#[inline(always)]
fn shr1_limbs(a: [u64; 4]) -> [u64; 4] {
    shr1_limbs_with_carry(a, 0)
}

#[inline(always)]
fn shr1_limbs_with_carry(a: [u64; 4], carry: u64) -> [u64; 4] {
    [
        (a[0] >> 1) | (a[1] << 63),
        (a[1] >> 1) | (a[2] << 63),
        (a[2] >> 1) | (a[3] << 63),
        (a[3] >> 1) | (carry << 63),
    ]
}

#[inline(always)]
fn half_mod(a: [u64; 4]) -> [u64; 4] {
    if is_even_limbs(a) {
        shr1_limbs(a)
    } else {
        let (sum, carry) = add_limbs(a, MODULUS);
        shr1_limbs_with_carry(sum, carry)
    }
}

#[inline(always)]
fn sub_mod(a: [u64; 4], b: [u64; 4]) -> [u64; 4] {
    let (difference, borrow) = sub_limbs(a, b);

    if borrow == 0 {
        difference
    } else {
        add_limbs(difference, MODULUS).0
    }
}

fn invert_canonical(value: [u64; 4]) -> [u64; 4] {
    let mut u = value;
    let mut v = MODULUS;
    let mut x1 = [1, 0, 0, 0];
    let mut x2 = [0; 4];

    while !is_one_limbs(u) && !is_one_limbs(v) {
        while is_even_limbs(u) {
            u = shr1_limbs(u);
            x1 = half_mod(x1);
        }

        while is_even_limbs(v) {
            v = shr1_limbs(v);
            x2 = half_mod(x2);
        }

        if ge_limbs(u, v) {
            u = sub_limbs(u, v).0;
            x1 = sub_mod(x1, x2);
        } else {
            v = sub_limbs(v, u).0;
            x2 = sub_mod(x2, x1);
        }
    }

    if is_one_limbs(u) { x1 } else { x2 }
}

#[inline(always)]
fn mul_wide(a: [u64; 4], b: [u64; 4]) -> [u64; 8] {
    let (w0, carry) = mac(0, a[0], b[0], 0);
    let (w1, carry) = mac(0, a[0], b[1], carry);
    let (w2, carry) = mac(0, a[0], b[2], carry);
    let (w3, w4) = mac(0, a[0], b[3], carry);

    let (w1, carry) = mac(w1, a[1], b[0], 0);
    let (w2, carry) = mac(w2, a[1], b[1], carry);
    let (w3, carry) = mac(w3, a[1], b[2], carry);
    let (w4, w5) = mac(w4, a[1], b[3], carry);

    let (w2, carry) = mac(w2, a[2], b[0], 0);
    let (w3, carry) = mac(w3, a[2], b[1], carry);
    let (w4, carry) = mac(w4, a[2], b[2], carry);
    let (w5, w6) = mac(w5, a[2], b[3], carry);

    let (w3, carry) = mac(w3, a[3], b[0], 0);
    let (w4, carry) = mac(w4, a[3], b[1], carry);
    let (w5, carry) = mac(w5, a[3], b[2], carry);
    let (w6, w7) = mac(w6, a[3], b[3], carry);

    [w0, w1, w2, w3, w4, w5, w6, w7]
}

#[inline(always)]
fn montgomery_mul(a: [u64; 4], b: [u64; 4]) -> [u64; 4] {
    montgomery_reduce(mul_wide(a, b))
}

#[inline(always)]
fn montgomery_square(a: [u64; 4]) -> [u64; 4] {
    let a0 = a[0] as u128;
    let a1 = a[1] as u128;
    let a2 = a[2] as u128;
    let a3 = a[3] as u128;

    let p00 = a0 * a0;
    let w0 = p00 as u64;
    let mut acc = p00 >> 64;
    let mut top = 0u64;

    let p01 = a0 * a1;
    top += (p01 >> 127) as u64;
    let (sum, overflow) = acc.overflowing_add(p01 << 1);
    let w1 = sum as u64;
    acc = sum >> 64;
    top += u64::from(overflow);

    acc |= (top as u128) << 64;
    top = 0;
    let p02 = a0 * a2;
    top += (p02 >> 127) as u64;
    let (sum, overflow) = acc.overflowing_add(p02 << 1);
    acc = sum;
    top += u64::from(overflow);
    let (sum, overflow) = acc.overflowing_add(a1 * a1);
    let w2 = sum as u64;
    acc = sum >> 64;
    top += u64::from(overflow);

    acc |= (top as u128) << 64;
    top = 0;
    let p03 = a0 * a3;
    top += (p03 >> 127) as u64;
    let (sum, overflow) = acc.overflowing_add(p03 << 1);
    acc = sum;
    top += u64::from(overflow);
    let p12 = a1 * a2;
    top += (p12 >> 127) as u64;
    let (sum, overflow) = acc.overflowing_add(p12 << 1);
    let w3 = sum as u64;
    acc = sum >> 64;
    top += u64::from(overflow);

    acc |= (top as u128) << 64;
    top = 0;
    let p13 = a1 * a3;
    top += (p13 >> 127) as u64;
    let (sum, overflow) = acc.overflowing_add(p13 << 1);
    acc = sum;
    top += u64::from(overflow);
    let (sum, overflow) = acc.overflowing_add(a2 * a2);
    let w4 = sum as u64;
    acc = sum >> 64;
    top += u64::from(overflow);

    acc |= (top as u128) << 64;
    top = 0;
    let p23 = a2 * a3;
    top += (p23 >> 127) as u64;
    let (sum, overflow) = acc.overflowing_add(p23 << 1);
    let w5 = sum as u64;
    acc = sum >> 64;
    top += u64::from(overflow);

    acc |= (top as u128) << 64;
    let (sum, overflow) = acc.overflowing_add(a3 * a3);
    let w6 = sum as u64;
    let w7 = (sum >> 64) as u64;
    debug_assert!(!overflow);

    montgomery_reduce_words(w0, w1, w2, w3, w4, w5, w6, w7)
}

#[inline(always)]
fn from_montgomery(a: [u64; 4]) -> [u64; 4] {
    montgomery_reduce([a[0], a[1], a[2], a[3], 0, 0, 0, 0])
}

#[inline(always)]
fn montgomery_reduce(input: [u64; 8]) -> [u64; 4] {
    montgomery_reduce_words(
        input[0], input[1], input[2], input[3], input[4], input[5], input[6], input[7],
    )
}

#[inline(always)]
#[allow(clippy::too_many_arguments)]
fn montgomery_reduce_words(
    r0: u64,
    r1: u64,
    r2: u64,
    r3: u64,
    r4: u64,
    r5: u64,
    r6: u64,
    r7: u64,
) -> [u64; 4] {
    let (r1, carry) = mac(r1, r0, MODULUS[1], r0);
    let (r2, carry) = adc(r2, 0, carry);
    let (r3, carry) = mac(r3, r0, MODULUS[3], carry);
    let (r4, carry2) = adc(r4, 0, carry);

    let (r2, carry) = mac(r2, r1, MODULUS[1], r1);
    let (r3, carry) = adc(r3, 0, carry);
    let (r4, carry) = mac(r4, r1, MODULUS[3], carry);
    let (r5, carry2) = adc(r5, carry2, carry);

    let (r3, carry) = mac(r3, r2, MODULUS[1], r2);
    let (r4, carry) = adc(r4, 0, carry);
    let (r5, carry) = mac(r5, r2, MODULUS[3], carry);
    let (r6, carry2) = adc(r6, carry2, carry);

    let (r4, carry) = mac(r4, r3, MODULUS[1], r3);
    let (r5, carry) = adc(r5, 0, carry);
    let (r6, carry) = mac(r6, r3, MODULUS[3], carry);
    let (r7, r8) = adc(r7, carry2, carry);

    reduce_wide([r4, r5, r6, r7, r8])
}

#[inline(always)]
fn reduce_wide(value: [u64; 5]) -> [u64; 4] {
    let (w0, borrow) = sbb(value[0], MODULUS[0], 0);
    let (w1, borrow) = sbb(value[1], MODULUS[1], borrow);
    let (w2, borrow) = sbb(value[2], MODULUS[2], borrow);
    let (w3, borrow) = sbb(value[3], MODULUS[3], borrow);
    let (_, borrow) = sbb(value[4], 0, borrow);

    if borrow == 0 {
        [w0, w1, w2, w3]
    } else {
        [value[0], value[1], value[2], value[3]]
    }
}

#[inline(always)]
fn adc(a: u64, b: u64, carry: u64) -> (u64, u64) {
    let sum = (a as u128) + (b as u128) + (carry as u128);
    (sum as u64, (sum >> 64) as u64)
}

#[inline(always)]
fn sbb(a: u64, b: u64, borrow: u64) -> (u64, u64) {
    let difference = (a as u128).wrapping_sub((b as u128) + (borrow as u128));
    (difference as u64, u64::from((difference >> 127) != 0))
}

#[inline(always)]
fn mac(a: u64, b: u64, c: u64, carry: u64) -> (u64, u64) {
    let product = (a as u128) + (b as u128) * (c as u128) + (carry as u128);
    (product as u64, (product >> 64) as u64)
}

#[inline]
fn limbs_from_be_bytes(bytes: [u8; 32]) -> [u64; 4] {
    let mut limbs = [0u64; 4];

    for (i, chunk) in bytes.chunks_exact(8).rev().enumerate() {
        limbs[i] = u64::from_be_bytes(chunk.try_into().expect("chunk length is 8"));
    }

    limbs
}

#[inline]
fn be_bytes_from_limbs(limbs: [u64; 4]) -> [u8; 32] {
    let mut bytes = [0u8; 32];

    for (i, limb) in limbs.iter().rev().enumerate() {
        bytes[i * 8..(i + 1) * 8].copy_from_slice(&limb.to_be_bytes());
    }

    bytes
}

#[cfg(test)]
mod tests {
    use super::FieldElement;
    use p256::{FieldElement as P256FieldElement, elliptic_curve::ff::PrimeField};

    const A: [u8; 32] = [
        0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60,
        0x70, 0x80,
    ];
    const B: [u8; 32] = [
        0x0f, 0xed, 0xcb, 0xa9, 0x87, 0x65, 0x43, 0x21, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99,
        0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00, 0x80, 0x70, 0x60, 0x50, 0x40, 0x30,
        0x20, 0x10,
    ];
    const P_MINUS_ONE: [u8; 32] = [
        0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xfe,
    ];
    const P: [u8; 32] = [
        0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff,
    ];

    fn p256_field(bytes: [u8; 32]) -> P256FieldElement {
        Option::from(P256FieldElement::from_repr(bytes.into())).unwrap()
    }

    fn assert_matches_p256(rust: FieldElement, p256: P256FieldElement, operation: &'static str) {
        let p256_bytes: [u8; 32] = p256.to_repr().into();
        assert_eq!(rust.to_be_bytes(), p256_bytes, "{operation}");
    }

    fn sample(mut seed: u64) -> [u8; 32] {
        let mut bytes = [0u8; 32];

        for chunk in bytes.chunks_exact_mut(8) {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            chunk.copy_from_slice(&seed.to_be_bytes());
        }

        // Keep samples well below p so generation cannot accidentally produce
        // a non-canonical field encoding.
        bytes[0] &= 0x7f;
        bytes
    }

    #[test]
    fn rejects_non_canonical_values() {
        assert!(FieldElement::from_be_bytes(P).is_none());
    }

    #[test]
    fn round_trips_canonical_values() {
        for bytes in [[0u8; 32], A, B, P_MINUS_ONE] {
            let element = FieldElement::from_be_bytes(bytes).unwrap();
            assert_eq!(element.to_be_bytes(), bytes);
        }
    }

    #[test]
    fn add_matches_p256() {
        assert_matches_p256(
            FieldElement::from_be_bytes(A).unwrap() + FieldElement::from_be_bytes(B).unwrap(),
            p256_field(A) + p256_field(B),
            "add",
        );
    }

    #[test]
    fn sub_matches_p256() {
        assert_matches_p256(
            FieldElement::from_be_bytes(A).unwrap() - FieldElement::from_be_bytes(B).unwrap(),
            p256_field(A) - p256_field(B),
            "sub",
        );
    }

    #[test]
    fn mul_matches_p256() {
        assert_matches_p256(
            FieldElement::from_be_bytes(A).unwrap() * FieldElement::from_be_bytes(B).unwrap(),
            p256_field(A) * p256_field(B),
            "mul",
        );
    }

    #[test]
    fn square_matches_p256() {
        assert_matches_p256(
            FieldElement::from_be_bytes(A).unwrap().square(),
            p256_field(A).square(),
            "square",
        );
    }

    #[test]
    fn invert_matches_p256() {
        assert!(FieldElement::ZERO.invert().is_none());

        for bytes in [A, B, P_MINUS_ONE] {
            let rust = FieldElement::from_be_bytes(bytes).unwrap();
            let p256 = p256_field(bytes);

            assert_matches_p256(
                rust.invert().unwrap(),
                Option::from(p256.invert()).unwrap(),
                "invert",
            );
            assert_eq!(
                (rust * rust.invert().unwrap()).to_be_bytes(),
                FieldElement::ONE.to_be_bytes()
            );
        }
    }

    #[test]
    fn edge_values_match_p256() {
        let rust = FieldElement::from_be_bytes(P_MINUS_ONE).unwrap();
        let p256 = p256_field(P_MINUS_ONE);
        let mut one_bytes = [0u8; 32];
        one_bytes[31] = 1;
        let rust_one = FieldElement::ONE;
        let p256_one = p256_field(one_bytes);

        assert_matches_p256(rust + rust, p256 + p256, "p_minus_one add");
        assert_matches_p256(rust - rust_one, p256 - p256_one, "p_minus_one sub");
        assert_matches_p256(rust * rust, p256 * p256, "p_minus_one mul");
        assert_matches_p256(rust.square(), p256.square(), "p_minus_one square");
    }

    #[test]
    fn arithmetic_matches_p256_for_many_samples() {
        for i in 0..256 {
            let a = sample(i);
            let b = sample(i ^ 0xa5a5_a5a5_a5a5_a5a5);
            let rust_a = FieldElement::from_be_bytes(a).unwrap();
            let rust_b = FieldElement::from_be_bytes(b).unwrap();
            let p256_a = p256_field(a);
            let p256_b = p256_field(b);

            assert_matches_p256(rust_a + rust_b, p256_a + p256_b, "add");
            assert_matches_p256(rust_a - rust_b, p256_a - p256_b, "sub");
            assert_matches_p256(rust_a * rust_b, p256_a * p256_b, "mul");
            assert_matches_p256(rust_a.square(), p256_a.square(), "square");
            if !rust_a.is_zero() {
                assert_matches_p256(
                    rust_a.invert().unwrap(),
                    Option::from(p256_a.invert()).unwrap(),
                    "invert",
                );
            }
        }
    }
}
