//! P-256 elliptic curve group operations.
//!
//! Points are represented in two forms:
//!
//! - [`AffinePoint`] — standard `(x, y)` coordinates, used for storage and
//!   table entries. Includes an `infinity` flag for the identity element.
//! - [`ProjectivePoint`] — Jacobian `(X : Y : Z)` coordinates, used during
//!   multi-step scalar multiplication to avoid per-step field inversions.
//!
//! Use [`ProjectivePoint::to_affine`] to convert back and pay the single
//! field inversion, or [`batch_normalize`][`ProjectivePoint`] implicitly via
//! the precomputed table builders.

use core::ops::{Add, Neg, Sub};
use std::sync::OnceLock;

use crate::Endianness;
use crate::field::FieldElement;

const BASE_WINDOWS: usize = 32;
const BASE_WINDOW_POINTS: usize = 256;
const SHAMIR_WINDOW_POINTS: usize = 16;

const CURVE_B: FieldElement = FieldElement::from_montgomery_limbs([
    0xd89c_df62_29c4_bddf,
    0xacf0_05cd_7884_3090,
    0xe5a2_20ab_f721_2ed6,
    0xdc30_061d_0487_4834,
]);

const GENERATOR_X: FieldElement = FieldElement::from_montgomery_limbs([
    0x79e7_30d4_18a9_143c,
    0x75ba_95fc_5fed_b601,
    0x79fb_732b_7762_2510,
    0x1890_5f76_a537_55c6,
]);

const GENERATOR_Y: FieldElement = FieldElement::from_montgomery_limbs([
    0xddf2_5357_ce95_560a,
    0x8b4a_b8e4_ba19_e45c,
    0xd2e8_8688_dd21_f325,
    0x8571_ff18_2588_5d85,
]);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AffinePoint {
    x: FieldElement,
    y: FieldElement,
    infinity: bool,
}

impl AffinePoint {
    pub const IDENTITY: Self = Self {
        x: FieldElement::ZERO,
        y: FieldElement::ZERO,
        infinity: true,
    };

    pub const GENERATOR: Self = Self {
        x: GENERATOR_X,
        y: GENERATOR_Y,
        infinity: false,
    };

    #[inline]
    pub fn identity() -> Self {
        Self::IDENTITY
    }

    #[inline]
    pub fn generator() -> Self {
        Self::GENERATOR
    }

    #[inline]
    pub fn new(x: FieldElement, y: FieldElement) -> Option<Self> {
        let point = Self {
            x,
            y,
            infinity: false,
        };

        point.is_on_curve().then_some(point)
    }

    #[inline]
    pub fn from_uncompressed(bytes: &[u8; 64], endianness: Endianness) -> Option<Self> {
        if bytes == &[0u8; 64] {
            return Some(Self::IDENTITY);
        }

        let mut x_bytes = [0u8; 32];
        let mut y_bytes = [0u8; 32];
        x_bytes.copy_from_slice(&bytes[0..32]);
        y_bytes.copy_from_slice(&bytes[32..64]);

        if endianness == Endianness::Little {
            x_bytes.reverse();
            y_bytes.reverse();
        }

        Self::new(
            FieldElement::from_be_bytes(x_bytes)?,
            FieldElement::from_be_bytes(y_bytes)?,
        )
    }

    #[inline]
    pub fn from_compressed(bytes: &[u8; 33], endianness: Endianness) -> Option<Self> {
        // `0x02`: Compressed point with an even Y-coordinate
        // `0x03`: Compressed point with an odd Y-coordinate
        if bytes[0] != 0x02 && bytes[0] != 0x03 {
            return None;
        }

        let mut x_bytes = [0u8; 32];
        x_bytes.copy_from_slice(&bytes[1..33]);

        if endianness == Endianness::Little {
            x_bytes.reverse();
        }

        let x = FieldElement::from_be_bytes(x_bytes)?;
        let rhs = x.square() * x - triple(x) + CURVE_B;
        let mut y = rhs.sqrt()?;

        if (y.to_be_bytes()[31] & 1) != (bytes[0] & 1) {
            y = -y;
        }

        ((y.to_be_bytes()[31] & 1) == (bytes[0] & 1)).then_some(Self {
            x,
            y,
            infinity: false,
        })
    }

    #[inline]
    pub fn to_projective(self) -> ProjectivePoint {
        if self.infinity {
            ProjectivePoint::IDENTITY
        } else {
            ProjectivePoint {
                x: self.x,
                y: self.y,
                z: FieldElement::ONE,
            }
        }
    }

    #[inline]
    pub fn to_uncompressed(self, endianness: Endianness) -> [u8; 64] {
        if self.is_identity() {
            return [0u8; 64];
        }

        let mut x_bytes = self.x.to_be_bytes();
        let mut y_bytes = self.y.to_be_bytes();

        if endianness == Endianness::Little {
            x_bytes.reverse();
            y_bytes.reverse();
        }

        let mut out = [0u8; 64];
        out[0..32].copy_from_slice(&x_bytes);
        out[32..64].copy_from_slice(&y_bytes);
        out
    }

    #[inline]
    pub fn to_compressed(self, endianness: Endianness) -> Option<[u8; 33]> {
        if self.is_identity() {
            return None;
        }

        let mut x_bytes = self.x.to_be_bytes();
        let y_bytes = self.y.to_be_bytes();

        let prefix = if (y_bytes[31] & 1) == 1 { 0x03 } else { 0x02 };

        if endianness == Endianness::Little {
            x_bytes.reverse();
        }

        let mut out = [0u8; 33];
        out[0] = prefix;
        out[1..33].copy_from_slice(&x_bytes);

        Some(out)
    }

    #[inline]
    pub fn is_identity(self) -> bool {
        self.infinity
    }

    #[inline]
    pub fn x(self) -> Option<FieldElement> {
        (!self.infinity).then_some(self.x)
    }

    #[inline]
    pub fn y(self) -> Option<FieldElement> {
        (!self.infinity).then_some(self.y)
    }

    #[inline]
    fn is_on_curve(self) -> bool {
        if self.infinity {
            return true;
        }

        let y2 = self.y.square();
        let x2 = self.x.square();
        let x3 = x2 * self.x;
        let three_x = triple(self.x);
        y2 == x3 - three_x + CURVE_B
    }
}

impl Neg for AffinePoint {
    type Output = Self;

    #[inline]
    fn neg(self) -> Self::Output {
        if self.infinity {
            self
        } else {
            Self {
                x: self.x,
                y: -self.y,
                infinity: false,
            }
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct ProjectivePoint {
    x: FieldElement,
    y: FieldElement,
    z: FieldElement,
}

impl PartialEq for ProjectivePoint {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        let self_is_identity = self.z.is_zero();
        let other_is_identity = other.z.is_zero();

        if self_is_identity || other_is_identity {
            return self_is_identity && other_is_identity;
        }

        let self_z2 = self.z.square();
        let other_z2 = other.z.square();
        let self_z3 = self_z2 * self.z;
        let other_z3 = other_z2 * other.z;

        // x1 * z2^2 == x2 * z1^2
        // y1 * z2^3 == y2 * z1^3

        self.x * other_z2 == other.x * self_z2 && self.y * other_z3 == other.y * self_z3
    }
}

impl Eq for ProjectivePoint {}

impl ProjectivePoint {
    pub const IDENTITY: Self = Self {
        x: FieldElement::ZERO,
        y: FieldElement::ONE,
        z: FieldElement::ZERO,
    };

    pub const GENERATOR: Self = Self {
        x: GENERATOR_X,
        y: GENERATOR_Y,
        z: FieldElement::ONE,
    };

    #[inline]
    pub fn identity() -> Self {
        Self::IDENTITY
    }

    #[inline]
    pub fn generator() -> Self {
        Self::GENERATOR
    }

    #[inline]
    pub fn from_affine(point: AffinePoint) -> Self {
        point.to_projective()
    }

    #[inline]
    pub fn to_affine(self) -> AffinePoint {
        match self.z.invert() {
            Some(zinv) => {
                let zinv2 = zinv.square();
                AffinePoint {
                    x: self.x * zinv2,
                    y: self.y * zinv2 * zinv,
                    infinity: false,
                }
            }
            None => AffinePoint::IDENTITY,
        }
    }

    #[inline]
    pub fn to_uncompressed(self, endianness: Endianness) -> [u8; 64] {
        self.to_affine().to_uncompressed(endianness)
    }

    #[inline]
    pub fn is_identity(self) -> bool {
        self.z.is_zero()
    }

    #[inline]
    pub fn has_affine_x(self, x: FieldElement) -> bool {
        !self.is_identity() && self.x == x * self.z.square()
    }

    #[inline]
    pub fn double(self) -> Self {
        if self.is_identity() || self.y.is_zero() {
            return Self::IDENTITY;
        }

        let xx = self.x.square();
        let yy = self.y.square();
        let yyyy = yy.square();
        let zz = self.z.square();
        let s = double((self.x + yy).square() - xx - yyyy);
        let m = triple(xx - zz.square());
        let x = m.square() - double(s);
        let y = m * (s - x) - double(double(double(yyyy)));
        let z = (self.y + self.z).square() - yy - zz;

        Self { x, y, z }
    }

    #[inline]
    pub fn add_mixed(self, rhs: AffinePoint) -> Self {
        if rhs.infinity {
            return self;
        }
        if self.is_identity() {
            return rhs.to_projective();
        }

        let z1z1 = self.z.square();
        let u2 = rhs.x * z1z1;
        let s2 = rhs.y * self.z * z1z1;
        let h = u2 - self.x;
        let slope_num = double(s2 - self.y);

        if h.is_zero() {
            return if slope_num.is_zero() {
                self.double()
            } else {
                Self::IDENTITY
            };
        }

        let hh = h.square();
        let i = double(double(hh));
        let j = h * i;
        let v = self.x * i;
        let x = slope_num.square() - j - double(v);
        let y = slope_num * (v - x) - double(self.y * j);
        let z = (self.z + h).square() - z1z1 - hh;

        Self { x, y, z }
    }

    #[inline]
    pub fn mul_scalar_vartime(self, scalar: [u8; 32]) -> Self {
        let mut table = [Self::IDENTITY; 16];
        table[1] = self;

        for i in 2..16 {
            table[i] = table[i - 1] + self;
        }
        let affine_table = batch_normalize(table);

        let mut out = Self::IDENTITY;

        for &byte in scalar.iter() {
            out = out.double().double().double().double();
            out = out.add_mixed(affine_table[(byte >> 4) as usize]);
            out = out.double().double().double().double();
            out = out.add_mixed(affine_table[(byte & 0x0f) as usize]);
        }

        out
    }

    #[inline]
    pub fn fixed_base_scalar_mul_vartime(scalar: [u8; 32]) -> Self {
        mul_window8_vartime(generator_window8_table(), &scalar)
    }

    #[inline]
    pub fn double_scalar_mul_vartime(
        generator_scalar: [u8; 32],
        point: AffinePoint,
        point_scalar: [u8; 32],
    ) -> Self {
        let generator_table = generator_window4_table();
        let point_table = window4_table(point);
        let mut out = Self::IDENTITY;

        for (&generator_byte, &point_byte) in generator_scalar.iter().zip(point_scalar.iter()) {
            out = double_n(out, 4)
                .add_mixed(generator_table[(generator_byte >> 4) as usize])
                .add_mixed(point_table[(point_byte >> 4) as usize]);
            out = double_n(out, 4)
                .add_mixed(generator_table[(generator_byte & 0x0f) as usize])
                .add_mixed(point_table[(point_byte & 0x0f) as usize]);
        }

        out
    }

    /// Computes `sum(scalars[i] * points[i])` using variable-time table
    /// lookups.
    ///
    /// Returns `None` when `points` and `scalars` have different lengths.
    /// This routine is intended for public inputs, such as syscall MSM
    /// plumbing; do not use it with secret scalars.
    #[inline]
    pub fn multi_scalar_mul_vartime(points: &[AffinePoint], scalars: &[[u8; 32]]) -> Option<Self> {
        if points.len() != scalars.len() {
            return None;
        }

        let tables: Vec<_> = points.iter().copied().map(window4_table).collect();
        let mut out = Self::IDENTITY;

        for byte_index in 0..32 {
            out = double_n(out, 4);
            for (table, scalar) in tables.iter().zip(scalars) {
                out = out.add_mixed(table[(scalar[byte_index] >> 4) as usize]);
            }

            out = double_n(out, 4);
            for (table, scalar) in tables.iter().zip(scalars) {
                out = out.add_mixed(table[(scalar[byte_index] & 0x0f) as usize]);
            }
        }

        Some(out)
    }
}

impl Add for ProjectivePoint {
    type Output = Self;

    #[inline]
    fn add(self, rhs: Self) -> Self::Output {
        if self.is_identity() {
            return rhs;
        }
        if rhs.is_identity() {
            return self;
        }

        let z1z1 = self.z.square();
        let z2z2 = rhs.z.square();
        let u1 = self.x * z2z2;
        let u2 = rhs.x * z1z1;
        let s1 = self.y * rhs.z * z2z2;
        let s2 = rhs.y * self.z * z1z1;

        if u1 == u2 {
            return if s1 == s2 {
                self.double()
            } else {
                Self::IDENTITY
            };
        }

        let h = u2 - u1;
        let i = double(h).square();
        let j = h * i;
        let slope_num = double(s2 - s1);
        let v = u1 * i;
        let x = slope_num.square() - j - double(v);
        let y = slope_num * (v - x) - double(s1 * j);
        let z = ((self.z + rhs.z).square() - z1z1 - z2z2) * h;

        Self { x, y, z }
    }
}

impl Sub for ProjectivePoint {
    type Output = Self;

    #[inline]
    fn sub(self, rhs: Self) -> Self::Output {
        self + (-rhs)
    }
}

impl Neg for ProjectivePoint {
    type Output = Self;

    #[inline]
    fn neg(self) -> Self::Output {
        Self {
            x: self.x,
            y: -self.y,
            z: self.z,
        }
    }
}

#[inline]
fn double(x: FieldElement) -> FieldElement {
    x + x
}

#[inline]
fn triple(x: FieldElement) -> FieldElement {
    x + x + x
}

fn generator_window8_table() -> &'static [[AffinePoint; BASE_WINDOW_POINTS]; BASE_WINDOWS] {
    static TABLE: OnceLock<Box<[[AffinePoint; BASE_WINDOW_POINTS]; BASE_WINDOWS]>> =
        OnceLock::new();

    TABLE
        .get_or_init(|| build_window8_table(ProjectivePoint::GENERATOR))
        .as_ref()
}

fn generator_window4_table() -> &'static [AffinePoint; SHAMIR_WINDOW_POINTS] {
    static TABLE: OnceLock<[AffinePoint; SHAMIR_WINDOW_POINTS]> = OnceLock::new();

    TABLE.get_or_init(|| window4_table(AffinePoint::GENERATOR))
}

fn window4_table(base: AffinePoint) -> [AffinePoint; SHAMIR_WINDOW_POINTS] {
    let mut projective = [ProjectivePoint::IDENTITY; SHAMIR_WINDOW_POINTS];

    for i in 1..SHAMIR_WINDOW_POINTS {
        projective[i] = projective[i - 1].add_mixed(base);
    }

    batch_normalize(projective)
}

fn batch_normalize<const N: usize>(points: [ProjectivePoint; N]) -> [AffinePoint; N] {
    let mut products = [FieldElement::ONE; N];
    let mut acc = FieldElement::ONE;

    for (i, point) in points.iter().enumerate() {
        products[i] = acc;
        if !point.is_identity() {
            acc = acc * point.z;
        }
    }

    let Some(mut acc_inverse) = acc.invert() else {
        return [AffinePoint::IDENTITY; N];
    };
    let mut out = [AffinePoint::IDENTITY; N];

    for i in (0..N).rev() {
        let point = points[i];
        if point.is_identity() {
            continue;
        }

        let z_inverse = acc_inverse * products[i];
        acc_inverse = acc_inverse * point.z;
        let z_inverse2 = z_inverse.square();
        out[i] = AffinePoint {
            x: point.x * z_inverse2,
            y: point.y * z_inverse2 * z_inverse,
            infinity: false,
        };
    }

    out
}

#[inline]
fn double_n(mut point: ProjectivePoint, count: usize) -> ProjectivePoint {
    for _ in 0..count {
        point = point.double();
    }

    point
}

fn build_window8_table(
    mut base: ProjectivePoint,
) -> Box<[[AffinePoint; BASE_WINDOW_POINTS]; BASE_WINDOWS]> {
    let mut rows = Vec::with_capacity(BASE_WINDOWS);

    for _ in 0..BASE_WINDOWS {
        rows.push(projective_window8_table(base));

        for _ in 0..8 {
            base = base.double();
        }
    }

    rows.into_boxed_slice()
        .try_into()
        .expect("fixed-point table has the expected number of rows")
}

fn projective_window8_table(base: ProjectivePoint) -> [AffinePoint; BASE_WINDOW_POINTS] {
    let mut projective = [ProjectivePoint::IDENTITY; BASE_WINDOW_POINTS];
    let mut multiple = ProjectivePoint::IDENTITY;

    for entry in projective.iter_mut().skip(1) {
        multiple = multiple + base;
        *entry = multiple;
    }

    batch_normalize(projective)
}

#[inline]
fn mul_window8_vartime(
    table: &[[AffinePoint; BASE_WINDOW_POINTS]; BASE_WINDOWS],
    scalar: &[u8; 32],
) -> ProjectivePoint {
    let mut out = ProjectivePoint::IDENTITY;

    for (window, byte) in scalar.iter().rev().enumerate() {
        out = out.add_mixed(table[window][*byte as usize]);
    }

    out
}

#[cfg(test)]
mod tests {
    use super::{AffinePoint, ProjectivePoint};
    use crate::{Endianness, field::FieldElement};
    use p256::{
        ProjectivePoint as P256ProjectivePoint, Scalar,
        elliptic_curve::{ff::PrimeField, group::Group, sec1::ToEncodedPoint},
    };

    const SCALAR: [u8; 32] = [
        0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
        0x77, 0x88,
    ];
    const SMALL_SCALAR: [u8; 32] = [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 5,
    ];

    fn assert_matches_p256(rust: ProjectivePoint, p256: P256ProjectivePoint) {
        let rust_bytes = rust.to_uncompressed(Endianness::Big);
        let p256_bytes = p256.to_affine().to_encoded_point(false);
        assert_eq!(rust_bytes.as_slice(), &p256_bytes.as_bytes()[1..]);
    }

    #[test]
    fn generator_matches_p256() {
        assert_matches_p256(
            ProjectivePoint::generator(),
            P256ProjectivePoint::generator(),
        );
    }

    #[test]
    fn parses_and_serializes_generator() {
        let bytes = ProjectivePoint::generator().to_uncompressed(Endianness::Big);
        assert_eq!(
            AffinePoint::from_uncompressed(&bytes, Endianness::Big).unwrap(),
            AffinePoint::generator()
        );
    }

    #[test]
    fn projective_equality_ignores_jacobian_scale() {
        let point = ProjectivePoint::generator().double();
        let normalized = ProjectivePoint::from_affine(point.to_affine());
        assert_eq!(point, normalized);

        let z = FieldElement::from_u64(7);
        let z2 = z.square();
        let scaled = ProjectivePoint {
            x: point.x * z2,
            y: point.y * z2 * z,
            z: point.z * z,
        };

        assert_eq!(point, scaled);
        assert_ne!(point, -point);
    }

    #[test]
    fn double_matches_p256() {
        let p256 = P256ProjectivePoint::generator().double();
        assert_matches_p256(ProjectivePoint::generator().double(), p256);
    }

    #[test]
    fn add_matches_p256() {
        let rust_g = ProjectivePoint::generator();
        let rust_2g = rust_g.double();
        let p256_g = P256ProjectivePoint::generator();
        let p256_2g = p256_g.double();

        assert_matches_p256(rust_2g + rust_g, p256_2g + p256_g);
    }

    #[test]
    fn mixed_add_matches_p256() {
        let rust_g = ProjectivePoint::generator();
        let rust_2g = rust_g.double();
        let p256_g = P256ProjectivePoint::generator();
        let p256_2g = p256_g.double();

        assert_matches_p256(
            rust_2g.add_mixed(AffinePoint::generator()),
            p256_2g + p256_g,
        );
    }

    #[test]
    fn scalar_mul_matches_p256() {
        let scalar = Option::<Scalar>::from(Scalar::from_repr(SCALAR.into())).unwrap();
        assert_matches_p256(
            ProjectivePoint::generator().mul_scalar_vartime(SCALAR),
            P256ProjectivePoint::generator() * scalar,
        );
    }

    #[test]
    fn fixed_base_scalar_mul_matches_p256() {
        let scalar = Option::<Scalar>::from(Scalar::from_repr(SCALAR.into())).unwrap();
        assert_matches_p256(
            ProjectivePoint::fixed_base_scalar_mul_vartime(SCALAR),
            P256ProjectivePoint::generator() * scalar,
        );
    }

    #[test]
    fn double_scalar_mul_matches_p256() {
        let scalar = Option::<Scalar>::from(Scalar::from_repr(SCALAR.into())).unwrap();
        let point = ProjectivePoint::generator().double().to_affine();
        let p256_point = P256ProjectivePoint::generator().double();

        assert_matches_p256(
            ProjectivePoint::double_scalar_mul_vartime(SCALAR, point, SCALAR),
            (P256ProjectivePoint::generator() * scalar) + (p256_point * scalar),
        );
    }

    #[test]
    fn multi_scalar_mul_matches_p256() {
        let scalar = Option::<Scalar>::from(Scalar::from_repr(SCALAR.into())).unwrap();
        let small_scalar = Option::<Scalar>::from(Scalar::from_repr(SMALL_SCALAR.into())).unwrap();
        let point = ProjectivePoint::generator().double().to_affine();
        let p256_point = P256ProjectivePoint::generator().double();

        assert_matches_p256(
            ProjectivePoint::multi_scalar_mul_vartime(
                &[AffinePoint::generator(), point],
                &[SCALAR, SMALL_SCALAR],
            )
            .unwrap(),
            (P256ProjectivePoint::generator() * scalar) + (p256_point * small_scalar),
        );
    }

    #[test]
    fn multi_scalar_mul_rejects_length_mismatch() {
        assert!(
            ProjectivePoint::multi_scalar_mul_vartime(&[AffinePoint::generator()], &[]).is_none()
        );
    }

    #[test]
    fn parses_and_serializes_little_endian() {
        let point = AffinePoint::generator();

        let be_bytes = point.to_uncompressed(Endianness::Big);
        let le_bytes = point.to_uncompressed(Endianness::Little);

        assert_ne!(be_bytes, le_bytes);
        assert_eq!(
            AffinePoint::from_uncompressed(&le_bytes, Endianness::Little).unwrap(),
            point
        );
    }

    #[test]
    fn parses_and_serializes_compressed() {
        let point = AffinePoint::generator();

        let be_compressed = point.to_compressed(Endianness::Big).unwrap();
        let le_compressed = point.to_compressed(Endianness::Little).unwrap();

        assert_eq!(
            AffinePoint::from_compressed(&be_compressed, Endianness::Big).unwrap(),
            point
        );
        assert_eq!(
            AffinePoint::from_compressed(&le_compressed, Endianness::Little).unwrap(),
            point
        );
    }

    #[test]
    fn rejects_invalid_compressed_prefixes() {
        let mut bytes = [0u8; 33];

        // Test the SEC1 identity marker (0x00)
        assert!(AffinePoint::from_compressed(&bytes, Endianness::Big).is_none());

        // Test the unassigned marker (0x01)
        bytes[0] = 0x01;
        assert!(AffinePoint::from_compressed(&bytes, Endianness::Big).is_none());

        // Test the uncompressed marker (0x04)
        bytes[0] = 0x04;
        assert!(AffinePoint::from_compressed(&bytes, Endianness::Big).is_none());
    }

    #[test]
    fn enforces_identity_point_rules() {
        let identity = AffinePoint::IDENTITY;

        // Uncompressed correctly handles the 64-byte zero array
        assert_eq!(identity.to_uncompressed(Endianness::Big), [0u8; 64]);
        assert_eq!(
            AffinePoint::from_uncompressed(&[0u8; 64], Endianness::Big).unwrap(),
            identity
        );

        // Compressed correctly refuses to serialize the identity point
        assert!(identity.to_compressed(Endianness::Big).is_none());
    }
}
