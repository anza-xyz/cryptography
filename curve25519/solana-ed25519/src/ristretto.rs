// -*- mode: rust; -*-
//
// This file is part of curve25519.
// Copyright (c) 2016-2021 isis lovecruft
// Copyright (c) 2016-2020 Henry de Valence
// See LICENSE for licensing information.
//
// Authors:
// - isis agora lovecruft <isis@patternsinthevoid.net>
// - Henry de Valence <hdevalence@hdevalence.ca>

// We allow non snake_case names because coordinates in projective space are
// traditionally denoted by the capitalisation of their respective
// counterparts in affine space.  Yeah, you heard me, rustc, I'm gonna have my
// affine and projective cakes and eat both of them too.
#![allow(non_snake_case)]

//! An implementation of [Ristretto][ristretto_main], which provides a
//! prime-order group.
//!
//! # The Ristretto Group
//!
//! Ristretto is a modification of Mike Hamburg's Decaf scheme to work
//! with cofactor-\\(8\\) curves, such as Curve25519.
//!
//! The introduction of the Decaf paper, [_Decaf:
//! Eliminating cofactors through point
//! compression_](https://eprint.iacr.org/2015/673.pdf), notes that while
//! most cryptographic systems require a group of prime order, most
//! concrete implementations using elliptic curve groups fall short –
//! they either provide a group of prime order, but with incomplete or
//! variable-time addition formulae (for instance, most Weierstrass
//! models), or else they provide a fast and safe implementation of a
//! group whose order is not quite a prime \\(q\\), but \\(hq\\) for a
//! small cofactor \\(h\\) (for instance, Edwards curves, which have
//! cofactor at least \\(4\\)).
//!
//! This abstraction mismatch is commonly “handled” by pushing the
//! complexity upwards, adding ad-hoc protocol modifications.  But
//! these modifications require careful analysis and are a recurring
//! source of [vulnerabilities][cryptonote] and [design
//! complications][ed25519_hkd].
//!
//! Instead, Decaf (and Ristretto) use a quotient group to implement a
//! prime-order group using a non-prime-order curve.  This provides
//! the correct abstraction for cryptographic systems, while retaining
//! the speed and safety benefits of an Edwards curve.
//!
//! Decaf is named “after the procedure which divides the effect of
//! coffee by \\(4\\)”.  However, Curve25519 has a cofactor of
//! \\(8\\).  To eliminate its cofactor, Ristretto restricts further;
//! this [additional restriction][ristretto_coffee] gives the
//! _Ristretto_ encoding.
//!
//! More details on why Ristretto is necessary can be found in the
//! [Why Ristretto?][why_ristretto] section of the Ristretto website.
//!
//! Ristretto
//! points are provided in `curve25519` by the `RistrettoPoint`
//! struct.
//!
//! ## Encoding and Decoding
//!
//! Encoding is done by converting to and from a `CompressedRistretto`
//! struct, which is a typed wrapper around `[u8; 32]`.
//!
//! The encoding is not batchable, but it is possible to
//! double-and-encode in a batch using
//! `RistrettoPoint::double_and_compress_batch`.
//!
//! ## Equality Testing
//!
//! Testing equality of points on an Edwards curve in projective
//! coordinates requires an expensive inversion.  By contrast, equality
//! checking in the Ristretto group can be done in projective
//! coordinates without requiring an inversion, so it is much faster.
//!
//! The `RistrettoPoint` struct implements the
//! [`subtle::ConstantTimeEq`] trait for constant-time equality
//! checking, and also uses this to ensure `Eq` equality checking
//! runs in constant time.
//!
//! ## Scalars
//!
//! Scalars are represented by the `Scalar` struct.  Each scalar has a
//! canonical representative mod the group order.  To attempt to load
//! a supposedly-canonical scalar, use
//! `Scalar::from_canonical_bytes()`. To check whether a
//! representative is canonical, use `Scalar::is_canonical()`.
//!
//! ## Scalar Multiplication
//!
//! Scalar multiplication on Ristretto points is provided by:
//!
//! * the `*` operator between a `Scalar` and a `RistrettoPoint`, which
//!   performs constant-time variable-base scalar multiplication;
//!
//! * the `*` operator between a `Scalar` and a
//!   `RistrettoBasepointTable`, which performs constant-time fixed-base
//!   scalar multiplication;
//!
//! * an implementation of the
//!   [`MultiscalarMul`](../traits/trait.MultiscalarMul.html) trait for
//!   constant-time variable-base multiscalar multiplication;
//!
//! * an implementation of the
//!   [`VartimeMultiscalarMul`](../traits/trait.VartimeMultiscalarMul.html)
//!   trait for variable-time variable-base multiscalar multiplication;
//!
//! ## Random Points and Hashing to Ristretto
//!
//! The Ristretto group comes equipped with an Elligator map.  This is
//! used to implement
//!
//! * `RistrettoPoint::random()`, which generates random points from an
//!   RNG - enabled by `rand_core` feature;
//!
//! * `RistrettoPoint::from_hash()` and
//!   `RistrettoPoint::hash_from_bytes()`, which perform hashing to the
//!   group.
//!
//! ## Implementation
//!
//! The Decaf suggestion is to use a quotient group, such as \\(\mathcal
//! E / \mathcal E\[4\]\\) or \\(2 \mathcal E / \mathcal E\[2\] \\), to
//! implement a prime-order group using a non-prime-order curve.
//!
//! This requires only changing
//!
//! 1. the function for equality checking (so that two representatives
//!    of the same coset are considered equal);
//! 2. the function for encoding (so that two representatives of the
//!    same coset are encoded as identical bitstrings);
//! 3. the function for decoding (so that only the canonical encoding of
//!    a coset is accepted).
//!
//! Internally, each coset is represented by a curve point; two points
//! \\( P, Q \\) may represent the same coset in the same way that two
//! points with different \\(X,Y,Z\\) coordinates may represent the
//! same point.  The group operations are carried out with no overhead
//! using Edwards formulas.
//!
//! Notes on the details of the encoding can be found in the
//! [Details][ristretto_notes] section of the Ristretto website.
//!
//! [cryptonote]:
//! https://moderncrypto.org/mail-archive/curves/2017/000898.html
//! [ed25519_hkd]:
//! https://moderncrypto.org/mail-archive/curves/2017/000858.html
//! [ristretto_coffee]:
//! https://en.wikipedia.org/wiki/Ristretto
//! [ristretto_notes]:
//! https://ristretto.group/details/index.html
//! [why_ristretto]:
//! https://ristretto.group/why_ristretto.html
//! [ristretto_main]:
//! https://ristretto.group/

mod elligator;

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use core::array::TryFromSliceError;
use core::borrow::Borrow;
use core::fmt::Debug;
use core::iter::Sum;
use core::ops::{Add, Neg, Sub};
use core::ops::{AddAssign, SubAssign};
use core::ops::{Mul, MulAssign};

#[cfg(feature = "digest")]
use digest::Digest;
#[cfg(feature = "digest")]
use digest::array::typenum::U64;

use crate::constants;
use crate::field::FieldElement;

#[cfg(feature = "group")]
use {
    group::{GroupEncoding, cofactor::CofactorGroup, prime::PrimeGroup},
    subtle::CtOption,
};

#[cfg(feature = "rand_core")]
use rand_core::CryptoRng;

use subtle::Choice;
use subtle::ConditionallyNegatable;
use subtle::ConditionallySelectable;
use subtle::ConstantTimeEq;

#[cfg(feature = "zeroize")]
use zeroize::Zeroize;

#[cfg(feature = "precomputed-tables")]
use crate::edwards::EdwardsBasepointTable;
use crate::edwards::EdwardsPoint;

use crate::scalar::Scalar;

#[cfg(feature = "precomputed-tables")]
use crate::traits::BasepointTable;
use crate::traits::Identity;
#[cfg(feature = "alloc")]
use crate::traits::{MultiscalarMul, VartimeMultiscalarMul, VartimePrecomputedMultiscalarMul};

// ------------------------------------------------------------------------
// Compressed points
// ------------------------------------------------------------------------

/// A Ristretto point, in compressed wire format.
///
/// The Ristretto encoding is canonical, so two points are equal if and
/// only if their encodings are equal.
#[allow(clippy::derived_hash_with_manual_eq)]
#[derive(Copy, Clone, Hash)]
pub struct CompressedRistretto(pub [u8; 32]);

impl Eq for CompressedRistretto {}
impl PartialEq for CompressedRistretto {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl ConstantTimeEq for CompressedRistretto {
    fn ct_eq(&self, other: &CompressedRistretto) -> Choice {
        self.as_bytes().ct_eq(other.as_bytes())
    }
}

impl CompressedRistretto {
    /// Copy the bytes of this `CompressedRistretto`.
    pub const fn to_bytes(&self) -> [u8; 32] {
        self.0
    }

    /// View this `CompressedRistretto` as an array of bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Construct a `CompressedRistretto` from a slice of bytes.
    ///
    /// # Errors
    ///
    /// Returns [`TryFromSliceError`] if the input `bytes` slice does not have
    /// a length of 32.
    pub fn from_slice(bytes: &[u8]) -> Result<CompressedRistretto, TryFromSliceError> {
        bytes.try_into().map(CompressedRistretto)
    }

    /// Attempt to decompress to an `RistrettoPoint`.
    ///
    /// # Return
    ///
    /// - `Some(RistrettoPoint)` if `self` was the canonical encoding of a point;
    ///
    /// - `None` if `self` was not the canonical encoding of a point.
    pub fn decompress(&self) -> Option<RistrettoPoint> {
        let (s_encoding_is_canonical, s_is_negative, s) = decompress::step_1(self);

        if (!s_encoding_is_canonical | s_is_negative).into() {
            return None;
        }

        let (ok, t_is_negative, y_is_zero, res) = decompress::step_2(s);

        if (!ok | t_is_negative | y_is_zero).into() {
            None
        } else {
            Some(res)
        }
    }

    /// Attempt to decompress two encodings at once.
    ///
    /// Returns `None` if either encoding is invalid, and otherwise exactly
    /// what `a.decompress()` and `b.decompress()` would return. The two
    /// inverse square roots are computed with their exponentiations
    /// interleaved; see `CompressedEdwardsY::decompress_pair`.
    pub fn decompress_pair(
        a: &CompressedRistretto,
        b: &CompressedRistretto,
    ) -> Option<(RistrettoPoint, RistrettoPoint)> {
        let (a, b) = decompress::pair(a, b)?;
        Some((a.point, b.point))
    }
}

mod decompress {
    use super::*;

    /// Decode and validate both inputs, retaining both curve representations.
    pub(super) fn pair(
        a: &CompressedRistretto,
        b: &CompressedRistretto,
    ) -> Option<(Decoded, Decoded)> {
        let (canonical_a, negative_a, sa) = step_1(a);
        let (canonical_b, negative_b, sb) = step_1(b);
        if (!canonical_a | negative_a | !canonical_b | negative_b).into() {
            return None;
        }

        let pa = prepare(sa);
        let pb = prepare(sb);
        let ((ok_a, Ia), (ok_b, Ib)) = FieldElement::invsqrt_pair(&pa.w, &pb.w);
        let da = finish(&pa, Ia);
        let db = finish(&pb, Ib);

        if (!ok_a | da.t_is_negative | da.y_is_zero | !ok_b | db.t_is_negative | db.y_is_zero)
            .into()
        {
            None
        } else {
            Some((da, db))
        }
    }

    pub(super) fn step_1(repr: &CompressedRistretto) -> (Choice, Choice, FieldElement) {
        // Step 1. Check s for validity:
        // 1.a) s must be 32 bytes (we get this from the type system)
        // 1.b) s < p
        // 1.c) s is nonnegative
        //
        // Our decoding routine ignores the high bit, so the only
        // possible failure for 1.b) is if someone encodes s in 0..18
        // as s+p in 2^255-19..2^255-1.  We can check this by
        // converting back to bytes, and checking that we get the
        // original input, since our encoding routine is canonical.

        let s = FieldElement::from_bytes(repr.as_bytes());
        let s_bytes_check = s.to_bytes();
        let s_encoding_is_canonical = s_bytes_check[..].ct_eq(repr.as_bytes());
        let s_is_negative = s.is_negative();

        (s_encoding_is_canonical, s_is_negative, s)
    }

    /// The quantities of step 2 that do not depend on the inverse square root.
    pub(super) struct Prepared {
        s: FieldElement,
        u1: FieldElement,
        u2: FieldElement,
        v: FieldElement,
        /// `v * u2²`, the element whose inverse square root is needed.
        pub(super) w: FieldElement,
    }

    pub(super) fn prepare(s: FieldElement) -> Prepared {
        // Step 2.  Compute (X:Y:Z:T).
        let one = FieldElement::ONE;
        let ss = s.square();
        let u1 = &one - &ss; //  1 + as²
        let u2 = &one + &ss; //  1 - as²    where a=-1
        let u2_sqr = u2.square(); // (1 - as²)²

        // v == ad(1+as²)² - (1-as²)²            where d=-121665/121666
        let v = &(&(-&constants::EDWARDS_D) * &u1.square()) - &u2_sqr;

        let w = &v * &u2_sqr;
        Prepared { s, u1, u2, v, w }
    }

    /// The outcome of step 2: the decoded point, the flags that may still
    /// reject it, and the same point on the Jacobi quartic.
    pub(super) struct Decoded {
        pub(super) t_is_negative: Choice,
        pub(super) y_is_zero: Choice,
        pub(super) point: RistrettoPoint,
        pub(super) quartic: JacobiQuartic,
    }

    /// Completes step 2 given `I = 1/sqrt(v * u2²)`.
    pub(super) fn finish(p: &Prepared, I: FieldElement) -> Decoded {
        let Dx = &I * &p.u2; // 1/sqrt(v)
        let sqrt_v = &Dx * &p.v; // sqrt(v), shared with the quartic coordinate
        let Dy = &I * &sqrt_v; // 1/u2

        // x == | 2s/sqrt(v) | == + sqrt(4s²/(ad(1+as²)² - (1-as²)²))
        let mut x = &(&p.s + &p.s) * &Dx;
        let x_neg = x.is_negative();
        x.conditional_negate(x_neg);

        // y == (1-as²)/(1+as²)
        let y = &p.u1 * &Dy;

        // t == ((1+as²) sqrt(4s²/(ad(1+as²)² - (1-as²)²)))/(1-as²)
        let t = &x * &y;

        // The decoded point is the image of (s, t_J) on the Jacobi quartic
        // under (s, t_J) -> (2 s / (t_J sqrt(a-d)), (1-s²)/(1+s²)), where
        // t_J = sqrt(v) / sqrt(a-d) with sqrt(v) = 1/Dx = v Dx, negated when
        // x was, so that the image has the non-negative x chosen above.
        let mut quartic_t = &constants::INVSQRT_A_MINUS_D * &sqrt_v;
        quartic_t.conditional_negate(x_neg);

        Decoded {
            t_is_negative: t.is_negative(),
            y_is_zero: y.is_zero(),
            point: RistrettoPoint(EdwardsPoint {
                X: x,
                Y: y,
                Z: FieldElement::ONE,
                T: t,
            }),
            quartic: JacobiQuartic {
                s: p.s,
                t: quartic_t,
            },
        }
    }

    pub(super) fn step_2(s: FieldElement) -> (Choice, Choice, Choice, RistrettoPoint) {
        let p = prepare(s);
        let (ok, I) = p.w.invsqrt(); // 1/sqrt(v*u_2²)
        let decoded = finish(&p, I);
        (ok, decoded.t_is_negative, decoded.y_is_zero, decoded.point)
    }
}

// ------------------------------------------------------------------------
// Group operations on the Jacobi quartic, for compressed inputs
// ------------------------------------------------------------------------

/// An affine point `(s, t)` on the Jacobi quartic
/// \( \mathcal J: t^2 = s^4 + 2A s^2 + 1 \), \( 2A = 486662 \), which is
/// 2-isogenous to the Edwards curve via
/// \( \varphi(s, t) = (2s / (t \sqrt{a-d}), (1-s^2)/(1+s^2)) \).
///
/// The Ristretto decoding of `s` is \( \varphi(s, t) \) for the `t` that
/// gives a non-negative `x`, so decoding produces a point of
/// \( \mathcal J \) at no extra cost, and the Ristretto encoding is the
/// `s`-coordinate of a chosen representative of the coset of
/// \( \varphi^{-1}(\mathcal E[4]) \). Adding on \( \mathcal J \)
/// instead of on the Edwards curve therefore lets `add_vartime` encode
/// its result with one field inversion instead of the square root that
/// `compress` needs to pull a point back through \( \varphi \).
#[derive(Copy, Clone)]
struct JacobiQuartic {
    s: FieldElement,
    t: FieldElement,
}

/// A point of the Jacobi quartic in weighted projective coordinates,
/// `s = X/Z`, `t = Y/Z²`; `Z = 0` is one of the two points at infinity,
/// which map to the order-2 Edwards point `(0, -1)`.
#[derive(Copy, Clone)]
struct JacobiQuarticProjective {
    X: FieldElement,
    Y: FieldElement,
    Z: FieldElement,
}

impl JacobiQuartic {
    /// The point mapping to `-φ(self)`.
    fn negate(&self) -> Self {
        JacobiQuartic {
            s: -&self.s,
            t: self.t,
        }
    }

    /// The sum of `self` and `other`, in variable time.
    ///
    /// Uses the unified addition law of Billet and Joye for
    /// \( t^2 = s^4 + 2A s^2 + 1 \):
    /// \( s_3 = (s_1 t_2 + t_1 s_2) / (1 - s_1^2 s_2^2) \) and
    /// \( t_3 = ((1 + s_1^2 s_2^2)(t_1 t_2 + 2A s_1 s_2) + 2 s_1 s_2 (s_1^2 + s_2^2)) / (1 - s_1^2 s_2^2)^2 \).
    ///
    /// The law is undefined only when \( s_1 s_2 = \pm 1 \), that is for
    /// \( (s_2, t_2) = (\pm 1/s_1, \pm t_1/s_1^2) \). With equal signs the
    /// sum is a point at infinity and comes out as `Z = 0` with `X ≠ 0`.
    /// With opposite signs
    /// \( \varphi(s_2, t_2) = \varphi(s_1, t_1) + (0, -1) \), so the sum
    /// is the finite point \( 2\varphi(s_1, t_1) + (0, -1) \), while the
    /// formulas give `(0:0:0)`. That case is detected and the sum computed
    /// by doubling `self` and applying \( (s, t) \mapsto (1/s, -t/s^2) \),
    /// the map on \( \mathcal J \) that adds \( (0, -1) \) downstairs.
    /// Doubling never produces `(0:0:0)`: \( s^4 = 1 \) forces
    /// \( t^2 = 2 \pm 2A \neq 0 \), so its `X = 2st` is nonzero.
    ///
    /// Decoded Ristretto encodings never reach the degenerate case, since
    /// there \( \varphi(s_2, t_2) \) would be \( (-x, -y) \), or
    /// \( (x, -y) \) before `negate`, for \( (x, y) = \varphi(s_1, t_1) \)
    /// with \( x > 0 \) and \( xy > 0 \), and neither is the
    /// representative decoding chooses. Handling it anyway keeps this
    /// function total on \( \mathcal J \).
    fn add_vartime(&self, other: &Self) -> JacobiQuarticProjective {
        let sum = self.add_unified(other);
        if bool::from(sum.Z.is_zero()) && bool::from(sum.X.is_zero()) {
            let doubled = self.add_unified(self);
            return JacobiQuarticProjective {
                X: doubled.Z,
                Y: -&doubled.Y,
                Z: doubled.X,
            };
        }
        sum
    }

    /// The Billet–Joye formulas as written; see `add_vartime` for the
    /// exceptional cases.
    fn add_unified(&self, other: &Self) -> JacobiQuarticProjective {
        let ss = &self.s * &other.s;
        let tt = &self.t * &other.t;
        let ss_sq = ss.square();
        let s1_sq = self.s.square();
        let s2_sq = other.s.square();

        let X = &(&self.s * &other.t) + &(&self.t * &other.s);
        let Z = &FieldElement::ONE - &ss_sq;
        let left =
            &(&FieldElement::ONE + &ss_sq) * &(&tt + &(&constants::JACOBI_QUARTIC_TWO_A * &ss));
        let right = &(&ss + &ss) * &(&s1_sq + &s2_sq);
        let Y = &left + &right;

        JacobiQuarticProjective { X, Y, Z }
    }
}

impl JacobiQuarticProjective {
    /// The Ristretto encoding of \( \varphi(\text{self}) \), in variable time.
    ///
    /// Follows the encoding specification: let \( (x, y) = \varphi(s, t) \);
    /// if `x·y` is negative or `y = 0`, replace the point by its torque
    /// `(i y, i x)`, which on \( \mathcal J \) is the sum with the
    /// 4-torsion preimage `(1, T)`; if `x` is then negative, replace
    /// `(x, y)` by `(-x, -y)`, which maps `s` to `1/s`; the encoding is
    /// `|s|`. All of these are rational in `(X, Y, Z)`, so one batched
    /// inversion suffices. Every exceptional case (`Z = 0`, `s = 0`,
    /// `s = ±1`) is the coset of the identity, whose encoding is zero.
    fn compress_vartime(&self) -> CompressedRistretto {
        let zz = self.Z.square();
        let xx = self.X.square();
        let one_plus_ss = &zz + &xx; // (1 + s²) Z²
        let one_minus_ss = &zz - &xx; // (1 - s²) Z²
        let xz = &self.X * &self.Z;
        // Numerator of the torqued s' = (T s + t) / (1 - s²), times Z².
        let torqued_num = &(&constants::JACOBI_QUARTIC_TORSION_T * &xz) + &self.Y;

        // Identity coset: a point at infinity (maps to (0,-1)), s = 0 (maps
        // to (0,1)), or s = ±1 (maps to (±i, 0)). `torqued_num = 0` means
        // the torqued point is the identity, which is the s = ±1 case again.
        let identity =
            self.Z.is_zero() | self.X.is_zero() | one_minus_ss.is_zero() | torqued_num.is_zero();
        if identity.into() {
            return CompressedRistretto([0u8; 32]);
        }

        // Valid points never have t = 0 or 1 + s² = 0, so everything below
        // is invertible. Batch the six inversions into one.
        let p1 = &self.Z * &self.Y;
        let p2 = &p1 * &one_plus_ss;
        let p3 = &p2 * &one_minus_ss;
        let p4 = &p3 * &self.X;
        let p5 = &p4 * &torqued_num;
        let mut inv = p5.invert_vartime();
        let inv_torqued_num = &inv * &p4;
        inv = &inv * &torqued_num;
        let inv_x = &inv * &p3;
        inv = &inv * &self.X;
        let inv_one_minus_ss = &inv * &p2;
        inv = &inv * &one_minus_ss;
        let inv_one_plus_ss = &inv * &p1;
        inv = &inv * &one_plus_ss;
        let inv_y = &inv * &self.Z;
        let inv_z = &inv * &self.Y;

        // The affine Edwards coordinates of φ(self).
        let y = &one_minus_ss * &inv_one_plus_ss;
        let two_magic = &constants::INVSQRT_A_MINUS_D + &constants::INVSQRT_A_MINUS_D;
        let x = &(&two_magic * &xz) * &inv_y;

        // The identity check excluded a zero numerator for y, and its denominator
        // is nonzero, so only the sign of x*y determines the torque here.
        let torque = (&x * &y).is_negative();
        let (x_final, mut s, mut s_inv) = if torque.into() {
            (
                &constants::SQRT_M1 * &y,
                &torqued_num * &inv_one_minus_ss,
                &one_minus_ss * &inv_torqued_num,
            )
        } else {
            (x, &self.X * &inv_z, &self.Z * &inv_x)
        };
        if x_final.is_negative().into() {
            core::mem::swap(&mut s, &mut s_inv);
        }
        let s_is_negative = s.is_negative();
        s.conditional_negate(s_is_negative);
        CompressedRistretto(s.to_bytes())
    }
}

impl CompressedRistretto {
    /// The encoding of the sum of the two encoded points, in variable time.
    ///
    /// Returns `None` if either encoding is invalid, and otherwise exactly
    /// `(a.decompress()? + b.decompress()?).compress()`. The two decodings
    /// share their exponentiations, the addition happens on the Jacobi
    /// quartic and the result is encoded with one inversion instead of a
    /// square root, so this costs two exponentiations rather than three.
    /// For public data only.
    pub fn add_vartime(&self, other: &CompressedRistretto) -> Option<CompressedRistretto> {
        Self::combine_vartime(self, other, false)
    }

    /// The encoding of the difference of the two encoded points, in
    /// variable time; see `add_vartime`.
    pub fn sub_vartime(&self, other: &CompressedRistretto) -> Option<CompressedRistretto> {
        Self::combine_vartime(self, other, true)
    }

    fn combine_vartime(
        a: &CompressedRistretto,
        b: &CompressedRistretto,
        subtract: bool,
    ) -> Option<CompressedRistretto> {
        let (da, db) = decompress::pair(a, b)?;

        let qb = if subtract {
            db.quartic.negate()
        } else {
            db.quartic
        };
        Some(da.quartic.add_vartime(&qb).compress_vartime())
    }
}

impl Identity for CompressedRistretto {
    fn identity() -> CompressedRistretto {
        CompressedRistretto([0u8; 32])
    }
}

impl Default for CompressedRistretto {
    fn default() -> CompressedRistretto {
        CompressedRistretto::identity()
    }
}

impl TryFrom<&[u8]> for CompressedRistretto {
    type Error = TryFromSliceError;

    fn try_from(slice: &[u8]) -> Result<CompressedRistretto, TryFromSliceError> {
        Self::from_slice(slice)
    }
}

// ------------------------------------------------------------------------
// Serde support
// ------------------------------------------------------------------------
// Serializes to and from `RistrettoPoint` directly, doing compression
// and decompression internally.  This means that users can create
// structs containing `RistrettoPoint`s and use Serde's derived
// serializers to serialize those structures.

#[cfg(feature = "serde")]
use serde::de::Visitor;
#[cfg(feature = "serde")]
use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[cfg(feature = "serde")]
impl Serialize for RistrettoPoint {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use serde::ser::SerializeTuple;
        let mut tup = serializer.serialize_tuple(32)?;
        for byte in self.compress().as_bytes().iter() {
            tup.serialize_element(byte)?;
        }
        tup.end()
    }
}

#[cfg(feature = "serde")]
impl Serialize for CompressedRistretto {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use serde::ser::SerializeTuple;
        let mut tup = serializer.serialize_tuple(32)?;
        for byte in self.as_bytes().iter() {
            tup.serialize_element(byte)?;
        }
        tup.end()
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for RistrettoPoint {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct RistrettoPointVisitor;

        impl<'de> Visitor<'de> for RistrettoPointVisitor {
            type Value = RistrettoPoint;

            fn expecting(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                formatter.write_str("a valid point in Ristretto format")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<RistrettoPoint, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let mut bytes = [0u8; 32];
                #[allow(clippy::needless_range_loop)]
                for i in 0..32 {
                    bytes[i] = seq
                        .next_element()?
                        .ok_or_else(|| serde::de::Error::invalid_length(i, &"expected 32 bytes"))?;
                }
                CompressedRistretto(bytes)
                    .decompress()
                    .ok_or_else(|| serde::de::Error::custom("decompression failed"))
            }
        }

        deserializer.deserialize_tuple(32, RistrettoPointVisitor)
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for CompressedRistretto {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct CompressedRistrettoVisitor;

        impl<'de> Visitor<'de> for CompressedRistrettoVisitor {
            type Value = CompressedRistretto;

            fn expecting(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                formatter.write_str("32 bytes of data")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<CompressedRistretto, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let mut bytes = [0u8; 32];
                #[allow(clippy::needless_range_loop)]
                for i in 0..32 {
                    bytes[i] = seq
                        .next_element()?
                        .ok_or_else(|| serde::de::Error::invalid_length(i, &"expected 32 bytes"))?;
                }
                Ok(CompressedRistretto(bytes))
            }
        }

        deserializer.deserialize_tuple(32, CompressedRistrettoVisitor)
    }
}

// ------------------------------------------------------------------------
// Internal point representations
// ------------------------------------------------------------------------

/// A `RistrettoPoint` represents a point in the Ristretto group for
/// Curve25519.  Ristretto, a variant of Decaf, constructs a
/// prime-order group as a quotient group of a subgroup of (the
/// Edwards form of) Curve25519.
///
/// Internally, a `RistrettoPoint` is implemented as a wrapper type
/// around `EdwardsPoint`, with custom equality, compression, and
/// decompression routines to account for the quotient.  This means that
/// operations on `RistrettoPoint`s are exactly as fast as operations on
/// `EdwardsPoint`s.
///
#[derive(Copy, Clone)]
pub struct RistrettoPoint(pub(crate) EdwardsPoint);

impl RistrettoPoint {
    /// Compress this point using the Ristretto encoding.
    pub fn compress(&self) -> CompressedRistretto {
        let mut X = self.0.X;
        let mut Y = self.0.Y;
        let Z = &self.0.Z;
        let T = &self.0.T;

        let u1 = &(Z + &Y) * &(Z - &Y);
        let u2 = &X * &Y;
        // Ignore return value since this is always square
        let (_, invsqrt) = (&u1 * &u2.square()).invsqrt();
        let i1 = &invsqrt * &u1;
        let i2 = &invsqrt * &u2;
        let z_inv = &i1 * &(&i2 * T);
        let mut den_inv = i2;

        let iX = &X * &constants::SQRT_M1;
        let iY = &Y * &constants::SQRT_M1;
        let ristretto_magic = &constants::INVSQRT_A_MINUS_D;
        let enchanted_denominator = &i1 * ristretto_magic;

        let rotate = (T * &z_inv).is_negative();

        X.conditional_assign(&iY, rotate);
        Y.conditional_assign(&iX, rotate);
        den_inv.conditional_assign(&enchanted_denominator, rotate);

        Y.conditional_negate((&X * &z_inv).is_negative());

        let mut s = &den_inv * &(Z - &Y);
        let s_is_negative = s.is_negative();
        s.conditional_negate(s_is_negative);

        CompressedRistretto(s.to_bytes())
    }

    /// Double-and-compress a batch of points.  The Ristretto encoding
    /// is not batchable, since it requires an inverse square root.
    ///
    /// However, given input points \\( P\_1, \ldots, P\_n, \\)
    /// it is possible to compute the encodings of their doubles \\(
    /// \mathrm{enc}( \[2\]P\_1), \ldots, \mathrm{enc}( \[2\]P\_n ) \\)
    /// in a batch.
    ///
    #[cfg_attr(feature = "rand_core", doc = "```")]
    #[cfg_attr(not(feature = "rand_core"), doc = "```ignore")]
    /// # use solana_ed25519::ristretto::RistrettoPoint;
    ///
    /// # // Need fn main() here in comment so the doctest compiles
    /// # // See https://doc.rust-lang.org/book/documentation.html#documentation-as-tests
    /// # fn main() {
    /// let mut rng = rand::rng();
    ///
    /// let points: Vec<RistrettoPoint> =
    ///     (0..32).map(|_| RistrettoPoint::random(&mut rng)).collect();
    ///
    /// let compressed = RistrettoPoint::double_and_compress_batch(&points);
    ///
    /// for (P, P2_compressed) in points.iter().zip(compressed.iter()) {
    ///     assert_eq!(*P2_compressed, (P + P).compress());
    /// }
    /// # }
    /// ```
    #[cfg(feature = "alloc")]
    pub fn double_and_compress_batch<'a, I>(points: I) -> Vec<CompressedRistretto>
    where
        I: IntoIterator<Item = &'a RistrettoPoint>,
    {
        #[derive(Copy, Clone, Debug)]
        struct BatchCompressState {
            e: FieldElement,
            f: FieldElement,
            g: FieldElement,
            h: FieldElement,
            eg: FieldElement,
            fh: FieldElement,
        }

        impl BatchCompressState {
            fn efgh(&self) -> FieldElement {
                &self.eg * &self.fh
            }
        }

        impl<'a> From<&'a RistrettoPoint> for BatchCompressState {
            #[rustfmt::skip] // keep alignment of explanatory comments
            fn from(P: &'a RistrettoPoint) -> BatchCompressState {
                let XX = P.0.X.square();
                let YY = P.0.Y.square();
                let ZZ = P.0.Z.square();
                let dTT = &P.0.T.square() * &constants::EDWARDS_D;

                let e = &P.0.X * &(&P.0.Y + &P.0.Y); // = 2*X*Y
                let f = &ZZ + &dTT;                  // = Z^2 + d*T^2
                let g = &YY + &XX;                   // = Y^2 - a*X^2
                let h = &ZZ - &dTT;                  // = Z^2 - d*T^2

                let eg = &e * &g;
                let fh = &f * &h;

                BatchCompressState{ e, f, g, h, eg, fh }
            }
        }

        let states: Vec<BatchCompressState> =
            points.into_iter().map(BatchCompressState::from).collect();

        let mut invs: Vec<FieldElement> = states.iter().map(|state| state.efgh()).collect();

        FieldElement::invert_batch_alloc(&mut invs[..]);

        states
            .iter()
            .zip(invs.iter())
            .map(|(state, inv): (&BatchCompressState, &FieldElement)| {
                let Zinv = &state.eg * inv;
                let Tinv = &state.fh * inv;

                let mut magic = constants::INVSQRT_A_MINUS_D;

                let negcheck1 = (&state.eg * &Zinv).is_negative();

                let mut e = state.e;
                let mut g = state.g;
                let mut h = state.h;

                let minus_e = -&e;
                let f_times_sqrta = &state.f * &constants::SQRT_M1;

                e.conditional_assign(&state.g, negcheck1);
                g.conditional_assign(&minus_e, negcheck1);
                h.conditional_assign(&f_times_sqrta, negcheck1);

                magic.conditional_assign(&constants::SQRT_M1, negcheck1);

                let negcheck2 = (&(&h * &e) * &Zinv).is_negative();

                g.conditional_negate(negcheck2);

                let mut s = &(&h - &g) * &(&magic * &(&g * &Tinv));

                let s_is_negative = s.is_negative();
                s.conditional_negate(s_is_negative);

                CompressedRistretto(s.to_bytes())
            })
            .collect()
    }

    /// Return the coset self + E\[4\], for debugging.
    fn coset4(&self) -> [EdwardsPoint; 4] {
        [
            self.0,
            self.0 + constants::EIGHT_TORSION[2],
            self.0 + constants::EIGHT_TORSION[4],
            self.0 + constants::EIGHT_TORSION[6],
        ]
    }

    /// Return a `RistrettoPoint` chosen uniformly at random using a user-provided RNG.
    ///
    /// # Inputs
    ///
    /// * `rng`: any RNG which implements `CryptoRng` interface.
    ///
    /// # Returns
    ///
    /// A random element of the Ristretto group.
    ///
    /// # Implementation
    ///
    /// Uses the Ristretto-flavoured Elligator 2 map, so that the
    /// discrete log of the output point with respect to any other
    /// point should be unknown.  The map is applied twice and the
    /// results are added, to ensure a uniform distribution.
    #[cfg(feature = "rand_core")]
    pub fn random<R: CryptoRng + ?Sized>(rng: &mut R) -> Self {
        let mut uniform_bytes = [0u8; 64];
        rng.fill_bytes(&mut uniform_bytes);

        RistrettoPoint::from_uniform_bytes(&uniform_bytes)
    }

    #[cfg(feature = "digest")]
    /// Hash a slice of bytes into a `RistrettoPoint`.
    ///
    /// Takes a type parameter `D`, which is any `Digest` producing 64
    /// bytes of output.
    ///
    /// Convenience wrapper around `from_hash`.
    ///
    /// # Implementation
    ///
    /// Uses the Ristretto-flavoured Elligator 2 map, so that the
    /// discrete log of the output point with respect to any other
    /// point should be unknown.  The map is applied twice and the
    /// results are added, to ensure a uniform distribution.
    ///
    /// # Example
    ///
    #[cfg_attr(feature = "digest", doc = "```")]
    #[cfg_attr(not(feature = "digest"), doc = "```ignore")]
    /// # use solana_ed25519::ristretto::RistrettoPoint;
    /// use sha2::Sha512;
    ///
    /// # // Need fn main() here in comment so the doctest compiles
    /// # // See https://doc.rust-lang.org/book/documentation.html#documentation-as-tests
    /// # fn main() {
    /// let msg = "To really appreciate architecture, you may even need to commit a murder";
    /// let P = RistrettoPoint::hash_from_bytes::<Sha512>(msg.as_bytes());
    /// # }
    /// ```
    ///
    pub fn hash_from_bytes<D>(input: &[u8]) -> RistrettoPoint
    where
        D: Digest<OutputSize = U64> + Default,
    {
        let mut hash = D::default();
        hash.update(input);
        RistrettoPoint::from_hash(hash)
    }

    #[cfg(feature = "digest")]
    /// Construct a `RistrettoPoint` from an existing `Digest` instance.
    ///
    /// Use this instead of `hash_from_bytes` if it is more convenient
    /// to stream data into the `Digest` than to pass a single byte
    /// slice.
    pub fn from_hash<D>(hash: D) -> RistrettoPoint
    where
        D: Digest<OutputSize = U64> + Default,
    {
        // dealing with generic arrays is clumsy, until const generics land
        let output = hash.finalize();
        let mut output_bytes = [0u8; 64];
        output_bytes.copy_from_slice(output.as_slice());

        RistrettoPoint::from_uniform_bytes(&output_bytes)
    }

    /// Construct a `RistrettoPoint` from 64 bytes of data.
    ///
    /// If the input bytes are uniformly distributed, the resulting
    /// point will be uniformly distributed over the group, and its
    /// discrete log with respect to other points should be unknown.
    ///
    /// # Implementation
    ///
    /// This function splits the input array into two 32-byte halves,
    /// takes the low 255 bits of each half mod p, applies the
    /// Ristretto-flavored Elligator map to each, and adds the results.
    pub fn from_uniform_bytes(bytes: &[u8; 64]) -> RistrettoPoint {
        // This follows the one-way map construction from the Ristretto RFC:
        // https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-ristretto255-decaf448-04#section-4.3.4
        let mut r_1_bytes = [0u8; 32];
        r_1_bytes.copy_from_slice(&bytes[0..32]);
        let r_1 = FieldElement::from_bytes(&r_1_bytes);
        let R_1 = RistrettoPoint::elligator_ristretto_flavor(&r_1);

        let mut r_2_bytes = [0u8; 32];
        r_2_bytes.copy_from_slice(&bytes[32..64]);
        let r_2 = FieldElement::from_bytes(&r_2_bytes);
        let R_2 = RistrettoPoint::elligator_ristretto_flavor(&r_2);

        // Applying Elligator twice and adding the results ensures a
        // uniform distribution.
        R_1 + R_2
    }
}

impl Identity for RistrettoPoint {
    fn identity() -> RistrettoPoint {
        RistrettoPoint(EdwardsPoint::identity())
    }
}

impl Default for RistrettoPoint {
    fn default() -> RistrettoPoint {
        RistrettoPoint::identity()
    }
}

// ------------------------------------------------------------------------
// Equality
// ------------------------------------------------------------------------

impl PartialEq for RistrettoPoint {
    fn eq(&self, other: &RistrettoPoint) -> bool {
        self.ct_eq(other).into()
    }
}

impl ConstantTimeEq for RistrettoPoint {
    /// Test equality between two `RistrettoPoint`s.
    ///
    /// # Returns
    ///
    /// * `Choice(1)` if the two `RistrettoPoint`s are equal;
    /// * `Choice(0)` otherwise.
    fn ct_eq(&self, other: &RistrettoPoint) -> Choice {
        let X1Y2 = &self.0.X * &other.0.Y;
        let Y1X2 = &self.0.Y * &other.0.X;
        let X1X2 = &self.0.X * &other.0.X;
        let Y1Y2 = &self.0.Y * &other.0.Y;

        X1Y2.ct_eq(&Y1X2) | X1X2.ct_eq(&Y1Y2)
    }
}

impl Eq for RistrettoPoint {}

// ------------------------------------------------------------------------
// Arithmetic
// ------------------------------------------------------------------------

impl<'a> Add<&'a RistrettoPoint> for &RistrettoPoint {
    type Output = RistrettoPoint;

    fn add(self, other: &'a RistrettoPoint) -> RistrettoPoint {
        RistrettoPoint(self.0 + other.0)
    }
}

define_add_variants!(
    LHS = RistrettoPoint,
    RHS = RistrettoPoint,
    Output = RistrettoPoint
);

impl AddAssign<&RistrettoPoint> for RistrettoPoint {
    fn add_assign(&mut self, _rhs: &RistrettoPoint) {
        *self = (self as &RistrettoPoint) + _rhs;
    }
}

define_add_assign_variants!(LHS = RistrettoPoint, RHS = RistrettoPoint);

impl<'a> Sub<&'a RistrettoPoint> for &RistrettoPoint {
    type Output = RistrettoPoint;

    fn sub(self, other: &'a RistrettoPoint) -> RistrettoPoint {
        RistrettoPoint(self.0 - other.0)
    }
}

define_sub_variants!(
    LHS = RistrettoPoint,
    RHS = RistrettoPoint,
    Output = RistrettoPoint
);

impl SubAssign<&RistrettoPoint> for RistrettoPoint {
    fn sub_assign(&mut self, _rhs: &RistrettoPoint) {
        *self = (self as &RistrettoPoint) - _rhs;
    }
}

define_sub_assign_variants!(LHS = RistrettoPoint, RHS = RistrettoPoint);

impl<T> Sum<T> for RistrettoPoint
where
    T: Borrow<RistrettoPoint>,
{
    fn sum<I>(iter: I) -> Self
    where
        I: Iterator<Item = T>,
    {
        iter.fold(RistrettoPoint::identity(), |acc, item| acc + item.borrow())
    }
}

impl Neg for &RistrettoPoint {
    type Output = RistrettoPoint;

    fn neg(self) -> RistrettoPoint {
        RistrettoPoint(-&self.0)
    }
}

impl Neg for RistrettoPoint {
    type Output = RistrettoPoint;

    fn neg(self) -> RistrettoPoint {
        -&self
    }
}

impl<'a> MulAssign<&'a Scalar> for RistrettoPoint {
    fn mul_assign(&mut self, scalar: &'a Scalar) {
        let result = (self as &RistrettoPoint) * scalar;
        *self = result;
    }
}

impl<'a> Mul<&'a Scalar> for &RistrettoPoint {
    type Output = RistrettoPoint;
    /// Scalar multiplication: compute `scalar * self`.
    fn mul(self, scalar: &'a Scalar) -> RistrettoPoint {
        RistrettoPoint(self.0 * scalar)
    }
}

impl<'a> Mul<&'a RistrettoPoint> for &Scalar {
    type Output = RistrettoPoint;

    /// Scalar multiplication: compute `self * scalar`.
    fn mul(self, point: &'a RistrettoPoint) -> RistrettoPoint {
        RistrettoPoint(self * point.0)
    }
}

impl RistrettoPoint {
    /// Fixed-base scalar multiplication by the Ristretto base point.
    ///
    /// Uses precomputed basepoint tables when the `precomputed-tables` feature
    /// is enabled, trading off increased code size for ~4x better performance.
    pub fn mul_base(scalar: &Scalar) -> Self {
        #[cfg(not(feature = "precomputed-tables"))]
        {
            scalar * constants::RISTRETTO_BASEPOINT_POINT
        }

        #[cfg(feature = "precomputed-tables")]
        {
            scalar * constants::RISTRETTO_BASEPOINT_TABLE
        }
    }
}

define_mul_assign_variants!(LHS = RistrettoPoint, RHS = Scalar);

define_mul_variants!(LHS = RistrettoPoint, RHS = Scalar, Output = RistrettoPoint);
define_mul_variants!(LHS = Scalar, RHS = RistrettoPoint, Output = RistrettoPoint);

// ------------------------------------------------------------------------
// Multiscalar Multiplication impls
// ------------------------------------------------------------------------

// These use iterator combinators to unwrap the underlying points and
// forward to the EdwardsPoint implementations.

#[cfg(feature = "alloc")]
impl MultiscalarMul for RistrettoPoint {
    type Point = RistrettoPoint;

    fn multiscalar_mul<I, J>(scalars: I, points: J) -> RistrettoPoint
    where
        I: IntoIterator,
        I::Item: Borrow<Scalar>,
        J: IntoIterator,
        J::Item: Borrow<RistrettoPoint>,
    {
        let extended_points = points.into_iter().map(|P| P.borrow().0);
        RistrettoPoint(EdwardsPoint::multiscalar_mul(scalars, extended_points))
    }
}

#[cfg(feature = "alloc")]
impl VartimeMultiscalarMul for RistrettoPoint {
    type Point = RistrettoPoint;

    fn optional_multiscalar_mul<I, J>(scalars: I, points: J) -> Option<RistrettoPoint>
    where
        I: IntoIterator,
        I::Item: Borrow<Scalar>,
        J: IntoIterator<Item = Option<RistrettoPoint>>,
    {
        let extended_points = points.into_iter().map(|opt_P| opt_P.map(|P| P.0));

        EdwardsPoint::optional_multiscalar_mul(scalars, extended_points).map(RistrettoPoint)
    }
}

/// Precomputation for variable-time multiscalar multiplication with `RistrettoPoint`s.
///
/// Note that for large numbers of `RistrettoPoint`s, this functionality may be less
/// efficient than the corresponding `VartimeMultiscalarMul` implementation.
// This wraps the inner implementation in a facade type so that we can
// decouple stability of the inner type from the stability of the
// outer type.
#[cfg(feature = "alloc")]
pub struct VartimeRistrettoPrecomputation(crate::backend::VartimePrecomputedStraus);

#[cfg(feature = "alloc")]
impl VartimePrecomputedMultiscalarMul for VartimeRistrettoPrecomputation {
    type Point = RistrettoPoint;

    fn new<I>(static_points: I) -> Self
    where
        I: IntoIterator,
        I::Item: Borrow<Self::Point>,
    {
        Self(crate::backend::VartimePrecomputedStraus::new(
            static_points.into_iter().map(|P| P.borrow().0),
        ))
    }

    fn len(&self) -> usize {
        self.0.len()
    }

    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    fn optional_mixed_multiscalar_mul<I, J, K>(
        &self,
        static_scalars: I,
        dynamic_scalars: J,
        dynamic_points: K,
    ) -> Option<Self::Point>
    where
        I: IntoIterator,
        I::Item: Borrow<Scalar>,
        J: IntoIterator,
        J::Item: Borrow<Scalar>,
        K: IntoIterator<Item = Option<Self::Point>>,
    {
        self.0
            .optional_mixed_multiscalar_mul(
                static_scalars,
                dynamic_scalars,
                dynamic_points.into_iter().map(|P_opt| P_opt.map(|P| P.0)),
            )
            .map(RistrettoPoint)
    }
}

impl RistrettoPoint {
    /// Compute \\(aA + bB\\) in variable time, where \\(B\\) is the
    /// Ristretto basepoint.
    pub fn vartime_double_scalar_mul_basepoint(
        a: &Scalar,
        A: &RistrettoPoint,
        b: &Scalar,
    ) -> RistrettoPoint {
        RistrettoPoint(EdwardsPoint::vartime_double_scalar_mul_basepoint(
            a, &A.0, b,
        ))
    }
}

/// A precomputed table of multiples of a basepoint, used to accelerate
/// scalar multiplication.
///
/// A precomputed table of multiples of the Ristretto basepoint is
/// available in the `constants` module:
/// ```
/// use solana_ed25519::constants::RISTRETTO_BASEPOINT_TABLE;
/// use solana_ed25519::scalar::Scalar;
///
/// let a = Scalar::from(87329482u64);
/// let P = &a * RISTRETTO_BASEPOINT_TABLE;
/// ```
#[cfg(feature = "precomputed-tables")]
#[derive(Clone)]
#[repr(transparent)]
pub struct RistrettoBasepointTable(pub(crate) EdwardsBasepointTable);

#[cfg(feature = "precomputed-tables")]
impl<'b> Mul<&'b Scalar> for &RistrettoBasepointTable {
    type Output = RistrettoPoint;

    fn mul(self, scalar: &'b Scalar) -> RistrettoPoint {
        RistrettoPoint(&self.0 * scalar)
    }
}

#[cfg(feature = "precomputed-tables")]
impl<'a> Mul<&'a RistrettoBasepointTable> for &Scalar {
    type Output = RistrettoPoint;

    fn mul(self, basepoint_table: &'a RistrettoBasepointTable) -> RistrettoPoint {
        RistrettoPoint(self * &basepoint_table.0)
    }
}

#[cfg(feature = "precomputed-tables")]
impl RistrettoBasepointTable {
    /// Create a precomputed table of multiples of the given `basepoint`.
    pub fn create(basepoint: &RistrettoPoint) -> RistrettoBasepointTable {
        RistrettoBasepointTable(EdwardsBasepointTable::create(&basepoint.0))
    }

    /// Get the basepoint for this table as a `RistrettoPoint`.
    pub fn basepoint(&self) -> RistrettoPoint {
        RistrettoPoint(self.0.basepoint())
    }
}

// ------------------------------------------------------------------------
// Constant-time conditional selection
// ------------------------------------------------------------------------

impl ConditionallySelectable for RistrettoPoint {
    /// Conditionally select between `self` and `other`.
    ///
    /// # Example
    ///
    /// ```
    /// use subtle::ConditionallySelectable;
    /// use subtle::Choice;
    /// #
    /// # use solana_ed25519::traits::Identity;
    /// # use solana_ed25519::ristretto::RistrettoPoint;
    /// # use solana_ed25519::constants;
    /// # fn main() {
    ///
    /// let A = RistrettoPoint::identity();
    /// let B = constants::RISTRETTO_BASEPOINT_POINT;
    ///
    /// let mut P = A;
    ///
    /// P = RistrettoPoint::conditional_select(&A, &B, Choice::from(0));
    /// assert_eq!(P, A);
    /// P = RistrettoPoint::conditional_select(&A, &B, Choice::from(1));
    /// assert_eq!(P, B);
    /// # }
    /// ```
    fn conditional_select(
        a: &RistrettoPoint,
        b: &RistrettoPoint,
        choice: Choice,
    ) -> RistrettoPoint {
        RistrettoPoint(EdwardsPoint::conditional_select(&a.0, &b.0, choice))
    }
}

// ------------------------------------------------------------------------
// Debug traits
// ------------------------------------------------------------------------

impl Debug for CompressedRistretto {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "CompressedRistretto: {:?}", self.as_bytes())
    }
}

impl Debug for RistrettoPoint {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let coset = self.coset4();
        write!(
            f,
            "RistrettoPoint: coset \n{:?}\n{:?}\n{:?}\n{:?}",
            coset[0], coset[1], coset[2], coset[3]
        )
    }
}

// ------------------------------------------------------------------------
// group traits
// ------------------------------------------------------------------------

// Use the full trait path to avoid Group::identity overlapping Identity::identity in the
// rest of the module (e.g. tests).
#[cfg(feature = "group")]
impl group::Group for RistrettoPoint {
    type Scalar = Scalar;

    fn try_random<R: rand_core::TryRng + ?Sized>(rng: &mut R) -> Result<Self, R::Error> {
        // NOTE: this is duplicated due to different `rng` bounds
        let mut uniform_bytes = [0u8; 64];
        rng.try_fill_bytes(&mut uniform_bytes)?;
        Ok(RistrettoPoint::from_uniform_bytes(&uniform_bytes))
    }

    fn identity() -> Self {
        Identity::identity()
    }

    fn generator() -> Self {
        constants::RISTRETTO_BASEPOINT_POINT
    }

    fn is_identity(&self) -> Choice {
        self.ct_eq(&Identity::identity())
    }

    fn double(&self) -> Self {
        self + self
    }
}

#[cfg(feature = "group")]
impl GroupEncoding for RistrettoPoint {
    type Repr = [u8; 32];

    fn from_bytes(bytes: &Self::Repr) -> CtOption<Self> {
        let (s_encoding_is_canonical, s_is_negative, s) =
            decompress::step_1(&CompressedRistretto(*bytes));

        let s_is_valid = s_encoding_is_canonical & !s_is_negative;

        let (ok, t_is_negative, y_is_zero, res) = decompress::step_2(s);

        CtOption::new(res, s_is_valid & ok & !t_is_negative & !y_is_zero)
    }

    fn from_bytes_unchecked(bytes: &Self::Repr) -> CtOption<Self> {
        // Just use the checked API; the checks we could skip aren't expensive.
        Self::from_bytes(bytes)
    }

    fn to_bytes(&self) -> Self::Repr {
        self.compress().to_bytes()
    }
}

#[cfg(feature = "group")]
impl PrimeGroup for RistrettoPoint {}

/// Ristretto has a cofactor of 1.
#[cfg(feature = "group")]
impl CofactorGroup for RistrettoPoint {
    type Subgroup = Self;

    fn clear_cofactor(&self) -> Self::Subgroup {
        *self
    }

    fn into_subgroup(self) -> CtOption<Self::Subgroup> {
        CtOption::new(self, Choice::from(1))
    }

    fn is_torsion_free(&self) -> Choice {
        Choice::from(1)
    }
}

// ------------------------------------------------------------------------
// Zeroize traits
// ------------------------------------------------------------------------

#[cfg(feature = "zeroize")]
impl Zeroize for CompressedRistretto {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

#[cfg(feature = "zeroize")]
impl Zeroize for RistrettoPoint {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

// ------------------------------------------------------------------------
// Tests
// ------------------------------------------------------------------------

#[cfg(test)]
mod test {
    use super::*;
    use crate::edwards::CompressedEdwardsY;
    #[cfg(all(feature = "alloc", feature = "group"))]
    use proptest::prelude::*;
    #[test]
    #[cfg(feature = "serde")]
    fn serde_bincode_basepoint_roundtrip() {
        use bincode;

        let encoded = bincode::serialize(&constants::RISTRETTO_BASEPOINT_POINT).unwrap();
        let enc_compressed =
            bincode::serialize(&constants::RISTRETTO_BASEPOINT_COMPRESSED).unwrap();
        assert_eq!(encoded, enc_compressed);

        // Check that the encoding is 32 bytes exactly
        assert_eq!(encoded.len(), 32);

        let dec_uncompressed: RistrettoPoint = bincode::deserialize(&encoded).unwrap();
        let dec_compressed: CompressedRistretto = bincode::deserialize(&encoded).unwrap();

        assert_eq!(dec_uncompressed, constants::RISTRETTO_BASEPOINT_POINT);
        assert_eq!(dec_compressed, constants::RISTRETTO_BASEPOINT_COMPRESSED);

        // Check that the encoding itself matches the usual one
        let raw_bytes = constants::RISTRETTO_BASEPOINT_COMPRESSED.as_bytes();
        let bp: RistrettoPoint = bincode::deserialize(raw_bytes).unwrap();
        assert_eq!(bp, constants::RISTRETTO_BASEPOINT_POINT);
    }

    #[test]
    fn scalarmult_ristrettopoint_works_both_ways() {
        let P = constants::RISTRETTO_BASEPOINT_POINT;
        let s = Scalar::from(999u64);

        let P1 = P * s;
        let P2 = s * P;

        assert!(P1.compress().as_bytes() == P2.compress().as_bytes());
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn impl_sum() {
        // Test that sum works for non-empty iterators
        let BASE = constants::RISTRETTO_BASEPOINT_POINT;

        let s1 = Scalar::from(999u64);
        let P1 = BASE * s1;

        let s2 = Scalar::from(333u64);
        let P2 = BASE * s2;

        let arr = [P1, P2];
        let sum: RistrettoPoint = arr.iter().sum();

        assert_eq!(sum, P1 + P2);

        // Test that sum works for the empty iterator
        let empty_array: [RistrettoPoint; 0] = [];
        let sum: RistrettoPoint = empty_array.iter().sum();

        assert_eq!(sum, RistrettoPoint::identity());

        // Test that sum works on owning iterators
        let s = Scalar::from(2u64);
        let mapped = arr.iter().map(|x| x * s);
        let sum: RistrettoPoint = mapped.sum();

        assert_eq!(sum, P1 * s + P2 * s);
    }

    /// `decompress_pair` must agree with `decompress` on valid encodings,
    /// encodings rejected at each step, and random bytes.
    #[test]
    fn pair_decompression_matches_single() {
        use rand::Rng;
        let mut rng = rand::rng();
        let mut encodings = std::vec![
            CompressedRistretto::identity(),
            constants::RISTRETTO_BASEPOINT_COMPRESSED,
        ];
        for _ in 0..64 {
            let mut wide = [0u8; 64];
            rng.fill_bytes(&mut wide);
            let p = RistrettoPoint::mul_base(&Scalar::from_bytes_mod_order_wide(&wide));
            let mut bytes = p.compress().to_bytes();
            encodings.push(CompressedRistretto(bytes));
            // Negative s: rejected in step 1.
            bytes[0] ^= 1;
            encodings.push(CompressedRistretto(bytes));
            // Random bytes: usually rejected in step 2, if not in step 1.
            rng.fill_bytes(&mut bytes);
            encodings.push(CompressedRistretto(bytes));
            bytes[0] &= 0xfe;
            bytes[31] &= 0x7f;
            encodings.push(CompressedRistretto(bytes));
        }
        // Non-canonical s.
        let mut non_canonical = [0xffu8; 32];
        non_canonical[0] = 0xee;
        non_canonical[31] = 0x7f;
        encodings.push(CompressedRistretto(non_canonical));

        for a in &encodings {
            for b in encodings.iter().step_by(5) {
                let expected = match (a.decompress(), b.decompress()) {
                    (Some(pa), Some(pb)) => Some((pa, pb)),
                    _ => None,
                };
                let actual = CompressedRistretto::decompress_pair(a, b);
                assert_eq!(actual.is_some(), expected.is_some());
                if let (Some((xa, xb)), Some((ea, eb))) = (actual, expected) {
                    assert_eq!(xa, ea);
                    assert_eq!(xb, eb);
                    assert_eq!(xa.0.X.to_bytes(), ea.0.X.to_bytes());
                    assert_eq!(xb.0.T.to_bytes(), eb.0.T.to_bytes());
                }
            }
        }
    }

    /// The Jacobi quartic constants and the isogeny agree with the Edwards
    /// curve constants.
    #[test]
    fn jacobi_quartic_constants() {
        let one = FieldElement::ONE;
        let d = constants::EDWARDS_D;
        let a = &(&one - &d) * &(&one + &d).invert();
        assert_eq!(&a + &a, constants::JACOBI_QUARTIC_TWO_A);
        let i = constants::SQRT_M1;
        let magic = constants::INVSQRT_A_MINUS_D;
        let expected_t = -&(&(&i + &i) * &magic);
        assert_eq!(expected_t, constants::JACOBI_QUARTIC_TORSION_T);
        // (1, T) lies on t² = s⁴ + 2A s² + 1 and maps to (i, 0).
        let t = constants::JACOBI_QUARTIC_TORSION_T;
        assert_eq!(
            t.square(),
            &(&one + &constants::JACOBI_QUARTIC_TWO_A) + &one
        );
        let x = &(&magic + &magic) * &t.invert();
        assert_eq!(x, i);
    }

    /// Adding on the Jacobi quartic and encoding with one inversion must
    /// give the same bytes as decoding, adding on the Edwards curve and
    /// compressing, for random, equal, opposite and identity inputs.
    #[test]
    fn compressed_add_sub_match_point_arithmetic() {
        use rand::Rng;
        let mut rng = rand::rng();
        let random_point = |rng: &mut rand::rngs::ThreadRng| {
            let mut wide = [0u8; 64];
            rng.fill_bytes(&mut wide);
            RistrettoPoint::mul_base(&Scalar::from_bytes_mod_order_wide(&wide))
        };
        let identity = RistrettoPoint::identity();
        for _ in 0..512 {
            let p = random_point(&mut rng);
            let q = random_point(&mut rng);
            let cases = [
                (p, q),
                (p, p),
                (p, -p),
                (p, identity),
                (identity, p),
                (identity, identity),
                (p, p + p),
            ];
            for (lhs, rhs) in cases {
                let (a, b) = (lhs.compress(), rhs.compress());
                assert_eq!(
                    a.add_vartime(&b),
                    Some((lhs + rhs).compress()),
                    "{a:?} + {b:?}"
                );
                assert_eq!(
                    a.sub_vartime(&b),
                    Some((lhs - rhs).compress()),
                    "{a:?} - {b:?}"
                );
                assert_eq!(
                    b.sub_vartime(&a),
                    Some((rhs - lhs).compress()),
                    "{b:?} - {a:?}"
                );
            }
        }
        // Invalid encodings are rejected exactly as by decompress.
        let valid = random_point(&mut rng).compress();
        let mut invalid = valid;
        invalid.0[0] ^= 1;
        assert!(invalid.decompress().is_none());
        assert_eq!(valid.add_vartime(&invalid), None);
        assert_eq!(invalid.add_vartime(&valid), None);
        assert_eq!(invalid.sub_vartime(&valid), None);
    }

    /// Every element of the identity coset must encode as zero, including
    /// the two points at infinity of the quartic, which the addition law
    /// produces as `Z = 0` when `s_1 s_2 = ±1`.
    #[test]
    fn identity_coset_encodes_as_zero() {
        use rand::Rng;
        let mut rng = rand::rng();
        for _ in 0..64 {
            let mut wide = [0u8; 64];
            rng.fill_bytes(&mut wide);
            let p = RistrettoPoint::mul_base(&Scalar::from_bytes_mod_order_wide(&wide));
            let compressed = p.compress();
            let (_, _, s) = decompress::step_1(&compressed);
            let prepared = decompress::prepare(s);
            let (ok, I) = prepared.w.invsqrt();
            assert!(bool::from(ok));
            let q = decompress::finish(&prepared, I).quartic;
            // (1/s, t/s²) is on the quartic and maps into -p's coset, so the
            // sum lands at infinity.
            let s_inv = q.s.invert();
            let shifted = JacobiQuartic {
                s: s_inv,
                t: &q.t * &s_inv.square(),
            };
            let sum = q.add_vartime(&shifted);
            assert!(bool::from(sum.Z.is_zero()));
            assert_eq!(sum.compress_vartime(), CompressedRistretto::identity());
            // The finite identity-coset points: s = 0 and s = ±1.
            for (s_val, t_val) in [
                (FieldElement::ZERO, FieldElement::ONE),
                (FieldElement::ZERO, FieldElement::MINUS_ONE),
                (FieldElement::ONE, constants::JACOBI_QUARTIC_TORSION_T),
                (FieldElement::MINUS_ONE, constants::JACOBI_QUARTIC_TORSION_T),
                (FieldElement::ONE, -&constants::JACOBI_QUARTIC_TORSION_T),
            ] {
                let point = JacobiQuarticProjective {
                    X: s_val,
                    Y: t_val,
                    Z: FieldElement::ONE,
                };
                assert_eq!(point.compress_vartime(), CompressedRistretto::identity());
            }
        }
    }

    /// For `other = (±1/s, ∓t/s²)` the Billet–Joye formulas vanish
    /// identically although the sum is finite; `add_vartime` must return
    /// the preimage of `2φ(self) + (0, -1)`, which encodes as `2P`.
    #[test]
    fn degenerate_quartic_sum_is_doubling() {
        use rand::Rng;
        let mut rng = rand::rng();
        let one = FieldElement::ONE;
        for _ in 0..64 {
            let mut wide = [0u8; 64];
            rng.fill_bytes(&mut wide);
            let p = RistrettoPoint::mul_base(&Scalar::from_bytes_mod_order_wide(&wide));
            let (_, _, s) = decompress::step_1(&p.compress());
            let prepared = decompress::prepare(s);
            let (ok, I) = prepared.w.invsqrt();
            assert!(bool::from(ok));
            let decoded = decompress::finish(&prepared, I);
            let q = decoded.quartic;
            // The two degenerate partners (1/s, -t/s²) and (-1/s, t/s²); the
            // other two sign choices are the sums at infinity.
            let s_inv = q.s.invert();
            let t_shift = &q.t * &s_inv.square();
            let degenerate = [
                JacobiQuartic {
                    s: s_inv,
                    t: -&t_shift,
                },
                JacobiQuartic {
                    s: -&s_inv,
                    t: t_shift,
                },
            ];
            // (x, y) = 2φ(q) on the Edwards curve.
            let doubled = decoded.point.0 + decoded.point.0;
            let z_inv = doubled.Z.invert();
            let (x, y) = (&doubled.X * &z_inv, &doubled.Y * &z_inv);
            for other in degenerate {
                let raw = q.add_unified(&other);
                assert!(bool::from(
                    raw.X.is_zero() & raw.Y.is_zero() & raw.Z.is_zero()
                ));
                let sum = q.add_vartime(&other);
                assert!(!bool::from(sum.Z.is_zero()));
                // φ(sum) must be 2φ(q) + (0, -1) = (-x, -y).
                let sum_z_inv = sum.Z.invert();
                let sum_s = &sum.X * &sum_z_inv;
                let sum_t = &sum.Y * &sum_z_inv.square();
                let phi_x = &(&(&sum_s + &sum_s) * &constants::INVSQRT_A_MINUS_D) * &sum_t.invert();
                let phi_y = &(&one - &sum_s.square()) * &(&one + &sum_s.square()).invert();
                assert_eq!(phi_x, -&x);
                assert_eq!(phi_y, -&y);
                assert_eq!(sum.compress_vartime(), (p + p).compress());
            }
        }
    }

    #[test]
    fn decompress_negative_s_fails() {
        // constants::d is neg, so decompression should fail as |d| != d.
        let bad_compressed = CompressedRistretto(constants::EDWARDS_D.to_bytes());
        assert!(bad_compressed.decompress().is_none());
    }

    #[test]
    fn decompress_id() {
        let compressed_id = CompressedRistretto::identity();
        let id = compressed_id
            .decompress()
            .expect("identity should decompress");
        let mut identity_in_coset = false;
        for P in &id.coset4() {
            if P.compress() == CompressedEdwardsY::identity() {
                identity_in_coset = true;
            }
        }
        assert!(identity_in_coset);
    }

    #[test]
    fn compress_id() {
        let id = RistrettoPoint::identity();
        assert_eq!(id.compress(), CompressedRistretto::identity());
    }

    #[test]
    fn basepoint_roundtrip() {
        let bp_compressed_ristretto = constants::RISTRETTO_BASEPOINT_POINT.compress();
        let bp_recaf = bp_compressed_ristretto
            .decompress()
            .expect("basepoint should decompress")
            .0;
        // Check that bp_recaf differs from bp by a point of order 4
        let diff = constants::RISTRETTO_BASEPOINT_POINT.0 - bp_recaf;
        let diff4 = diff.mul_by_pow_2(2);
        assert_eq!(diff4.compress(), CompressedEdwardsY::identity());
    }

    #[test]
    fn encodings_of_small_multiples_of_basepoint() {
        // Table of encodings of i*basepoint
        // Generated using ristretto.sage
        let compressed = [
            CompressedRistretto([
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0,
            ]),
            CompressedRistretto([
                226, 242, 174, 10, 106, 188, 78, 113, 168, 132, 169, 97, 197, 0, 81, 95, 88, 227,
                11, 106, 165, 130, 221, 141, 182, 166, 89, 69, 224, 141, 45, 118,
            ]),
            CompressedRistretto([
                106, 73, 50, 16, 247, 73, 156, 209, 127, 236, 181, 16, 174, 12, 234, 35, 161, 16,
                232, 213, 185, 1, 248, 172, 173, 211, 9, 92, 115, 163, 185, 25,
            ]),
            CompressedRistretto([
                148, 116, 31, 93, 93, 82, 117, 94, 206, 79, 35, 240, 68, 238, 39, 213, 209, 234,
                30, 43, 209, 150, 180, 98, 22, 107, 22, 21, 42, 157, 2, 89,
            ]),
            CompressedRistretto([
                218, 128, 134, 39, 115, 53, 139, 70, 111, 250, 223, 224, 179, 41, 58, 179, 217,
                253, 83, 197, 234, 108, 149, 83, 88, 245, 104, 50, 45, 175, 106, 87,
            ]),
            CompressedRistretto([
                232, 130, 177, 49, 1, 107, 82, 193, 211, 51, 112, 128, 24, 124, 247, 104, 66, 62,
                252, 203, 181, 23, 187, 73, 90, 184, 18, 196, 22, 15, 244, 78,
            ]),
            CompressedRistretto([
                246, 71, 70, 211, 201, 43, 19, 5, 14, 216, 216, 2, 54, 167, 240, 0, 124, 59, 63,
                150, 47, 91, 167, 147, 209, 154, 96, 30, 187, 29, 244, 3,
            ]),
            CompressedRistretto([
                68, 245, 53, 32, 146, 110, 200, 31, 189, 90, 56, 120, 69, 190, 183, 223, 133, 169,
                106, 36, 236, 225, 135, 56, 189, 207, 166, 167, 130, 42, 23, 109,
            ]),
            CompressedRistretto([
                144, 50, 147, 216, 242, 40, 126, 190, 16, 226, 55, 77, 193, 165, 62, 11, 200, 135,
                229, 146, 105, 159, 2, 208, 119, 213, 38, 60, 221, 85, 96, 28,
            ]),
            CompressedRistretto([
                2, 98, 42, 206, 143, 115, 3, 163, 28, 175, 198, 63, 143, 196, 143, 220, 22, 225,
                200, 200, 210, 52, 178, 240, 214, 104, 82, 130, 169, 7, 96, 49,
            ]),
            CompressedRistretto([
                32, 112, 111, 215, 136, 178, 114, 10, 30, 210, 165, 218, 212, 149, 43, 1, 244, 19,
                188, 240, 231, 86, 77, 232, 205, 200, 22, 104, 158, 45, 185, 95,
            ]),
            CompressedRistretto([
                188, 232, 63, 139, 165, 221, 47, 165, 114, 134, 76, 36, 186, 24, 16, 249, 82, 43,
                198, 0, 74, 254, 149, 135, 122, 199, 50, 65, 202, 253, 171, 66,
            ]),
            CompressedRistretto([
                228, 84, 158, 225, 107, 154, 160, 48, 153, 202, 32, 140, 103, 173, 175, 202, 250,
                76, 63, 62, 78, 83, 3, 222, 96, 38, 227, 202, 143, 248, 68, 96,
            ]),
            CompressedRistretto([
                170, 82, 224, 0, 223, 46, 22, 245, 95, 177, 3, 47, 195, 59, 196, 39, 66, 218, 214,
                189, 90, 143, 192, 190, 1, 103, 67, 108, 89, 72, 80, 31,
            ]),
            CompressedRistretto([
                70, 55, 107, 128, 244, 9, 178, 157, 194, 181, 246, 240, 197, 37, 145, 153, 8, 150,
                229, 113, 111, 65, 71, 124, 211, 0, 133, 171, 127, 16, 48, 30,
            ]),
            CompressedRistretto([
                224, 196, 24, 247, 200, 217, 196, 205, 215, 57, 91, 147, 234, 18, 79, 58, 217, 144,
                33, 187, 104, 29, 252, 51, 2, 169, 217, 154, 46, 83, 230, 78,
            ]),
        ];
        let mut bp = RistrettoPoint::identity();
        for point in compressed {
            assert_eq!(bp.compress(), point);
            bp += constants::RISTRETTO_BASEPOINT_POINT;
        }
    }

    #[test]
    fn four_torsion_basepoint() {
        let bp = constants::RISTRETTO_BASEPOINT_POINT;
        let bp_coset = bp.coset4();
        for point in bp_coset {
            assert_eq!(bp, RistrettoPoint(point));
        }
    }

    #[cfg(feature = "rand_core")]
    #[test]
    fn four_torsion_random() {
        let mut rng = rand::rng();
        let P = RistrettoPoint::mul_base(&Scalar::random(&mut rng));
        let P_coset = P.coset4();
        for point in P_coset {
            assert_eq!(P, RistrettoPoint(point));
        }
    }

    #[cfg(feature = "rand_core")]
    #[test]
    fn random_roundtrip() {
        let mut rng = rand::rng();
        for _ in 0..100 {
            let P = RistrettoPoint::mul_base(&Scalar::random(&mut rng));
            let compressed_P = P.compress();
            let Q = compressed_P
                .decompress()
                .expect("compression round-trip should decompress");
            assert_eq!(P, Q);
        }
    }

    #[test]
    #[cfg(all(feature = "alloc", feature = "rand_core", feature = "group"))]
    fn double_and_compress_1024_random_points() {
        use group::Group;
        let mut rng = rand::rng();

        let mut points: Vec<RistrettoPoint> = (0..1024)
            .map(|_| RistrettoPoint::random(&mut rng))
            .collect();
        points[500] = <RistrettoPoint as Group>::identity();

        let compressed = RistrettoPoint::double_and_compress_batch(&points);

        for (P, P2_compressed) in points.iter().zip(compressed.iter()) {
            assert_eq!(*P2_compressed, (P + P).compress());
        }
    }

    #[cfg(all(feature = "alloc", feature = "group"))]
    proptest! {
        #[test]
        fn multiply_double_and_compress_random_points(
            p1 in any::<[u8; 64]>(),
            p2 in any::<[u8; 64]>(),
            s1 in any::<[u8; 32]>(),
            s2 in any::<[u8; 32]>(),
        ) {
            use group::Group;

            let scalars = [
                Scalar::from_bytes_mod_order(s1),
                Scalar::ZERO,
                Scalar::from_bytes_mod_order(s2),
            ];

            let points = [
                RistrettoPoint::from_uniform_bytes(&p1),
                <RistrettoPoint as Group>::identity(),
                RistrettoPoint::from_uniform_bytes(&p2),
            ];

            let multiplied_points: [_; 3] =
                core::array::from_fn(|i| scalars[i].div_by_2() * points[i]);
            let compressed = RistrettoPoint::double_and_compress_batch(&multiplied_points);

            for ((s, P), P2_compressed) in scalars.iter().zip(points).zip(compressed) {
                prop_assert_eq!(P2_compressed, (s * P).compress());
            }
        }
    }

    #[test]
    #[cfg(all(feature = "alloc", feature = "rand_core"))]
    fn vartime_precomputed_vs_nonprecomputed_multiscalar() {
        let mut rng = rand::rng();

        let static_scalars = (0..128)
            .map(|_| Scalar::random(&mut rng))
            .collect::<Vec<_>>();

        let dynamic_scalars = (0..128)
            .map(|_| Scalar::random(&mut rng))
            .collect::<Vec<_>>();

        let check_scalar: Scalar = static_scalars
            .iter()
            .chain(dynamic_scalars.iter())
            .map(|s| s * s)
            .sum();

        let static_points = static_scalars
            .iter()
            .map(RistrettoPoint::mul_base)
            .collect::<Vec<_>>();
        let dynamic_points = dynamic_scalars
            .iter()
            .map(RistrettoPoint::mul_base)
            .collect::<Vec<_>>();

        let precomputation = VartimeRistrettoPrecomputation::new(static_points.iter());

        assert_eq!(precomputation.len(), 128);
        assert!(!precomputation.is_empty());

        let P = precomputation.vartime_mixed_multiscalar_mul(
            &static_scalars,
            &dynamic_scalars,
            &dynamic_points,
        );

        use crate::traits::VartimeMultiscalarMul;
        let Q = RistrettoPoint::vartime_multiscalar_mul(
            static_scalars.iter().chain(dynamic_scalars.iter()),
            static_points.iter().chain(dynamic_points.iter()),
        );

        let R = RistrettoPoint::mul_base(&check_scalar);

        assert_eq!(P.compress(), R.compress());
        assert_eq!(Q.compress(), R.compress());
    }

    #[test]
    #[cfg(all(feature = "alloc", feature = "rand_core"))]
    fn partial_precomputed_mixed_multiscalar_empty() {
        let mut rng = rand::rng();

        let n_static = 16;
        let n_dynamic = 8;

        let static_points = (0..n_static)
            .map(|_| RistrettoPoint::random(&mut rng))
            .collect::<Vec<_>>();

        // Use zero scalars
        let static_scalars = Vec::new();

        let dynamic_points = (0..n_dynamic)
            .map(|_| RistrettoPoint::random(&mut rng))
            .collect::<Vec<_>>();

        let dynamic_scalars = (0..n_dynamic)
            .map(|_| Scalar::random(&mut rng))
            .collect::<Vec<_>>();

        // Compute the linear combination using precomputed multiscalar multiplication
        let precomputation = VartimeRistrettoPrecomputation::new(static_points.iter());
        let result_multiscalar = precomputation.vartime_mixed_multiscalar_mul(
            &static_scalars,
            &dynamic_scalars,
            &dynamic_points,
        );

        // Compute the linear combination manually
        let mut result_manual = RistrettoPoint::identity();
        for i in 0..static_scalars.len() {
            result_manual += static_points[i] * static_scalars[i];
        }
        for i in 0..n_dynamic {
            result_manual += dynamic_points[i] * dynamic_scalars[i];
        }

        assert_eq!(result_multiscalar, result_manual);
    }

    #[test]
    #[cfg(all(feature = "alloc", feature = "rand_core"))]
    fn partial_precomputed_mixed_multiscalar() {
        let mut rng = rand::rng();

        let n_static = 16;
        let n_dynamic = 8;

        let static_points = (0..n_static)
            .map(|_| RistrettoPoint::random(&mut rng))
            .collect::<Vec<_>>();

        // Use one fewer scalars
        let static_scalars = (0..n_static - 1)
            .map(|_| Scalar::random(&mut rng))
            .collect::<Vec<_>>();

        let dynamic_points = (0..n_dynamic)
            .map(|_| RistrettoPoint::random(&mut rng))
            .collect::<Vec<_>>();

        let dynamic_scalars = (0..n_dynamic)
            .map(|_| Scalar::random(&mut rng))
            .collect::<Vec<_>>();

        // Compute the linear combination using precomputed multiscalar multiplication
        let precomputation = VartimeRistrettoPrecomputation::new(static_points.iter());
        let result_multiscalar = precomputation.vartime_mixed_multiscalar_mul(
            &static_scalars,
            &dynamic_scalars,
            &dynamic_points,
        );

        // Compute the linear combination manually
        let mut result_manual = RistrettoPoint::identity();
        for i in 0..static_scalars.len() {
            result_manual += static_points[i] * static_scalars[i];
        }
        for i in 0..n_dynamic {
            result_manual += dynamic_points[i] * dynamic_scalars[i];
        }

        assert_eq!(result_multiscalar, result_manual);
    }

    #[test]
    #[cfg(all(feature = "alloc", feature = "rand_core"))]
    fn partial_precomputed_multiscalar() {
        let mut rng = rand::rng();

        let n_static = 16;

        let static_points = (0..n_static)
            .map(|_| RistrettoPoint::random(&mut rng))
            .collect::<Vec<_>>();

        // Use one fewer scalars
        let static_scalars = (0..n_static - 1)
            .map(|_| Scalar::random(&mut rng))
            .collect::<Vec<_>>();

        // Compute the linear combination using precomputed multiscalar multiplication
        let precomputation = VartimeRistrettoPrecomputation::new(static_points.iter());
        let result_multiscalar = precomputation.vartime_multiscalar_mul(&static_scalars);

        // Compute the linear combination manually
        let mut result_manual = RistrettoPoint::identity();
        for i in 0..static_scalars.len() {
            result_manual += static_points[i] * static_scalars[i];
        }

        assert_eq!(result_multiscalar, result_manual);
    }

    #[test]
    #[cfg(all(feature = "alloc", feature = "rand_core"))]
    fn partial_precomputed_multiscalar_empty() {
        let mut rng = rand::rng();

        let n_static = 16;

        let static_points = (0..n_static)
            .map(|_| RistrettoPoint::random(&mut rng))
            .collect::<Vec<_>>();

        // Use zero scalars
        let static_scalars = Vec::new();

        // Compute the linear combination using precomputed multiscalar multiplication
        let precomputation = VartimeRistrettoPrecomputation::new(static_points.iter());
        let result_multiscalar = precomputation.vartime_multiscalar_mul(&static_scalars);

        // Compute the linear combination manually
        let mut result_manual = RistrettoPoint::identity();
        for i in 0..static_scalars.len() {
            result_manual += static_points[i] * static_scalars[i];
        }

        assert_eq!(result_multiscalar, result_manual);
    }
}
