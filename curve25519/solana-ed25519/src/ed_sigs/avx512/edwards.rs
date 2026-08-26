//! Point tables for the AVX-512 verifier.
//!
//! Points themselves are the crate's [`EdwardsPoint`]. `CachedPoint` stays
//! local because it is the type the IFMA lanes read: the crate's
//! `ProjectiveNielsPoint` computes `Y+X` with the lazy `Add`, which can leave a
//! limb above the `< 2^52` bound those lanes require, so the coordinates here
//! are built with [`Fe51`]'s eagerly reducing operations instead.

use super::field::Fe51;
use crate::edwards::EdwardsPoint;
use crate::traits::Identity;

// Signed-indexed layout: digit `d` maps to `entries[d + N]`, avoiding a hot
// unpredictable branch on the digit sign.
#[derive(Clone, Debug)]
pub(crate) struct PointTable {
    entries: [CachedPoint; SIGNED_POINT_TABLE_SIZE],
}

#[derive(Clone, Debug)]
pub(crate) struct BasepointTable {
    entries: [CachedPoint; SIGNED_BASEPOINT_TABLE_SIZE],
}

// `base_pair_digit` folds two radix-16 digits into a radix-256 digit with
// maximum magnitude `8 + 8*16 = 136`.
const POINT_TABLE_SIZE: usize = 8;
const SIGNED_POINT_TABLE_SIZE: usize = 2 * POINT_TABLE_SIZE + 1;
const BASEPOINT_TABLE_SIZE: usize = 136;
const SIGNED_BASEPOINT_TABLE_SIZE: usize = 2 * BASEPOINT_TABLE_SIZE + 1;

#[derive(Clone, Debug)]
pub(crate) struct CachedPoint {
    y_plus_x: Fe51,
    y_minus_x: Fe51,
    z2: Fe51,
    t2d: Fe51,
}

impl CachedPoint {
    fn new(point: &EdwardsPoint) -> Self {
        let x = Fe51::from_field(point.X);
        let y = Fe51::from_field(point.Y);
        let z = Fe51::from_field(point.Z);
        let t = Fe51::from_field(point.T);
        Self {
            y_plus_x: y.add(&x),
            y_minus_x: y.subtract(&x),
            z2: z.double(),
            t2d: t.multiply(&Fe51::two_d()),
        }
    }

    pub(crate) fn coords(&self) -> (&Fe51, &Fe51, &Fe51, &Fe51) {
        (&self.y_plus_x, &self.y_minus_x, &self.z2, &self.t2d)
    }

    /// Accept loosely-reduced fields (`< 2^52` per limb) from SIMD table
    /// construction; all consumers tolerate that bound.
    pub(crate) fn from_fields(y_plus_x: Fe51, y_minus_x: Fe51, z2: Fe51, t2d: Fe51) -> Self {
        Self {
            y_plus_x,
            y_minus_x,
            z2,
            t2d,
        }
    }

    pub(crate) fn identity() -> Self {
        Self::new(&EdwardsPoint::identity())
    }

    /// Cached form of `-P`: swap `y+x`/`y-x` and negate `t*2d`; `z2` is unchanged.
    fn negate(&self) -> Self {
        Self {
            y_plus_x: self.y_minus_x,
            y_minus_x: self.y_plus_x,
            z2: self.z2,
            t2d: self.t2d.negate(),
        }
    }
}

impl PointTable {
    pub(crate) fn from_cached(
        cached_points: [CachedPoint; POINT_TABLE_SIZE],
        negative_cached_points: [CachedPoint; POINT_TABLE_SIZE],
        identity_cached: CachedPoint,
    ) -> Self {
        let entries = signed_cached_entries(cached_points, negative_cached_points, identity_cached);
        Self { entries }
    }

    pub(crate) fn new(point: &EdwardsPoint) -> Self {
        let points = multiples_of(point);
        let cached_points: [CachedPoint; POINT_TABLE_SIZE] =
            core::array::from_fn(|i| CachedPoint::new(&points[i]));
        let negative_cached_points = core::array::from_fn(|i| cached_points[i].negate());
        let identity_cached = CachedPoint::new(&EdwardsPoint::identity());
        Self::from_cached(cached_points, negative_cached_points, identity_cached)
    }

    /// Select the cached point for a signed digit in `-8..=8`.
    pub(crate) fn select_signed_cached_ref(&self, digit: i8) -> &CachedPoint {
        debug_assert!((-8..=8).contains(&digit));
        // SAFETY: `digit` is a radix-16 digit in `-8..=8`, so `digit + 8` is
        // in bounds for this 17-entry table.
        unsafe { self.entries.get_unchecked((digit + 8) as usize) }
    }
}

impl BasepointTable {
    pub(crate) fn new() -> Self {
        // Built once per process (see BASE_TABLE in verifier.rs), so there's
        // no reason to special-case even m via double() to save a handful of
        // multiplies: this whole computation runs once ever.
        let basepoint = crate::constants::ED25519_BASEPOINT_POINT;
        let mut points = [basepoint; BASEPOINT_TABLE_SIZE];
        for i in 1..BASEPOINT_TABLE_SIZE {
            points[i] = points[i - 1] + basepoint;
        }
        let cached_points: [CachedPoint; BASEPOINT_TABLE_SIZE] =
            core::array::from_fn(|i| CachedPoint::new(&points[i]));
        let negative_cached_points: [CachedPoint; BASEPOINT_TABLE_SIZE] =
            core::array::from_fn(|i| cached_points[i].negate());
        let identity_cached = CachedPoint::new(&EdwardsPoint::identity());
        let entries = signed_cached_entries(cached_points, negative_cached_points, identity_cached);
        Self { entries }
    }

    /// Select the cached point for a signed digit in
    /// `-BASEPOINT_TABLE_SIZE..=BASEPOINT_TABLE_SIZE`.
    pub(crate) fn select_signed_cached_ref(&self, digit: i16) -> &CachedPoint {
        debug_assert!(
            (-(BASEPOINT_TABLE_SIZE as i16)..=(BASEPOINT_TABLE_SIZE as i16)).contains(&digit)
        );
        // SAFETY: `base_pair_digit` bounds `digit` to
        // `-BASEPOINT_TABLE_SIZE..=BASEPOINT_TABLE_SIZE`.
        unsafe {
            self.entries
                .get_unchecked((digit + BASEPOINT_TABLE_SIZE as i16) as usize)
        }
    }
}

fn signed_cached_entries<const N: usize, const OUT: usize>(
    cached_points: [CachedPoint; N],
    negative_cached_points: [CachedPoint; N],
    identity_cached: CachedPoint,
) -> [CachedPoint; OUT] {
    debug_assert_eq!(OUT, 2 * N + 1);
    core::array::from_fn(|i| {
        if i < N {
            negative_cached_points[N - 1 - i].clone()
        } else if i == N {
            identity_cached.clone()
        } else {
            cached_points[i - N - 1].clone()
        }
    })
}

fn multiples_of(point: &EdwardsPoint) -> [EdwardsPoint; POINT_TABLE_SIZE] {
    let p = *point;
    let p2 = p.double();
    let p3 = p2 + p;
    let p4 = p2.double();
    let p5 = p4 + p;
    let p6 = p3.double();
    let p7 = p6 + p;
    let p8 = p4.double();
    [p, p2, p3, p4, p5, p6, p7, p8]
}
