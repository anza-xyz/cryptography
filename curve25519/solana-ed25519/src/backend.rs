// -*- mode: rust; -*-
//
// This file is part of curve25519-dalek.
// Copyright (c) 2016-2021 isis lovecruft
// Copyright (c) 2016-2019 Henry de Valence
// See LICENSE for licensing information.
//
// Authors:
// - isis agora lovecruft <isis@patternsinthevoid.net>
// - Henry de Valence <hdevalence@hdevalence.ca>

//! **INTERNALS:** Pluggable implementations for different architectures.
//!
//! The backend code is split into two parts: a serial backend,
//! and a vector backend.
//!
//! The [`serial`] backend contains 32- and 64-bit implementations of
//! field arithmetic and scalar arithmetic, as well as implementations
//! of point operations using the mixed-model strategy (passing
//! between different curve models depending on the operation).
//!
//! The [`vector`] backend contains implementations of vectorized
//! field arithmetic, used to implement point operations using a novel
//! implementation strategy derived from parallel formulas of Hisil,
//! Wong, Carter, and Dawson.
//!
//! Because the two strategies give rise to different curve models,
//! it's not possible to reuse exactly the same scalar multiplication
//! code (or to write it generically), so both serial and vector
//! backends contain matching implementations of scalar multiplication
//! algorithms.  These are intended to be selected by a `#[cfg]`-based
//! type alias.
//!
//! The [`vector`] backend is compiled in on x86_64 unless the build is
//! overridden with `RUSTFLAGS='--cfg curve25519_backend="serial"'`; it uses the
//! [`serial`] backend for non-vectorized operations. When it is compiled in,
//! the choice between it and the [`serial`] backend is made per-host at runtime
//! by [`get_selected_backend`], based on AVX2 availability.

use crate::EdwardsPoint;
use crate::Scalar;

pub mod serial;

pub(crate) mod lanes;

#[cfg(curve25519_backend = "simd")]
pub mod vector;

#[derive(Copy, Clone)]
enum BackendKind {
    #[cfg(curve25519_backend = "simd")]
    Avx2,
    #[cfg(curve25519_backend = "simd")]
    Avx512,
    Serial,
}

#[inline]
fn get_selected_backend() -> BackendKind {
    #[cfg(curve25519_backend = "simd")]
    {
        cpufeatures::new!(cpuid_avx512, "avx512ifma", "avx512vl");
        let token_avx512: cpuid_avx512::InitToken = cpuid_avx512::init();
        if token_avx512.get() {
            return BackendKind::Avx512;
        }
    }

    #[cfg(curve25519_backend = "simd")]
    {
        cpufeatures::new!(cpuid_avx2, "avx2");
        let token_avx2: cpuid_avx2::InitToken = cpuid_avx2::init();
        if token_avx2.get() {
            return BackendKind::Avx2;
        }
    }

    BackendKind::Serial
}

#[allow(missing_docs)]
#[cfg(feature = "alloc")]
pub fn pippenger_optional_multiscalar_mul<I, J>(scalars: I, points: J) -> Option<EdwardsPoint>
where
    I: IntoIterator,
    I::Item: core::borrow::Borrow<Scalar>,
    J: IntoIterator<Item = Option<EdwardsPoint>>,
{
    use crate::traits::VartimeMultiscalarMul;

    match get_selected_backend() {
        #[cfg(curve25519_backend = "simd")]
        BackendKind::Avx2 => {
            vector::scalar_mul::pippenger::spec_avx2::Pippenger::optional_multiscalar_mul::<I, J>(
                scalars, points,
            )
        }
        #[cfg(curve25519_backend = "simd")]
        BackendKind::Avx512 => {
            vector::scalar_mul::pippenger::spec_avx512ifma_avx512vl::Pippenger::optional_multiscalar_mul::<I, J>(
                scalars, points,
            )
        }
        BackendKind::Serial => {
            serial::scalar_mul::pippenger::Pippenger::optional_multiscalar_mul::<I, J>(
                scalars, points,
            )
        }
    }
}

#[cfg(feature = "alloc")]
pub(crate) enum VartimePrecomputedStraus {
    #[cfg(curve25519_backend = "simd")]
    Avx2(vector::scalar_mul::precomputed_straus::spec_avx2::VartimePrecomputedStraus),
    #[cfg(curve25519_backend = "simd")]
    Avx512ifma(
        vector::scalar_mul::precomputed_straus::spec_avx512ifma_avx512vl::VartimePrecomputedStraus,
    ),
    Scalar(serial::scalar_mul::precomputed_straus::VartimePrecomputedStraus),
}

#[cfg(feature = "alloc")]
impl VartimePrecomputedStraus {
    pub fn new<I>(static_points: I) -> Self
    where
        I: IntoIterator,
        I::Item: core::borrow::Borrow<EdwardsPoint>,
    {
        use crate::traits::VartimePrecomputedMultiscalarMul;

        match get_selected_backend() {
            #[cfg(curve25519_backend = "simd")]
            BackendKind::Avx2 => VartimePrecomputedStraus::Avx2(
                vector::scalar_mul::precomputed_straus::spec_avx2::VartimePrecomputedStraus::new(
                    static_points,
                ),
            ),
            #[cfg(curve25519_backend = "simd")]
            BackendKind::Avx512 => VartimePrecomputedStraus::Avx512ifma(
                vector::scalar_mul::precomputed_straus::spec_avx512ifma_avx512vl::VartimePrecomputedStraus::new(
                    static_points,
                ),
            ),
            BackendKind::Serial => VartimePrecomputedStraus::Scalar(
                serial::scalar_mul::precomputed_straus::VartimePrecomputedStraus::new(
                    static_points,
                ),
            ),
        }
    }

    /// Return the number of static points in the precomputation.
    pub fn len(&self) -> usize {
        use crate::traits::VartimePrecomputedMultiscalarMul;

        match self {
            #[cfg(curve25519_backend = "simd")]
            VartimePrecomputedStraus::Avx2(inner) => inner.len(),
            #[cfg(curve25519_backend = "simd")]
            VartimePrecomputedStraus::Avx512ifma(inner) => inner.len(),
            VartimePrecomputedStraus::Scalar(inner) => inner.len(),
        }
    }

    /// Determine if the precomputation is empty.
    pub fn is_empty(&self) -> bool {
        use crate::traits::VartimePrecomputedMultiscalarMul;

        match self {
            #[cfg(curve25519_backend = "simd")]
            VartimePrecomputedStraus::Avx2(inner) => inner.is_empty(),
            #[cfg(curve25519_backend = "simd")]
            VartimePrecomputedStraus::Avx512ifma(inner) => inner.is_empty(),
            VartimePrecomputedStraus::Scalar(inner) => inner.is_empty(),
        }
    }

    pub fn optional_mixed_multiscalar_mul<I, J, K>(
        &self,
        static_scalars: I,
        dynamic_scalars: J,
        dynamic_points: K,
    ) -> Option<EdwardsPoint>
    where
        I: IntoIterator,
        I::Item: core::borrow::Borrow<Scalar>,
        J: IntoIterator,
        J::Item: core::borrow::Borrow<Scalar>,
        K: IntoIterator<Item = Option<EdwardsPoint>>,
    {
        use crate::traits::VartimePrecomputedMultiscalarMul;

        match self {
            #[cfg(curve25519_backend = "simd")]
            VartimePrecomputedStraus::Avx2(inner) => inner.optional_mixed_multiscalar_mul(
                static_scalars,
                dynamic_scalars,
                dynamic_points,
            ),
            #[cfg(curve25519_backend = "simd")]
            VartimePrecomputedStraus::Avx512ifma(inner) => inner.optional_mixed_multiscalar_mul(
                static_scalars,
                dynamic_scalars,
                dynamic_points,
            ),
            VartimePrecomputedStraus::Scalar(inner) => inner.optional_mixed_multiscalar_mul(
                static_scalars,
                dynamic_scalars,
                dynamic_points,
            ),
        }
    }
}

#[allow(missing_docs)]
#[cfg(feature = "alloc")]
pub fn straus_multiscalar_mul<I, J>(scalars: I, points: J) -> EdwardsPoint
where
    I: IntoIterator,
    I::Item: core::borrow::Borrow<Scalar>,
    J: IntoIterator,
    J::Item: core::borrow::Borrow<EdwardsPoint>,
{
    use crate::traits::MultiscalarMul;

    match get_selected_backend() {
        #[cfg(curve25519_backend = "simd")]
        BackendKind::Avx2 => {
            vector::scalar_mul::straus::spec_avx2::Straus::multiscalar_mul::<I, J>(scalars, points)
        }
        #[cfg(curve25519_backend = "simd")]
        BackendKind::Avx512 => {
            vector::scalar_mul::straus::spec_avx512ifma_avx512vl::Straus::multiscalar_mul::<I, J>(
                scalars, points,
            )
        }
        BackendKind::Serial => {
            serial::scalar_mul::straus::Straus::multiscalar_mul::<I, J>(scalars, points)
        }
    }
}

#[allow(missing_docs)]
#[cfg(feature = "alloc")]
pub fn straus_optional_multiscalar_mul<I, J>(scalars: I, points: J) -> Option<EdwardsPoint>
where
    I: IntoIterator,
    I::Item: core::borrow::Borrow<Scalar>,
    J: IntoIterator<Item = Option<EdwardsPoint>>,
{
    use crate::traits::VartimeMultiscalarMul;

    match get_selected_backend() {
        #[cfg(curve25519_backend = "simd")]
        BackendKind::Avx2 => {
            vector::scalar_mul::straus::spec_avx2::Straus::optional_multiscalar_mul::<I, J>(
                scalars, points,
            )
        }
        #[cfg(curve25519_backend = "simd")]
        BackendKind::Avx512 => {
            vector::scalar_mul::straus::spec_avx512ifma_avx512vl::Straus::optional_multiscalar_mul::<
                I,
                J,
            >(scalars, points)
        }
        BackendKind::Serial => {
            serial::scalar_mul::straus::Straus::optional_multiscalar_mul::<I, J>(scalars, points)
        }
    }
}

/// Perform constant-time, variable-base scalar multiplication.
pub fn variable_base_mul(point: &EdwardsPoint, scalar: &Scalar) -> EdwardsPoint {
    match get_selected_backend() {
        #[cfg(curve25519_backend = "simd")]
        BackendKind::Avx2 => vector::scalar_mul::variable_base::spec_avx2::mul(point, scalar),
        #[cfg(curve25519_backend = "simd")]
        BackendKind::Avx512 => {
            vector::scalar_mul::variable_base::spec_avx512ifma_avx512vl::mul(point, scalar)
        }
        BackendKind::Serial => serial::scalar_mul::variable_base::mul(point, scalar),
    }
}

/// Compute \\(aA + bB\\) in variable time, where \\(B\\) is the Ed25519 basepoint.
#[allow(non_snake_case)]
pub fn vartime_double_base_mul(a: &Scalar, A: &EdwardsPoint, b: &Scalar) -> EdwardsPoint {
    match get_selected_backend() {
        #[cfg(curve25519_backend = "simd")]
        BackendKind::Avx2 => vector::scalar_mul::vartime_double_base::spec_avx2::mul(a, A, b),
        #[cfg(curve25519_backend = "simd")]
        BackendKind::Avx512 => {
            vector::scalar_mul::vartime_double_base::spec_avx512ifma_avx512vl::mul(a, A, b)
        }
        BackendKind::Serial => serial::scalar_mul::vartime_double_base::mul(a, A, b),
    }
}

/// Compute \\(a_1 A_1 + a_2 A_2 + b B\\) in variable time, where \\(B\\) is the Ed25519 basepoint.
///
/// This function uses an optimized path when \\(a_1\\) and \\(a_2\\) are less than \\(2^{128}\\),
/// and falls back to general scalar multiplication otherwise.
#[allow(non_snake_case)]
pub fn vartime_triple_base_mul_128_128_256(
    a1: &Scalar,
    A1: &EdwardsPoint,
    a2: &Scalar,
    A2: &EdwardsPoint,
    b: &Scalar,
) -> EdwardsPoint {
    if !scalar_fits_in_128_bits(a1) || !scalar_fits_in_128_bits(a2) {
        return (a1 * A1) + (a2 * A2) + EdwardsPoint::mul_base(b);
    }

    vartime_triple_base_mul_128_128_256_prechecked(a1, A1, a2, A2, b)
}

/// Compute \\(a_1 A_1 + a_2 A_2 + b B\\) using the optimized 128/128/256-bit path.
///
/// Callers must ensure \\(a_1\\) and \\(a_2\\) are less than \\(2^{128}\\).
#[allow(non_snake_case)]
pub(crate) fn vartime_triple_base_mul_128_128_256_prechecked(
    a1: &Scalar,
    A1: &EdwardsPoint,
    a2: &Scalar,
    A2: &EdwardsPoint,
    b: &Scalar,
) -> EdwardsPoint {
    match get_selected_backend() {
        #[cfg(curve25519_backend = "simd")]
        BackendKind::Avx2 => {
            vector::scalar_mul::vartime_triple_base::spec_avx2::mul_128_128_256_prechecked(
                a1, A1, a2, A2, b,
            )
        }
        #[cfg(curve25519_backend = "simd")]
        BackendKind::Avx512 => {
            vector::scalar_mul::vartime_triple_base::spec_avx512ifma_avx512vl::mul_128_128_256_prechecked(
                a1, A1, a2, A2, b,
            )
        }
        BackendKind::Serial => {
            serial::scalar_mul::vartime_triple_base::mul_128_128_256_prechecked(a1, A1, a2, A2, b)
        }
    }
}

/// A prepared width-8 odd-multiples lookup table for a fixed point, stored in
/// the format of whichever backend was selected when it was built.
///
/// Boxed, because callers hold this type long-term inside prepared keys.
#[cfg(feature = "alloc")]
#[derive(Clone)]
pub(crate) enum PreparedNafTable {
    #[cfg(curve25519_backend = "simd")]
    Avx2(alloc::boxed::Box<crate::window::NafLookupTable8<vector::avx2::edwards::CachedPoint>>),
    #[cfg(curve25519_backend = "simd")]
    Ifma(alloc::boxed::Box<crate::window::NafLookupTable8<vector::ifma::edwards::CachedPoint>>),
    Serial(
        alloc::boxed::Box<crate::window::NafLookupTable8<serial::curve_models::AffineNielsPoint>>,
    ),
}

#[cfg(feature = "alloc")]
impl PreparedNafTable {
    /// Build the table for `A` using the currently selected backend.
    #[allow(non_snake_case)]
    pub(crate) fn for_point(A: &EdwardsPoint) -> Self {
        match get_selected_backend() {
            #[cfg(curve25519_backend = "simd")]
            BackendKind::Avx2 => PreparedNafTable::Avx2(alloc::boxed::Box::new(
                vector::scalar_mul::vartime_triple_base::spec_avx2::build_prepared_a2_table(A),
            )),
            #[cfg(curve25519_backend = "simd")]
            BackendKind::Avx512 => PreparedNafTable::Ifma(alloc::boxed::Box::new(
                vector::scalar_mul::vartime_triple_base::spec_avx512ifma_avx512vl::build_prepared_a2_table(A),
            )),
            BackendKind::Serial => PreparedNafTable::Serial(alloc::boxed::Box::new(
                crate::window::NafLookupTable8::from_edwards_batch(A),
            )),
        }
    }
}

/// Compute \\(a_1 A_1 + a_2 A_2 + b B\\) using the optimized 128/128/256-bit
/// path, with \\(A_2\\) available both as a point and as a prepared lookup table.
///
/// If `negate_A2` is true the \\(a_2\\) digits are negated, so the cached table
/// serves both signs. The raw `A2` point is only used by the fallback for a
/// table whose backend does not match the selected one.
///
/// Callers must ensure \\(a_1\\) and \\(a_2\\) are less than \\(2^{128}\\).
#[cfg(feature = "alloc")]
#[allow(non_snake_case)]
pub(crate) fn vartime_triple_base_mul_128_128_256_prechecked_prepared(
    a1: &Scalar,
    A1: &EdwardsPoint,
    a2: &Scalar,
    table_A2: &PreparedNafTable,
    negate_A2: bool,
    A2: &EdwardsPoint,
    b: &Scalar,
) -> EdwardsPoint {
    match (get_selected_backend(), table_A2) {
        #[cfg(curve25519_backend = "simd")]
        (BackendKind::Avx2, PreparedNafTable::Avx2(table)) => {
            vector::scalar_mul::vartime_triple_base::spec_avx2::mul_128_128_256_prechecked_prepared(
                a1, A1, a2, table, negate_A2, b,
            )
        }
        #[cfg(curve25519_backend = "simd")]
        (BackendKind::Avx512, PreparedNafTable::Ifma(table)) => {
            vector::scalar_mul::vartime_triple_base::spec_avx512ifma_avx512vl::mul_128_128_256_prechecked_prepared(
                a1, A1, a2, table, negate_A2, b,
            )
        }
        (BackendKind::Serial, PreparedNafTable::Serial(table)) => {
            serial::scalar_mul::vartime_triple_base::mul_128_128_256_prechecked_prepared(
                a1, A1, a2, table, negate_A2, b,
            )
        }
        #[allow(unreachable_patterns)]
        _ => {
            let A2 = if negate_A2 { -A2 } else { *A2 };
            vartime_triple_base_mul_128_128_256_prechecked(a1, A1, a2, &A2, b)
        }
    }
}

#[inline]
fn scalar_fits_in_128_bits(scalar: &Scalar) -> bool {
    scalar.as_bytes()[16..32].iter().all(|&byte| byte == 0)
}
