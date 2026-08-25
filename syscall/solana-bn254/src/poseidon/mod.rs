//! Poseidon hash implementation using the Fr scalar field.
//!
//! Includes optimized scalar execution routes using sparse matrices
//! for partial rounds, alongside an AVX-512 IFMA batched execution route
//! for maximum throughput on supporting hardware.
//!
//! # Hybrid Execution Architecture
//! - Partial Rounds: Uses strictly scalar logic. Because only the first element
//!   `state[0]` receives an S-box, parallelization provides no benefit here.
//! - Full Rounds: When compiled for native targets supporting `AVX-512 IFMA`,
//!   the full rounds dynamically route to an 8-way batched SIMD engine.

use crate::backend::{Backend, Fr, MontgomeryBackend, U256};

pub mod constants;

/// Sparse matrix representation for Poseidon partial rounds.
///
/// Precomputing the MDS matrix transitions into a sparse vector form reduces
/// the `O(T^2)` dense matrix multiplication down to an `O(T)` sparse matrix
/// computation, saving massive Compute Units on-chain.
///
/// `row` is the matrix's first row; `col[i]` for `i >= 1` is the entry at
/// `[i][0]`. All other entries are the identity, and `col[0]` is unused.
#[derive(Clone, Debug)]
pub struct SparseMatrix<const T: usize> {
    pub row: [U256; T],
    pub col: [U256; T],
}

/// Constants required for Poseidon execution over a state of width `T`.
///
/// # Layout
/// `round_constants` holds exactly `T * full_rounds + partial_rounds` elements
/// in Montgomery form, ordered as `T` per full round in the first half, then one
/// per partial round, then `T` per full round in the second half.
///
/// The factorization follows the optimized Poseidon construction: the final full
/// round of the first half applies `pre_sparse_matrix` in place of `mds_matrix`,
/// and each partial round applies its own `SparseMatrix`. See
/// [`constants`] for the default circom-compatible parameters.
pub struct PoseidonConstants<const T: usize> {
    pub full_rounds: usize,
    pub partial_rounds: usize,
    pub round_constants: &'static [U256],
    pub mds_matrix: &'static [[U256; T]; T],
    pub pre_sparse_matrix: &'static [[U256; T]; T],
    pub sparse_matrices: &'static [SparseMatrix<T>],
}

/// Computes the scalar Poseidon S-box (`x^5`) using exactly 3 inlined multiplications.
#[inline(always)]
pub fn sbox(x: &U256) -> U256 {
    type B = Backend<Fr>;
    let x2 = B::sqr(x);
    let x4 = B::sqr(&x2);
    B::mul(&x4, x)
}

/// Computes 8 Poseidon S-boxes simultaneously utilizing AVX-512 vectorization.
///
/// The state is dynamically chunked in groups of 8. This guarantees full utilization
/// of the SIMD registers for large state widths.
#[cfg(all(target_arch = "x86_64", target_feature = "avx512ifma"))]
#[inline]
#[target_feature(enable = "avx512f,avx512ifma,avx512dq")]
unsafe fn apply_sbox_simd<const T: usize>(state: &mut [U256; T]) {
    use crate::backend::avx512::{
        math::sbox_8x,
        pack::{pack_8x, unpack_8x_into},
    };
    let mut i = 0;

    // Process state in chunks of 8 to saturate the SIMD lanes
    while i < T {
        let chunk_size = core::cmp::min(8, T - i);
        let mut chunk = [U256::zero(); 8];
        chunk[..chunk_size].copy_from_slice(&state[i..i + chunk_size]);

        unsafe {
            let packed = pack_8x(&chunk);
            let sboxed = sbox_8x(&packed);
            unpack_8x_into(&sboxed, &mut chunk);
        }

        state[i..i + chunk_size].copy_from_slice(&chunk[..chunk_size]);
        i += chunk_size;
    }
}

/// Computes a dense Matrix-Vector multiplication using AVX-512 Column-Accumulation.
///
/// Instead of computing rows sequentially (`T^2` multiplications), we broadcast
/// the scalar `state[j]`, pack the Matrix Column `j` into a SIMD vector, and execute
/// parallel multiplications.
///
/// # Input criteria
/// Every element of `state` and of `mds` must be a fully reduced Montgomery-form
/// field element (`x < Fr::MODULUS`). Products are accumulated with the scalar
/// backend's `add`, which performs a single conditional subtraction and is only
/// correct for reduced operands. `mul_8x` upholds this on its results by ending
/// with a conditional subtraction of the modulus.
#[cfg(all(target_arch = "x86_64", target_feature = "avx512ifma"))]
#[inline]
#[target_feature(enable = "avx512f,avx512ifma,avx512dq")]
unsafe fn apply_dense_matrix_simd<const T: usize>(state: &mut [U256; T], mds: &[[U256; T]; T]) {
    use crate::backend::avx512::{
        math::mul_8x,
        pack::{broadcast, pack_8x, unpack_8x_into},
    };

    let mut new_state = [U256::zero(); T];

    for j in 0..T {
        // Broadcast state[j] horizontally across all 8 SIMD lanes
        let sj_broadcast = unsafe { broadcast(&state[j]) };

        // Extract column j from the dense matrix
        let mut col = [U256::zero(); T];
        for i in 0..T {
            col[i] = mds[i][j];
        }

        let mut i = 0;
        while i < T {
            let chunk_size = core::cmp::min(8, T - i);
            let mut col_chunk = [U256::zero(); 8];
            col_chunk[..chunk_size].copy_from_slice(&col[i..i + chunk_size]);

            let mut terms = [U256::zero(); 8];
            unsafe {
                let col_packed = pack_8x(&col_chunk);
                // Compute (Column * state[j]) simultaneously across up to 8 elements
                let term_packed = mul_8x(&sj_broadcast, &col_packed);
                unpack_8x_into(&term_packed, &mut terms);
            }

            // Accumulate safely using the scalar backend to automatically handle Modulus bounds
            for k in 0..chunk_size {
                new_state[i + k] = Backend::<Fr>::add(&new_state[i + k], &terms[k]);
            }
            i += chunk_size;
        }
    }
    *state = new_state;
}

/// Branchlessly executes a dense matrix multiplication on the scalar state.
#[cfg(not(all(target_arch = "x86_64", target_feature = "avx512ifma")))]
#[inline(always)]
fn apply_dense_matrix<const T: usize>(state: &mut [U256; T], m: &[[U256; T]; T]) {
    type B = Backend<Fr>;
    let mut new_state = [U256::zero(); T];
    for i in 0..T {
        let mut sum = U256::zero();
        for (j, state_val) in state.iter().enumerate() {
            let term = B::mul(&m[i][j], state_val);
            sum = B::add(&sum, &term);
        }
        new_state[i] = sum;
    }
    *state = new_state;
}

/// Executes an `O(T)` sparse matrix multiplication on the scalar state.
#[inline(always)]
fn apply_sparse_matrix<const T: usize>(state: &mut [U256; T], m: &SparseMatrix<T>) {
    type B = Backend<Fr>;
    let mut first_word = U256::zero();

    // Row vector dot product for the new state[0]
    for (j, state_val) in state.iter().enumerate() {
        let term = B::mul(&m.row[j], state_val);
        first_word = B::add(&first_word, &term);
    }

    let prev_first = state[0];
    state[0] = first_word;

    // Identity operations scaled by the sparse column vector
    for (i, state_val) in state.iter_mut().enumerate().skip(1) {
        let term = B::mul(&m.col[i], &prev_first);
        *state_val = B::add(state_val, &term);
    }
}

/// Applies the S-box to every state element, routing to SIMD where available.
#[inline(always)]
fn sbox_layer<const T: usize>(state: &mut [U256; T]) {
    #[cfg(all(target_arch = "x86_64", target_feature = "avx512ifma"))]
    unsafe {
        apply_sbox_simd(state);
    }
    #[cfg(not(all(target_arch = "x86_64", target_feature = "avx512ifma")))]
    for state_val in state.iter_mut() {
        *state_val = sbox(state_val);
    }
}

/// Applies a dense matrix to the state, routing to SIMD where available.
#[inline(always)]
fn dense_layer<const T: usize>(state: &mut [U256; T], m: &[[U256; T]; T]) {
    #[cfg(all(target_arch = "x86_64", target_feature = "avx512ifma"))]
    unsafe {
        apply_dense_matrix_simd(state, m);
    }
    #[cfg(not(all(target_arch = "x86_64", target_feature = "avx512ifma")))]
    apply_dense_matrix(state, m);
}

/// Executes the Poseidon permutation on a state already in Montgomery form.
///
/// Every element of `state` must be a fully reduced Montgomery-form field
/// element (`x < Fr::MODULUS`), per the `MontgomeryBackend` contract.
pub fn poseidon<const T: usize>(
    mut state: [U256; T],
    constants: &PoseidonConstants<T>,
) -> [U256; T] {
    type B = Backend<Fr>;
    let half_full = constants.full_rounds / 2;
    let rc = constants.round_constants;
    debug_assert_eq!(
        rc.len(),
        T * constants.full_rounds + constants.partial_rounds
    );
    let mut rc_idx = 0;

    // --- First Half: Full Rounds ---
    // The final round applies `pre_sparse_matrix`, setting up the sparse
    // factorization that the partial rounds rely on.
    for round in 0..half_full {
        for state_val in state.iter_mut() {
            *state_val = B::add(state_val, &rc[rc_idx]);
            rc_idx += 1;
        }
        sbox_layer(&mut state);
        if round + 1 == half_full {
            dense_layer(&mut state, constants.pre_sparse_matrix);
        } else {
            dense_layer(&mut state, constants.mds_matrix);
        }
    }

    // --- Middle: Partial Rounds ---
    // Kept strictly scalar because only state[0] receives the S-box computation,
    // rendering SIMD parallelization overhead highly inefficient here.
    for sparse_idx in 0..constants.partial_rounds {
        state[0] = B::add(&state[0], &rc[rc_idx]);
        rc_idx += 1;
        state[0] = sbox(&state[0]);
        apply_sparse_matrix(&mut state, &constants.sparse_matrices[sparse_idx]);
    }

    // --- Second Half: Full Rounds ---
    for _ in 0..half_full {
        for state_val in state.iter_mut() {
            *state_val = B::add(state_val, &rc[rc_idx]);
            rc_idx += 1;
        }
        sbox_layer(&mut state);
        dense_layer(&mut state, constants.mds_matrix);
    }

    state
}

/// Hashes `T - 1` field elements under the circom-compatible Poseidon
/// construction: a zero capacity element in `state[0]`, the inputs in
/// `state[1..]`, one permutation, and `state[0]` as the digest.
///
/// Inputs are Montgomery-form field elements. Returns `None` if
/// `inputs.len() != T - 1`, or if any input is not fully reduced —
/// an unreduced input would otherwise alias the value congruent to it,
/// so `MODULUS` and `0` would hash identically.
pub fn hash<const T: usize>(inputs: &[U256], constants: &PoseidonConstants<T>) -> Option<U256> {
    if inputs.len() + 1 != T {
        return None;
    }
    if !inputs.iter().all(Backend::<Fr>::is_reduced) {
        return None;
    }
    let mut state = [U256::zero(); T];
    state[1..].copy_from_slice(inputs);
    Some(poseidon(state, constants)[0])
}
