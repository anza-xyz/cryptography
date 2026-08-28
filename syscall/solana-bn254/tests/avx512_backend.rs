//! Direct tests for the AVX-512 IFMA backend, checked against the portable one.
//!
//! Compiles to an empty binary unless the SIMD path is active:
//!
//! ```bash
//! RUSTFLAGS="-C target-feature=+avx512f,+avx512ifma,+avx512dq" \
//!     cargo test -p solana-bn254 --test avx512_backend
//! ```

#![cfg(all(target_arch = "x86_64", target_feature = "avx512ifma"))]

use ark_ff::{BigInteger, PrimeField};
use rand::RngExt;
use solana_bn254::backend::avx512::math::{mul_8x, sbox_8x};
use solana_bn254::backend::avx512::pack::{pack_8x, unpack_8x};
use solana_bn254::backend::{Backend, Field, Fr, MontgomeryBackend, U256};
use solana_bn254::poseidon::sbox;

/// A uniformly random fully reduced field element.
fn random_element() -> U256 {
    let mut rng = rand::rng();
    let f = ark_bn254::Fr::from_be_bytes_mod_order(&rng.random::<[u8; 32]>());
    U256::new(f.into_bigint().0)
}

fn is_canonical(v: &U256) -> bool {
    let m = <Fr as Field>::MODULUS.0;
    for i in (0..4).rev() {
        if v.0[i] != m[i] {
            return v.0[i] < m[i];
        }
    }
    false
}

/// The largest fully reduced value, `MODULUS - 1`.
fn modulus_minus_one() -> U256 {
    let mut m = <Fr as Field>::MODULUS;
    m.0[0] -= 1;
    m
}

#[test]
fn mul_matches_portable_backend() {
    for _ in 0..64 {
        let a: [U256; 8] = core::array::from_fn(|_| random_element());
        let b: [U256; 8] = core::array::from_fn(|_| random_element());

        let got = unsafe { unpack_8x(&mul_8x(&pack_8x(&a), &pack_8x(&b))) };

        for lane in 0..8 {
            assert_eq!(
                got[lane],
                Backend::<Fr>::mul(&a[lane], &b[lane]),
                "lane {lane}"
            );
            assert!(is_canonical(&got[lane]), "lane {lane} left unreduced");
        }
    }
}

/// Zero, one, and `MODULUS - 1` in every combination. The largest operands are
/// the ones that push the CIOS result above the modulus, so they exercise the
/// final conditional subtraction rather than leaving it to chance.
#[test]
fn mul_edge_cases() {
    let values = [
        U256::zero(),
        Backend::<Fr>::to_mont(&U256::one()),
        modulus_minus_one(),
    ];

    for u in values.iter() {
        for v in values.iter() {
            let a = [*u; 8];
            let b = [*v; 8];
            let got = unsafe { unpack_8x(&mul_8x(&pack_8x(&a), &pack_8x(&b))) };
            let want = Backend::<Fr>::mul(u, v);
            for lane in got.iter() {
                assert_eq!(*lane, want);
                assert!(is_canonical(lane));
            }
        }
    }
}

#[test]
fn sbox_matches_portable_backend() {
    for _ in 0..64 {
        let x: [U256; 8] = core::array::from_fn(|_| random_element());
        let got = unsafe { unpack_8x(&sbox_8x(&pack_8x(&x))) };
        for lane in 0..8 {
            assert_eq!(got[lane], sbox(&x[lane]), "lane {lane}");
            assert!(is_canonical(&got[lane]), "lane {lane} left unreduced");
        }
    }
}
