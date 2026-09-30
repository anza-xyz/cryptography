//! `sum_of_products` over moduli with and without a spare top bit.

use num_bigint::BigUint;
use rand::{RngExt, SeedableRng, rngs::StdRng};
use solana_bn254::backend::{Backend, Field, Fq, Fr, MontgomeryBackend, U256};

/// 2^255 - 19, two products per reduction.
struct P25519;

impl Field for P25519 {
    const MODULUS: U256 = U256::new([0xffffffffffffffed, u64::MAX, u64::MAX, 0x7fffffffffffffff]);
    const INV: u64 = 0x86bca1af286bca1b;
    const R2: U256 = U256::new([0x5a4, 0, 0, 0]);
}

/// 2^256 - 189, where reduction carries past 2^256.
struct P256;

impl Field for P256 {
    const MODULUS: U256 = U256::new([0xffffffffffffff43, u64::MAX, u64::MAX, u64::MAX]);
    const INV: u64 = 0xa53fa94fea53fa95;
    const R2: U256 = U256::new([0x8b89, 0, 0, 0]);
}

/// 97, where `LAZY_TERMS` saturates.
struct P97;

impl Field for P97 {
    const MODULUS: U256 = U256::new([97, 0, 0, 0]);
    const INV: u64 = 0x5c5f02a3a0fd5c5f;
    const R2: U256 = U256::new([35, 0, 0, 0]);
}

fn big(x: &U256) -> BigUint {
    x.0.iter()
        .rev()
        .fold(BigUint::ZERO, |acc, &limb| (acc << 64u32) + limb)
}

fn limbs(x: &BigUint) -> U256 {
    let mut out = [0; 4];
    for (limb, digit) in out.iter_mut().zip(x.iter_u64_digits()) {
        *limb = digit;
    }
    U256::new(out)
}

struct Oracle {
    p: BigUint,
    r_inverse: BigUint,
}

impl Oracle {
    fn new<F: Field>() -> Self {
        let p = big(&F::MODULUS);
        let r_inverse = (BigUint::from(1u8) << 256u32).modpow(&(&p - 2u8), &p);
        Self { p, r_inverse }
    }

    fn element(&self, x: BigUint) -> U256 {
        limbs(&(x % &self.p))
    }

    fn sum_of_products(&self, a: &[U256], b: &[U256]) -> U256 {
        let sum: BigUint = a.iter().zip(b).map(|(x, y)| big(x) * big(y)).sum();
        self.element(sum * &self.r_inverse)
    }

    fn boundary_values(&self) -> Vec<U256> {
        let mut values: Vec<U256> = (0u8..4).map(|v| self.element(v.into())).collect();
        for delta in [1u64, 2, 3, 4, 7, 8, 15, 16, u64::MAX] {
            values.push(self.element(&self.p - delta % &self.p));
        }
        for bit in [
            1u32, 63, 64, 65, 127, 128, 129, 191, 192, 193, 252, 253, 255,
        ] {
            let power = BigUint::from(1u8) << bit;
            values.extend([&power - 1u8, power.clone(), power + 1u8].map(|v| self.element(v)));
        }
        values
    }

    fn uniform(&self, rng: &mut StdRng) -> U256 {
        self.element(BigUint::from_bytes_le(&rng.random::<[u8; 32]>()))
    }

    /// Pushes each chunk sum toward `MODULUS * 2^256`.
    fn near_modulus(&self, rng: &mut StdRng) -> U256 {
        self.element(&self.p - (u64::from(rng.random::<u32>()) + 1) % &self.p)
    }
}

fn check<F: Field, const N: usize>(oracle: &Oracle, rng: &mut StdRng) {
    let assert_sum = |a: &[U256; N], b: &[U256; N]| {
        assert_eq!(
            Backend::<F>::sum_of_products(a, b),
            oracle.sum_of_products(a, b),
            "width {N}, a={a:?}, b={b:?}"
        );
    };

    let top = oracle.element(&oracle.p - 1u8);
    assert_sum(&[top; N], &[top; N]);

    let values = oracle.boundary_values();
    for start in 0..values.len() {
        let a = core::array::from_fn(|k| values[(start + k) % values.len()]);
        let b = core::array::from_fn(|k| values[(start + 3 * k + 1) % values.len()]);
        assert_sum(&a, &b);
    }

    for operand in [Oracle::uniform, Oracle::near_modulus] {
        for _ in 0..64 {
            let a = core::array::from_fn(|_| operand(oracle, rng));
            let b = core::array::from_fn(|_| operand(oracle, rng));
            assert_sum(&a, &b);
        }
    }
}

fn check_field<F: Field>(seed: u64) {
    let oracle = Oracle::new::<F>();
    let mut rng = StdRng::seed_from_u64(seed);
    macro_rules! widths {
        ($($n:literal)+) => { $(check::<F, $n>(&oracle, &mut rng);)+ };
    }
    widths!(0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17);
}

#[test]
fn fr_matches_oracle() {
    check_field::<Fr>(0x7375_6d5f_6672);
}

#[test]
fn fq_matches_oracle() {
    check_field::<Fq>(0x7375_6d5f_6671);
}

#[test]
fn two_products_per_chunk_match_oracle() {
    check_field::<P25519>(0x7375_6d5f_3235_3531);
}

#[test]
fn carry_out_matches_oracle() {
    check_field::<P256>(0x7375_6d5f_3235_3639);
}

#[test]
fn saturated_chunk_matches_oracle() {
    check_field::<P97>(0x7375_6d5f_3937);
}

#[test]
fn every_operand_pair_matches_oracle_modulo_97() {
    let oracle = Oracle::new::<P97>();
    for a in 0..97 {
        for b in 0..97 {
            let x = U256::new([a, 0, 0, 0]);
            let y = U256::new([b, 0, 0, 0]);
            assert_eq!(
                Backend::<P97>::sum_of_products(&[x], &[y]),
                oracle.sum_of_products(&[x], &[y]),
                "a={a}, b={b}"
            );
            assert_eq!(
                Backend::<P97>::sum_of_products(&[x; 2], &[y; 2]),
                oracle.sum_of_products(&[x; 2], &[y; 2]),
                "a={a}, b={b}, two terms"
            );
        }
    }
}
