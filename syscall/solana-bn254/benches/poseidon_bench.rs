use ark_ff::{Field as _, PrimeField};
use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use light_poseidon::PoseidonHasher;
use rand::{RngExt, SeedableRng, rngs::StdRng};
use solana_bn254::backend::{Backend, Fr, MontgomeryBackend, U256};
use solana_bn254::poseidon::{constants::*, hash, sbox};
use std::hint::black_box;

/// A field element represented by both arkworks and this crate.
/// Both representations correspond to the same field value.
fn random_element(rng: &mut StdRng) -> (ark_bn254::Fr, U256) {
    let f = ark_bn254::Fr::from_be_bytes_mod_order(&rng.random::<[u8; 32]>());
    (f, Backend::<Fr>::to_mont(&U256::new(f.into_bigint().0)))
}

macro_rules! bench_width {
    ($c:expr, $t:literal, $params:ident) => {{
        let params = &$params;
        let nr_inputs = $t - 1;
        let mut rng = StdRng::seed_from_u64(0x706f_7365_6964_6f6e);

        let mut ark_inputs = Vec::with_capacity(nr_inputs);
        let mut our_inputs = Vec::with_capacity(nr_inputs);
        for _ in 0..nr_inputs {
            let (f, u) = random_element(&mut rng);
            ark_inputs.push(f);
            our_inputs.push(u);
        }

        let mut hasher = light_poseidon::Poseidon::<ark_bn254::Fr>::new_circom(nr_inputs).unwrap();

        // Both sides must agree before either is timed. Without this, a build
        // whose arithmetic is wrong still produces publishable-looking numbers.
        let ours = Backend::<Fr>::from_mont(&hash(&our_inputs, params).unwrap());
        let theirs = U256::new(hasher.hash(&ark_inputs).unwrap().into_bigint().0);
        assert_eq!(ours, theirs, concat!("digest mismatch at T = ", $t));

        let mut group = $c.benchmark_group(concat!("poseidon_t", $t));

        group.bench_function("solana-bn254", |b| {
            b.iter(|| hash(std::hint::black_box(&our_inputs), params).unwrap())
        });

        group.bench_function("light-poseidon", |b| {
            b.iter(|| hasher.hash(std::hint::black_box(&ark_inputs)).unwrap())
        });

        group.finish();
    }};
}

fn bench_poseidon(c: &mut Criterion) {
    // Solana `sol_poseidon` syscall supported parameters: state widths
    // t = 2..=13, mapping to 1..=12 inputs. Round counts now come from the
    // parameter sets themselves rather than being repeated here.
    bench_width!(c, 2, BN254_X5_T2);
    bench_width!(c, 3, BN254_X5_T3);
    bench_width!(c, 4, BN254_X5_T4);
    bench_width!(c, 5, BN254_X5_T5);
    bench_width!(c, 6, BN254_X5_T6);
    bench_width!(c, 7, BN254_X5_T7);
    bench_width!(c, 8, BN254_X5_T8);
    bench_width!(c, 9, BN254_X5_T9);
    bench_width!(c, 10, BN254_X5_T10);
    bench_width!(c, 11, BN254_X5_T11);
    bench_width!(c, 12, BN254_X5_T12);
    bench_width!(c, 13, BN254_X5_T13);
}

fn bench_scalar_arithmetic(c: &mut Criterion) {
    type B = Backend<Fr>;
    const CHAIN_LENGTH: u64 = 64;

    let mut rng = StdRng::seed_from_u64(0x6172_6974_685f_7631);
    let (ark_start, start) = random_element(&mut rng);
    let (ark_factor, factor) = random_element(&mut rng);

    // Check all four chains against arkworks before timing anything.
    let mut mul_result = start;
    let mut mul_self_result = start;
    let mut sqr_result = start;
    let mut sbox_result = start;

    let mut ark_mul = ark_start;
    let mut ark_square = ark_start;
    let mut ark_sbox = ark_start;

    for _ in 0..CHAIN_LENGTH {
        mul_result = B::mul(&mul_result, &factor);
        mul_self_result = B::mul(&mul_self_result, &mul_self_result);
        sqr_result = B::sqr(&sqr_result);
        sbox_result = sbox(&sbox_result);

        ark_mul *= ark_factor;
        ark_square = ark_square.square();
        ark_sbox = ark_sbox.pow([5u64]);
    }

    // Construct the expected Montgomery residues using arkworks alone.
    // Exact limb equality also checks that each result is fully reduced.
    let radix = ark_bn254::Fr::from(2u64).pow([256u64]);

    for (name, actual, expected) in [
        ("mul", mul_result, ark_mul),
        ("mul_self", mul_self_result, ark_square),
        ("sqr", sqr_result, ark_square),
        ("sbox", sbox_result, ark_sbox),
    ] {
        assert_eq!(
            actual,
            U256::new((expected * radix).into_bigint().0),
            "{name} chain mismatch"
        );
    }

    let mut group = c.benchmark_group("scalar_arithmetic");
    group.throughput(Throughput::Elements(CHAIN_LENGTH));

    // Every chain begins with the same inputs on every iteration.
    // Each call consumes the preceding call's result.
    // Black boxes at the chain boundaries prevent constant folding
    // and removal of the result without adding barriers between calls.

    group.bench_function("mul_chain_64", |b| {
        b.iter(|| {
            let mut value = black_box(start);
            let multiplier = black_box(factor);

            for _ in 0..CHAIN_LENGTH {
                value = B::mul(&value, &multiplier);
            }

            black_box(value)
        })
    });

    // This matches the operation used by the original sqr implementation.
    group.bench_function("mul_self_chain_64", |b| {
        b.iter(|| {
            let mut value = black_box(start);

            for _ in 0..CHAIN_LENGTH {
                value = B::mul(&value, &value);
            }

            black_box(value)
        })
    });

    group.bench_function("sqr_chain_64", |b| {
        b.iter(|| {
            let mut value = black_box(start);

            for _ in 0..CHAIN_LENGTH {
                value = B::sqr(&value);
            }

            black_box(value)
        })
    });

    // Measure two squares followed by a multiplication in their actual
    // scalar S-box context.
    group.bench_function("sbox_chain_64", |b| {
        b.iter(|| {
            let mut value = black_box(start);

            for _ in 0..CHAIN_LENGTH {
                value = sbox(&value);
            }

            black_box(value)
        })
    });

    group.finish();
}

criterion_group!(benches, bench_poseidon, bench_scalar_arithmetic);
criterion_main!(benches);
