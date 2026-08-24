use ark_ff::PrimeField;
use criterion::{Criterion, criterion_group, criterion_main};
use light_poseidon::PoseidonHasher;
use rand::RngExt; // Required for the `.random()` trait method
use solana_bn254::backend::{Backend, Fr, MontgomeryBackend, U256};
use solana_bn254::poseidon::{constants::*, hash};

/// A uniformly random field element, as both an arkworks element and a
/// Montgomery-form `U256`, so both implementations hash identical inputs.
fn random_element() -> (ark_bn254::Fr, U256) {
    let mut rng = rand::rng();
    let f = ark_bn254::Fr::from_be_bytes_mod_order(&rng.random::<[u8; 32]>());
    (f, Backend::<Fr>::to_mont(&U256::new(f.into_bigint().0)))
}

macro_rules! bench_width {
    ($c:expr, $t:literal, $params:ident) => {{
        let params = &$params;
        let nr_inputs = $t - 1;

        let mut ark_inputs = Vec::with_capacity(nr_inputs);
        let mut our_inputs = Vec::with_capacity(nr_inputs);
        for _ in 0..nr_inputs {
            let (f, u) = random_element();
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

criterion_group!(benches, bench_poseidon);
criterion_main!(benches);
