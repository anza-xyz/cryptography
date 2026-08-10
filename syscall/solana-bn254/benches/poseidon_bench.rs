use ark_ff::PrimeField;
use criterion::{Criterion, criterion_group, criterion_main};
use light_poseidon::PoseidonHasher;
use rand::RngExt; // Required for the `.random()` trait method
use solana_bn254::{
    backend::U256,
    poseidon::{PoseidonConstants, SparseMatrix},
};

/// Generates a randomized field element safely constrained below the BN254 Fr modulus.
fn random_fr() -> U256 {
    let mut rng = rand::rng();
    let mut limbs: [u64; 4] = rng.random();
    // Mask the top u64 to guarantee it stays strictly below Fr::MODULUS
    limbs[3] &= 0x0FFFFFFFFFFFFFFF;
    U256::new(limbs)
}

/// Dynamically leaks a set of dummy parameters onto the heap.
/// Because Criterion runs this outside the hot-loop, the `O(1)` memory
/// leak per benchmark group is completely acceptable and ensures
/// we can provide the `'static` lifetimes required by the crate.
fn make_dummy_constants<const T: usize>(partial_rounds: usize) -> &'static PoseidonConstants<T> {
    let num_round_constants = (9 * T) + partial_rounds;
    let round_constants = (0..num_round_constants)
        .map(|_| random_fr())
        .collect::<Vec<_>>()
        .leak();

    let mut mds_matrix = [[U256::zero(); T]; T];
    for row in mds_matrix.iter_mut() {
        for val in row.iter_mut() {
            *val = random_fr();
        }
    }
    let mds_matrix = Box::leak(Box::new(mds_matrix));

    let mut pre_sparse_matrix = [[U256::zero(); T]; T];
    for row in pre_sparse_matrix.iter_mut() {
        for val in row.iter_mut() {
            *val = random_fr();
        }
    }
    let pre_sparse_matrix = Box::leak(Box::new(pre_sparse_matrix));

    let sparse_matrices = (0..partial_rounds)
        .map(|_| {
            let mut row = [U256::zero(); T];
            let mut col = [U256::zero(); T];
            for i in 0..T {
                row[i] = random_fr();
                col[i] = random_fr();
            }
            SparseMatrix { row, col }
        })
        .collect::<Vec<_>>()
        .leak();

    Box::leak(Box::new(PoseidonConstants {
        full_rounds: 8,
        partial_rounds,
        round_constants,
        mds_matrix,
        pre_sparse_matrix,
        sparse_matrices,
    }))
}

macro_rules! bench_width {
    ($c:expr, $t:literal, $partial_rounds:literal) => {
        let constants = make_dummy_constants::<$t>($partial_rounds);

        let mut group = $c.benchmark_group(concat!("poseidon_t", $t));
        let nr_inputs = $t - 1;

        // --- solana-bn254 ---
        let state = core::array::from_fn(|_| random_fr());
        group.bench_function("solana-bn254", |b| {
            b.iter(|| {
                // Uses std::hint::black_box instead of deprecated criterion::black_box
                solana_bn254::poseidon::poseidon(std::hint::black_box(state), constants)
            })
        });

        // --- light-poseidon ---
        // Note: light-poseidon handles its own internal constant generation
        // via `new_circom()`. We generate inputs from randomized byte arrays
        // here, but because this happens outside the `b.iter()` block, it does
        // not penalize the light-poseidon benchmark times.
        let mut hasher = light_poseidon::Poseidon::<ark_bn254::Fr>::new_circom(nr_inputs).unwrap();
        let mut rng = rand::rng();
        let inputs: Vec<_> = (0..nr_inputs)
            .map(|_| ark_bn254::Fr::from_be_bytes_mod_order(&rng.random::<[u8; 32]>()))
            .collect();

        group.bench_function("light-poseidon", |b| {
            b.iter(|| hasher.hash(std::hint::black_box(&inputs)).unwrap())
        });

        group.finish();
    };
}

fn bench_poseidon(c: &mut Criterion) {
    // Solana `sol_poseidon` syscall supported parameters.
    // These specific partial round counts are mandated by the SVM
    // for state widths t=2..13 (which map to 1..12 inputs).
    // [56, 57, 56, 60, 60, 63, 64, 63, 60, 66, 60, 65]
    bench_width!(c, 2, 56);
    bench_width!(c, 3, 57);
    bench_width!(c, 4, 56);
    bench_width!(c, 5, 60);
    bench_width!(c, 6, 60);
    bench_width!(c, 7, 63);
    bench_width!(c, 8, 64);
    bench_width!(c, 9, 63);
    bench_width!(c, 10, 60);
    bench_width!(c, 11, 66);
    bench_width!(c, 12, 60);
    bench_width!(c, 13, 65);
}

criterion_group!(benches, bench_poseidon);
criterion_main!(benches);
