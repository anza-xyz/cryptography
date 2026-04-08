use std::time::Instant;

use ed25519_pokos::{
    Seed, deserialize_proof, gen_pokos, private_seed_chain, serialize_proof, verify_pokos,
};

fn main() -> Result<(), String> {
    let seed: Seed = [7_u8; 32];

    let proving_start = Instant::now();
    let proof = gen_pokos(seed)?;
    let proving_time = proving_start.elapsed();

    let verification_start = Instant::now();
    verify_pokos(&proof).map_err(|err| format!("verification failed: {err:?}"))?;
    let verification_time = verification_start.elapsed();

    let encoded = serialize_proof(&proof);
    let decoded = deserialize_proof(&encoded).map_err(|err| format!("decode failed: {err:?}"))?;
    verify_pokos(&decoded).map_err(|err| format!("round-trip verification failed: {err:?}"))?;

    println!("commit_of_seed: {:02x?}", proof.statement.commit_of_seed);
    println!("hash_of_sk: {:02x?}", proof.statement.hash_of_sk);
    println!("proving_time_ms: {}", proving_time.as_millis());
    println!("verification_time_ms: {}", verification_time.as_millis());
    println!(
        "air_trace_rows: {}",
        private_seed_chain::ACTIVE_AIR_TRACE_ROWS
    );
    println!(
        "air_trace_cols: {}",
        private_seed_chain::ACTIVE_AIR_TRACE_COLS
    );
    println!("proof_bytes: {}", encoded.len());
    println!("verification: ok");

    Ok(())
}
