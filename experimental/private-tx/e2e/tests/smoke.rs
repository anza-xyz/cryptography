//! Pipeline smoke test: a gnark proof of 3·5 = 15 from `privtx smoke-fixture`
//! converts to the on-chain format, verifies through the verifier's host
//! path, and, when the SBF artifact is available, through the verifier
//! program itself under Mollusk.

mod sbf;

use {
    private_tx_e2e::{load_groth16, u64_to_bytes},
    solana_groth16_verify::{constants::FR_MODULUS, verify, Groth16Error, Proof, VerifyingKey},
};

const FIXTURE: &str = "smoke";

#[test]
fn public_inputs_are_3_5_15() {
    let g = load_groth16(FIXTURE);
    assert_eq!(g.key.num_public_inputs(), 3);
    g.key.validate_for_publish().unwrap();
    assert_eq!(
        g.public_inputs,
        vec![u64_to_bytes(3), u64_to_bytes(5), u64_to_bytes(15)]
    );
}

#[test]
fn proof_verifies_on_host_path() {
    let g = load_groth16(FIXTURE);
    let vk = VerifyingKey::from_body(g.key.body()).unwrap();
    let proof = Proof::from_bytes(&g.proof.0).unwrap();
    let flat: Vec<u8> = g.public_inputs.concat();
    verify(&vk, &proof, &flat).unwrap();

    // 3 · 5 ≠ 16.
    let mut wrong = flat.clone();
    wrong[95] = 16;
    assert_eq!(verify(&vk, &proof, &wrong), Err(Groth16Error::ProofInvalid));

    // A non-canonical scalar is rejected before the pairing.
    let mut non_canonical = flat.clone();
    non_canonical[..32].copy_from_slice(&FR_MODULUS);
    assert_eq!(
        verify(&vk, &proof, &non_canonical),
        Err(Groth16Error::NonCanonicalScalar)
    );
    assert_eq!(
        verify(&vk, &proof, &flat[..64]),
        Err(Groth16Error::PublicInputCountMismatch)
    );
}

#[test]
fn proof_verifies_on_sbf() {
    let Some(h) = sbf::Harness::new() else { return };
    let g = load_groth16(FIXTURE);
    let key_account = h.register(&g.key);

    let ok = h.verify(&key_account, &g.proof.0, &g.public_inputs);
    sbf::assert_success(&ok);
    println!(
        "smoke on SBF: n = {}, {} CUs",
        g.key.num_public_inputs(),
        ok.compute_units_consumed
    );

    let mut wrong = g.public_inputs.clone();
    wrong[2][31] = 16;
    sbf::assert_custom_error(
        &h.verify(&key_account, &g.proof.0, &wrong),
        sbf::code::PROOF_INVALID,
    );
    sbf::assert_custom_error(
        &h.verify(&key_account, &g.proof.0, &g.public_inputs[..2]),
        sbf::code::PUBLIC_INPUT_COUNT_MISMATCH,
    );
}
