//! C_mint end to end: the fixture's commitment is the Solana Poseidon of the
//! note, the proof verifies through the verifier's host path, and, when the
//! SBF artifact is available, through the verifier program itself.

mod sbf;

use {
    private_tx_e2e::{load_groth16, NoteOpening},
    solana_groth16_verify::{constants::FR_MODULUS, verify, Groth16Error, Proof, VerifyingKey},
};

const FIXTURE: &str = "mint";

#[test]
fn public_inputs_are_the_commitment_and_the_value() {
    let g = load_groth16(FIXTURE);
    let note = NoteOpening::load(FIXTURE);
    assert_eq!(g.public_inputs.len(), 2, "C_mint has two public inputs");
    assert_eq!(
        g.public_inputs[0],
        note.commitment_bytes(),
        "note.json commitment"
    );
    assert_eq!(
        g.public_inputs[0],
        note.poseidon_commitment(),
        "gnark Poseidon gadget disagrees with light-poseidon (Solana sol_poseidon parameters)"
    );
    let mut value = [0u8; 32];
    value[24..].copy_from_slice(&note.value.to_be_bytes());
    assert_eq!(g.public_inputs[1], value, "public value");
}

#[test]
fn key_is_plain_groth16_with_two_public_inputs() {
    let g = load_groth16(FIXTURE);
    assert_eq!(g.key.num_public_inputs(), 2);
    g.key.validate_for_publish().unwrap();
}

#[test]
fn proof_verifies_on_host_path() {
    let g = load_groth16(FIXTURE);
    let vk = VerifyingKey::from_body(g.key.body()).unwrap();
    let proof = Proof::from_bytes(&g.proof.0).unwrap();
    let flat: Vec<u8> = g.public_inputs.concat();
    verify(&vk, &proof, &flat).unwrap();

    // Any other commitment fails.
    let mut wrong = flat.clone();
    wrong[31] ^= 1;
    assert_eq!(verify(&vk, &proof, &wrong), Err(Groth16Error::ProofInvalid));
    // So does any other value: the proof binds the public amount.
    let mut wrong = flat.clone();
    wrong[63] ^= 1;
    assert_eq!(verify(&vk, &proof, &wrong), Err(Groth16Error::ProofInvalid));
    // A non-canonical scalar is rejected before the pairing.
    let mut non_canonical = flat.clone();
    non_canonical[32..].copy_from_slice(&FR_MODULUS);
    assert_eq!(
        verify(&vk, &proof, &non_canonical),
        Err(Groth16Error::NonCanonicalScalar)
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
        "C_mint on SBF: n = {}, {} CUs",
        g.key.num_public_inputs(),
        ok.compute_units_consumed
    );

    let mut wrong_commitment = g.public_inputs.clone();
    wrong_commitment[0][31] ^= 1;
    sbf::assert_custom_error(
        &h.verify(&key_account, &g.proof.0, &wrong_commitment),
        sbf::code::PROOF_INVALID,
    );
    let mut wrong_value = g.public_inputs.clone();
    wrong_value[1][31] ^= 1;
    sbf::assert_custom_error(
        &h.verify(&key_account, &g.proof.0, &wrong_value),
        sbf::code::PROOF_INVALID,
    );

    let mut swapped = g.proof.0;
    swapped[..64].copy_from_slice(&g.proof.0[192..]);
    swapped[192..].copy_from_slice(&g.proof.0[..64]);
    sbf::assert_custom_error(
        &h.verify(&key_account, &swapped, &g.public_inputs),
        sbf::code::PROOF_INVALID,
    );
}
