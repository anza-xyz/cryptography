//! C_mint end to end: the fixture's commitment is the Solana Poseidon of the
//! note, the audit hash is the Solana Poseidon of the audit ciphertext and
//! the recipient blob's hash, the proof verifies through the verifier's host
//! path, and, when the SBF artifact is available, through the verifier
//! program itself.

mod sbf;

use {
    private_tx_e2e::{bytes_from_hex, encrypt, hex_bytes, load_groth16, u64_to_bytes, MintFixture},
    solana_groth16_verify::{constants::FR_MODULUS, verify, Groth16Error, Proof, VerifyingKey},
};

const FIXTURE: &str = "mint";

#[test]
fn public_inputs_are_commitment_value_and_audit_hash() {
    let g = load_groth16(FIXTURE);
    let f = MintFixture::load(FIXTURE);
    let note = &f.note;
    assert_eq!(g.public_inputs.len(), 3, "C_mint has three public inputs");
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
    assert_eq!(g.public_inputs[1], u64_to_bytes(note.value), "public value");

    let enc_blob = hex_bytes(&f.enc_blob);
    let audit_blob = hex_bytes(&f.audit_blob);
    assert_eq!(enc_blob.len(), encrypt::RECIPIENT_BLOB_LEN);
    assert_eq!(audit_blob.len(), 64 + 32 * encrypt::AUDIT_ELEMENTS);
    let enc_hash = encrypt::enc_hash(&enc_blob);
    assert_eq!(enc_hash, bytes_from_hex(&f.enc_hash), "note.json enc_hash");
    let audit_hash = encrypt::audit_hash(&f.audit_pk(), &audit_blob, &[enc_hash]);
    assert_eq!(
        audit_hash,
        bytes_from_hex(&f.audit_hash),
        "note.json audit_hash"
    );
    assert_eq!(
        g.public_inputs[2], audit_hash,
        "gnark audit gadget disagrees with light-poseidon over the audit blob"
    );
}

#[test]
fn key_is_plain_groth16_with_three_public_inputs() {
    let g = load_groth16(FIXTURE);
    assert_eq!(g.key.num_public_inputs(), 3);
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
    // And any other audit hash: the ciphertexts are what the proof says.
    let mut wrong = flat.clone();
    wrong[95] ^= 1;
    assert_eq!(verify(&vk, &proof, &wrong), Err(Groth16Error::ProofInvalid));
    // A non-canonical scalar is rejected before the pairing.
    let mut non_canonical = flat.clone();
    non_canonical[32..64].copy_from_slice(&FR_MODULUS);
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
