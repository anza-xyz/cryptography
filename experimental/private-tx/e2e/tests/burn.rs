//! C_burn end to end: the fixture's root is the Solana Poseidon Merkle root
//! of the published leaves, the nullifier is the Solana Poseidon of the
//! note's (owner_pk, rho), the `forced` flag is what the fixture says, the
//! proof verifies through the verifier's host path, and, when the SBF
//! artifact is available, through the verifier program itself.

mod sbf;

use {
    private_tx_e2e::{bytes_from_hex, load_groth16, u64_to_bytes, BurnFixture},
    solana_groth16_verify::{constants::FR_MODULUS, verify, Groth16Error, Proof, VerifyingKey},
};

const FIXTURE: &str = "burn";

#[test]
fn public_inputs_are_root_nullifier_value_and_forced() {
    let g = load_groth16(FIXTURE);
    let f = BurnFixture::load(FIXTURE);
    assert_eq!(g.public_inputs.len(), 4, "C_burn has four public inputs");

    let note = &f.note;
    assert_eq!(
        f.leaves[f.index as usize], note.commitment,
        "burned leaf is the note's commitment"
    );
    assert_eq!(
        note.commitment_bytes(),
        note.poseidon_commitment(),
        "gnark Poseidon gadget disagrees with light-poseidon on the commitment"
    );

    assert_eq!(
        g.public_inputs[0],
        bytes_from_hex(&f.root),
        "burn.json root"
    );
    assert_eq!(
        g.public_inputs[0],
        f.poseidon_root(),
        "gnark Merkle gadget disagrees with a light-poseidon tree over the leaves"
    );
    assert_eq!(
        g.public_inputs[1],
        bytes_from_hex(&f.nullifier),
        "burn.json nullifier"
    );
    assert_eq!(
        g.public_inputs[1],
        note.poseidon_nullifier(),
        "gnark nullifier gadget disagrees with light-poseidon"
    );
    assert_eq!(g.public_inputs[2], u64_to_bytes(note.value), "public value");
    assert_eq!(
        g.public_inputs[3],
        u64_to_bytes(f.forced as u64),
        "forced flag"
    );
}

#[test]
fn key_is_plain_groth16_with_four_public_inputs() {
    let g = load_groth16(FIXTURE);
    assert_eq!(g.key.num_public_inputs(), 4);
    g.key.validate_for_publish().unwrap();
}

#[test]
fn proof_verifies_on_host_path() {
    let g = load_groth16(FIXTURE);
    let vk = VerifyingKey::from_body(g.key.body()).unwrap();
    let proof = Proof::from_bytes(&g.proof.0).unwrap();
    let flat: Vec<u8> = g.public_inputs.concat();
    verify(&vk, &proof, &flat).unwrap();

    // Any other root (e.g. a tree the note is not in) fails.
    let mut wrong = flat.clone();
    wrong[31] ^= 1;
    assert_eq!(verify(&vk, &proof, &wrong), Err(Groth16Error::ProofInvalid));
    // So does any other nullifier: the proof binds the one the program records.
    let mut wrong = flat.clone();
    wrong[63] ^= 1;
    assert_eq!(verify(&vk, &proof, &wrong), Err(Groth16Error::ProofInvalid));
    // And any other value.
    let mut wrong = flat.clone();
    wrong[95] ^= 1;
    assert_eq!(verify(&vk, &proof, &wrong), Err(Groth16Error::ProofInvalid));
    // Flipping the flag turns an unshield into a forfeiture (or back): the
    // proof binds which authorization the program must check.
    let mut wrong = flat.clone();
    wrong[127] ^= 1;
    assert_eq!(verify(&vk, &proof, &wrong), Err(Groth16Error::ProofInvalid));
    // A non-canonical scalar is rejected before the pairing.
    let mut non_canonical = flat.clone();
    non_canonical[96..].copy_from_slice(&FR_MODULUS);
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
        "C_burn on SBF: n = {}, {} CUs",
        g.key.num_public_inputs(),
        ok.compute_units_consumed
    );

    for (i, what) in ["root", "nullifier", "value", "forced"].iter().enumerate() {
        let mut wrong = g.public_inputs.clone();
        wrong[i][31] ^= 1;
        let r = h.verify(&key_account, &g.proof.0, &wrong);
        sbf::assert_custom_error(&r, sbf::code::PROOF_INVALID);
        assert!(r.program_result.is_err(), "wrong {what} accepted");
    }
}
