//! Agreement with upstream dalek on the same inputs used by the syscall benchmarks.
#[path = "support/syscall_ops.rs"]
mod support;
use support::{Corpus, Encoding, ours, upstream};

fn check_validation(
    corpus: &Corpus,
    validate: fn(&Encoding) -> bool,
    reference: fn(&Encoding) -> bool,
) {
    for (case, inputs) in &corpus.validation {
        for (index, input) in inputs.iter().enumerate() {
            assert_eq!(validate(input), reference(input), "{case}[{index}]");
        }
    }
}

fn check_group_op(
    corpus: &Corpus,
    apply: fn(&Encoding, &Encoding) -> Option<Encoding>,
    reference: fn(&Encoding, &Encoding) -> Option<Encoding>,
) {
    for (case, inputs) in &corpus.pairs {
        for (index, (a, b)) in inputs.iter().enumerate() {
            assert_eq!(apply(a, b), reference(a, b), "{case}[{index}]");
        }
    }
}

#[test]
fn edwards_validation_matches_dalek() {
    let corpus = Corpus::edwards();
    check_validation(&corpus, ours::edwards_validate, upstream::edwards_validate);
    check_validation(
        &corpus,
        ours::edwards_validate_decompress,
        upstream::edwards_validate,
    );
}

#[test]
fn edwards_add_matches_dalek() {
    let corpus = Corpus::edwards();
    check_group_op(&corpus, ours::edwards_add, upstream::edwards_add);
    check_group_op(&corpus, ours::edwards_add_decompress, upstream::edwards_add);
}

#[test]
fn edwards_sub_matches_dalek() {
    let corpus = Corpus::edwards();
    check_group_op(&corpus, ours::edwards_sub, upstream::edwards_sub);
    check_group_op(&corpus, ours::edwards_sub_decompress, upstream::edwards_sub);
}

#[test]
fn ristretto_validation_matches_dalek() {
    let corpus = Corpus::ristretto();
    check_validation(
        &corpus,
        ours::ristretto_validate,
        upstream::ristretto_validate,
    );
}

#[test]
fn ristretto_add_matches_dalek() {
    let corpus = Corpus::ristretto();
    check_group_op(&corpus, ours::ristretto_add, upstream::ristretto_add);
    check_group_op(
        &corpus,
        ours::ristretto_add_decompress,
        upstream::ristretto_add,
    );
}

#[test]
fn ristretto_sub_matches_dalek() {
    let corpus = Corpus::ristretto();
    check_group_op(&corpus, ours::ristretto_sub, upstream::ristretto_sub);
    check_group_op(
        &corpus,
        ours::ristretto_sub_decompress,
        upstream::ristretto_sub,
    );
}

#[test]
fn ristretto_invalid_corpus_reaches_square_root_checks() {
    let corpus = Corpus::ristretto();
    let (_, inputs) = corpus
        .validation
        .iter()
        .find(|(case, _)| *case == "invalid")
        .unwrap();
    assert_eq!(inputs.len(), 64);
    let modulus: [u8; 32] =
        hex::decode("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f")
            .unwrap()
            .try_into()
            .unwrap();
    for input in inputs {
        assert_eq!(input[0] & 1, 0, "s must be nonnegative");
        assert!(
            input.iter().rev().lt(modulus.iter().rev()),
            "s must be canonical"
        );
        assert!(!upstream::ristretto_validate(input));
        assert!(!ours::ristretto_validate(input));
    }
}
