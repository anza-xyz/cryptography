# Private transactions: gnark circuits, fixtures, and end-to-end verification
# against the Solana Groth16 verifier program.

VERIFIER_REPO = https://github.com/solana-program/groth16-verifier-program
# Keep in sync with the `rev` of the verifier git dependencies in e2e/Cargo.toml.
VERIFIER_REV  = 8bd06b4fb07f636c1872993a99f1a296b23b69fa
VERIFIER_DIR  = $(CURDIR)/target/groth16-verifier-program
SBF_OUT_DIR   = $(VERIFIER_DIR)/target/deploy
# solana-cli 4.2+ builds SBF v3; 3.x stops at v2.
SBF_ARCH     ?= v2

.PHONY: all lint test test-go test-e2e fixtures verifier-sbf clean

all: lint test

# Formatting and lints for both halves. The e2e crate is its own workspace, so
# the repository-level `cargo fmt` / `cargo clippy` do not reach it.
lint:
	cd circuits && test -z "$$(gofmt -l .)" && go vet ./...
	cd e2e && cargo fmt --all -- --check && cargo clippy --all-targets -- -D warnings

# Go unit tests: Poseidon known answers, gadget vs native, circuit prove/verify.
test-go:
	cd circuits && go test ./...

# Rust end to end. The SBF test runs only if the verifier artifact exists;
# `make verifier-sbf` first for the full run.
test-e2e:
	cd e2e && SBF_OUT_DIR=$(SBF_OUT_DIR) cargo test --release

test: test-go test-e2e

# Regenerate fixtures/smoke/*. The trusted setup is random, so the bytes change
# on every run; the witness itself is fixed.
fixtures:
	cd circuits && go run ./cmd/privtx smoke-fixture -out ../fixtures/smoke

# Clone the verifier program at the pinned revision and build its SBF artifact.
verifier-sbf:
	@if [ ! -d "$(VERIFIER_DIR)/.git" ]; then \
		git clone -q $(VERIFIER_REPO) "$(VERIFIER_DIR)"; \
	fi
	cd "$(VERIFIER_DIR)" && git fetch -q origin && git checkout -q $(VERIFIER_REV)
	cd "$(VERIFIER_DIR)" && cargo build-sbf --arch $(SBF_ARCH) --manifest-path program/Cargo.toml -- --locked

clean:
	rm -rf target e2e/target
