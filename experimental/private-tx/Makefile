# Private transactions: gnark circuits, fixtures, the pool program, and
# end-to-end verification against the Solana Groth16 verifier program.

VERIFIER_REPO = https://github.com/solana-program/groth16-verifier-program
# Keep in sync with the `rev` of the verifier git dependencies in e2e/Cargo.toml.
VERIFIER_REV  = 8bd06b4fb07f636c1872993a99f1a296b23b69fa
VERIFIER_DIR  = $(CURDIR)/target/groth16-verifier-program
SBF_OUT_DIR   = $(VERIFIER_DIR)/target/deploy
POOL_SBF_OUT_DIR = $(CURDIR)/program/target/deploy
# solana-cli 4.2+ (cargo-build-sbf 4.1, platform-tools v1.54) builds SBF v3,
# which is what CI uses. Older toolchains stop at v2: `make SBF_ARCH=v2`.
SBF_ARCH     ?= v3

.PHONY: all lint test test-go test-e2e fixtures verifier-sbf pool-sbf clean

all: lint test

# Formatting and lints for all three. The Rust crates are their own
# workspaces, so the repository-level `cargo fmt` / `cargo clippy` do not
# reach them.
lint:
	cd circuits && test -z "$$(gofmt -l .)" && go vet ./...
	cd program && cargo fmt --all -- --check && cargo clippy --all-targets --features instruction -- -D warnings
	cd e2e && cargo fmt --all -- --check && cargo clippy --all-targets -- -D warnings

# Go unit tests: Poseidon known answers, gadget vs native, keys and notes, Merkle tree, encryption, circuits, client lifecycle.
# The burn fixture is an owner unshield; `-forced` would make it a forfeiture.
test-go:
	cd circuits && go test ./...

# Rust end to end. The SBF tests run only if the artifacts exist: `make
# verifier-sbf` for the proof tests, plus `make pool-sbf` for the pool test.
test-e2e:
	cd e2e && SBF_OUT_DIR=$(SBF_OUT_DIR) POOL_SBF_OUT_DIR=$(POOL_SBF_OUT_DIR) cargo test --release

test: test-go test-e2e

# Regenerate fixtures/*. The trusted setup is random, so the bytes change on
# every run; the witnesses themselves are fixed.
fixtures:
	cd circuits && go run ./cmd/privtx smoke-fixture -out ../fixtures/smoke
	cd circuits && go run ./cmd/privtx mint-fixture -out ../fixtures/mint
	cd circuits && go run ./cmd/privtx burn-fixture -out ../fixtures/burn
	cd circuits && go run ./cmd/privtx pool-fixture -out ../fixtures/pool

# Clone the verifier program at the pinned revision and build its SBF artifact.
verifier-sbf:
	@if [ ! -d "$(VERIFIER_DIR)/.git" ]; then \
		git clone -q $(VERIFIER_REPO) "$(VERIFIER_DIR)"; \
	fi
	cd "$(VERIFIER_DIR)" && git fetch -q origin && git checkout -q $(VERIFIER_REV)
	cd "$(VERIFIER_DIR)" && cargo build-sbf --arch $(SBF_ARCH) --manifest-path program/Cargo.toml -- --locked

# Build the pool program's SBF artifact.
pool-sbf:
	cd program && cargo build-sbf --arch $(SBF_ARCH) -- --locked

clean:
	rm -rf target e2e/target program/target
