#!/usr/bin/env bash
# End-to-end demo on a local validator: public token A is shielded into a
# private note (Mint), moved privately (Transfer), and unshielded back to A
# (Burn), with every step checked on-chain through token balances and the
# pool account.
#
# Needs: solana-test-validator, solana-keygen, cargo build-sbf, Go; and the
# artifacts `make verifier-sbf pool-sbf` build (built here if missing).
#
#   ./demo.sh            run everything, stop the validator at the end
#   KEEP=1 ./demo.sh     leave the validator running for a look around
#   DEMO_DIR=...         where keys, proofs and the ledger go (default target/demo)
set -euo pipefail

DIR=$(cd "$(dirname "$0")" && pwd)
WORK=${DEMO_DIR:-$DIR/target/demo}
SBF_ARCH=${SBF_ARCH:-v2}
VERIFIER_SO=$DIR/target/groth16-verifier-program/target/deploy/solana_groth16_program.so
POOL_SO=$DIR/program/target/deploy/private_tx_pool.so
VERIFIER_ID=GrPeAM83MtRfR8NvbW3tMMSBzQ9BsmQrgLjLCQNwZW4P
POOL_ID=3sDoL7Tan84VmueUVRp1NRkhfPRF2z54ccf4J4LMHXdT
RPC=${RPC:-http://127.0.0.1:8899}

step() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
field() { awk -v k="$1" '$1 == k { print $2 }'; }

# ---------------------------------------------------------------- build
step "Building"
[ -f "$VERIFIER_SO" ] || make -C "$DIR" verifier-sbf SBF_ARCH="$SBF_ARCH"
[ -f "$POOL_SO" ] || make -C "$DIR" pool-sbf SBF_ARCH="$SBF_ARCH"
(cd "$DIR/cli" && cargo build --release -q)
mkdir -p "$WORK"
(cd "$DIR/circuits" && go build -o "$WORK/privtx" ./cmd/privtx)
PRIVTX="$WORK/privtx"
CLI="$DIR/cli/target/release/privtx-cli --url $RPC --keypair $WORK/payer.json"

# Always: the development setup takes seconds, and keys made for an older
# version of a circuit are refused by the prover.
step "Groth16 setup (development keys)"
"$PRIVTX" setup -keys "$WORK/keys" 2>&1 | grep -v DBG

# ------------------------------------------------------------ validator
step "Starting a local validator with the verifier and pool programs"
if solana cluster-version -u "$RPC" >/dev/null 2>&1; then
  echo "something already answers on $RPC; stop it or set RPC to a free port" >&2
  exit 1
fi
rm -rf "$WORK/ledger"
solana-test-validator --reset --quiet --ledger "$WORK/ledger" \
  --bpf-program "$VERIFIER_ID" "$VERIFIER_SO" \
  --bpf-program "$POOL_ID" "$POOL_SO" \
  >"$WORK/validator.log" 2>&1 &
VALIDATOR=$!
cleanup() { if [ -z "${KEEP:-}" ]; then kill "$VALIDATOR" 2>/dev/null || true; fi; }
trap cleanup EXIT
for _ in $(seq 1 60); do
  solana cluster-version -u "$RPC" >/dev/null 2>&1 && break
  sleep 1
done
solana cluster-version -u "$RPC"

solana-keygen new -o "$WORK/payer.json" --no-bip39-passphrase --force --silent
$CLI airdrop --sol 100

# ------------------------------------------------------------- registry
step "Registering the three verifying keys with the verifier program"
MINT_VK=$($CLI register-vk "$WORK/keys/mint/vk.bin" | tail -1)
BURN_VK=$($CLI register-vk "$WORK/keys/burn/vk.bin" | tail -1)
TRANSFER_VK=$($CLI register-vk "$WORK/keys/transfer/vk.bin" | tail -1)
echo "mint $MINT_VK"; echo "burn $BURN_VK"; echo "transfer $TRANSFER_VK"

# ----------------------------------------------------------------- keys
step "Keys: Alice, Bob, the custodian's audit key"
"$PRIVTX" keygen -out "$WORK/alice.json" >/dev/null
"$PRIVTX" keygen -out "$WORK/bob.json" >/dev/null
"$PRIVTX" audit-keygen -out "$WORK/audit.json"
ALICE=$("$PRIVTX" address -wallet "$WORK/alice.json")
BOB=$("$PRIVTX" address -wallet "$WORK/bob.json")
echo "alice address $ALICE"
echo "bob   address $BOB"

# ---------------------------------------------------------------- token
step "Public token A: a mint, a depositor account with 10 A, an empty destination"
TOKENS=$($CLI token-setup --amount 10000000)
echo "$TOKENS"
TOKEN_MINT=$(echo "$TOKENS" | field token_mint)
DEPOSITOR=$(echo "$TOKENS" | field depositor)
DESTINATION=$(echo "$TOKENS" | field destination)
DESTINATION_HEX=$($CLI hex "$DESTINATION")

# ----------------------------------------------------------------- pool
step "Creating the pool over A"
POOL_OUT=$($CLI create-pool --token-mint "$TOKEN_MINT" --mint-vk "$MINT_VK" --burn-vk "$BURN_VK" \
  --transfer-vk "$TRANSFER_VK" --audit-key "$WORK/audit.json")
echo "$POOL_OUT"
POOL=$(echo "$POOL_OUT" | field pool)
POOL_HEX=$(echo "$POOL_OUT" | field pool_hex)
$CLI info --pool "$POOL" --token-account "$DEPOSITOR" --token-account "$DESTINATION"

# --------------------------------------------------------------- shield
step "1. Shield: 3 A from the depositor into a private note for Alice"
"$PRIVTX" shield -keys "$WORK/keys" -to "$ALICE" -value 3000000 -audit-pk "$WORK/audit.json" \
  -out "$WORK/shield.json" 2>&1 | grep -v DBG
$CLI shield --pool "$POOL" --source "$DEPOSITOR" "$WORK/shield.json"
$CLI info --pool "$POOL" --token-account "$DEPOSITOR" --token-account "$DESTINATION"

step "Alice scans the pool"
$CLI ledger --pool "$POOL" --out "$WORK/ledger.json"
"$PRIVTX" scan -wallet "$WORK/alice.json" -ledger "$WORK/ledger.json"

# ------------------------------------------------------------- transfer
step "2. Transfer: Alice pays Bob 2 A privately, keeps 1 A as change"
"$PRIVTX" transfer -keys "$WORK/keys" -wallet "$WORK/alice.json" -ledger "$WORK/ledger.json" \
  -pool "$POOL_HEX" -audit-pk "$WORK/audit.json" -spend 0 -to "$BOB" -value 2000000 \
  -out "$WORK/transfer.json" 2>&1 | grep -v DBG
$CLI transfer --pool "$POOL" "$WORK/transfer.json"
$CLI info --pool "$POOL" --token-account "$DEPOSITOR" --token-account "$DESTINATION"

step "Alice and Bob scan the pool"
$CLI ledger --pool "$POOL" --out "$WORK/ledger.json"
echo "alice:"; "$PRIVTX" scan -wallet "$WORK/alice.json" -ledger "$WORK/ledger.json"
echo "bob:";   BOB_SCAN=$("$PRIVTX" scan -wallet "$WORK/bob.json" -ledger "$WORK/ledger.json"); echo "$BOB_SCAN"
BOB_INDEX=$(echo "$BOB_SCAN" | awk '$1 == "index" { print $2; exit }')

# ------------------------------------------------------------- unshield
step "3. Unshield: Bob takes his 2 A out to the destination account"
"$PRIVTX" unshield -keys "$WORK/keys" -wallet "$WORK/bob.json" -ledger "$WORK/ledger.json" \
  -pool "$POOL_HEX" -destination "$DESTINATION_HEX" -index "$BOB_INDEX" \
  -out "$WORK/unshield.json" 2>&1 | grep -v DBG
$CLI unshield --pool "$POOL" "$WORK/unshield.json"
$CLI info --pool "$POOL" --token-account "$DEPOSITOR" --token-account "$DESTINATION"

step "After: Bob's note is spent, Alice still holds her change"
$CLI ledger --pool "$POOL" --out "$WORK/ledger.json"
echo "bob:";   "$PRIVTX" scan -wallet "$WORK/bob.json" -ledger "$WORK/ledger.json"
echo "alice:"; "$PRIVTX" scan -wallet "$WORK/alice.json" -ledger "$WORK/ledger.json"

step "Done. Validator log: $WORK/validator.log; proofs and keys under $WORK"
[ -n "${KEEP:-}" ] && echo "validator left running (pid $VALIDATOR), RPC $RPC"
