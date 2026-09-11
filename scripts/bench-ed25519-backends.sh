#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage:
  scripts/bench-ed25519-backends.sh [criterion-filter-or-args...]

Runs solana-ed25519 Criterion benchmarks twice on an AVX-512 IFMA-capable host:

  1. AVX2 curve-arithmetic path:
     - features: alloc,rand_core,digest
     - rustflags: -C target-cpu=native -C target-feature=+avx2,-avx512f,-avx512dq,-avx512ifma

  2. AVX-512 Ed25519 batch-verifier path:
     - features: alloc,rand_core,digest,avx512
     - rustflags: -C target-cpu=native -C target-feature=+avx2,+avx512f,+avx512dq,+avx512ifma

Arguments after the script name are passed to Criterion. If omitted, the script
defaults to the "Batch Verification" benchmark group.

Environment overrides:
  AVX2_RUSTFLAGS       Rust flags for the AVX2 run
  AVX512_RUSTFLAGS     Rust flags for the AVX-512 run
  AVX2_FEATURES        Cargo features for the AVX2 run
  AVX512_FEATURES      Cargo features for the AVX-512 run
  CARGO                Cargo binary to use

Examples:
  scripts/bench-ed25519-backends.sh
  scripts/bench-ed25519-backends.sh "Batch Verification/AVX512"
  AVX512_RUSTFLAGS="-C target-cpu=native" scripts/bench-ed25519-backends.sh
USAGE
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

cargo_bin="${CARGO:-cargo}"

host_arch="$(uname -m)"
case "$host_arch" in
  x86_64|amd64) ;;
  *)
    echo "error: AVX2/AVX-512 benchmarks require x86_64; found ${host_arch}" >&2
    exit 1
    ;;
esac

cpu_flags() {
  case "$(uname -s)" in
    Linux)
      tr '[:upper:]' '[:lower:]' < /proc/cpuinfo
      ;;
    Darwin)
      sysctl -a machdep.cpu.features machdep.cpu.leaf7_features 2>/dev/null \
        | tr '[:upper:]' '[:lower:]'
      ;;
    *)
      echo ""
      ;;
  esac
}

flags="$(cpu_flags)"
require_flag() {
  local flag="$1"
  if ! grep -Eq "(^|[^a-z0-9_])${flag}([^a-z0-9_]|$)" <<<"$flags"; then
    echo "error: CPU/OS feature '${flag}' was not detected" >&2
    exit 1
  fi
}

require_flag avx2
require_flag avx512f
require_flag avx512dq
require_flag avx512ifma

criterion_args=("$@")
if [[ ${#criterion_args[@]} -eq 0 ]]; then
  criterion_args=("Batch Verification")
fi

avx2_features="${AVX2_FEATURES:-alloc,rand_core,digest}"
avx512_features="${AVX512_FEATURES:-alloc,rand_core,digest,avx512}"
avx2_rustflags="${AVX2_RUSTFLAGS:--C target-cpu=native -C target-feature=+avx2,-avx512f,-avx512dq,-avx512ifma}"
avx512_rustflags="${AVX512_RUSTFLAGS:--C target-cpu=native -C target-feature=+avx2,+avx512f,+avx512dq,+avx512ifma}"

run_bench() {
  local label="$1"
  local features="$2"
  local rustflags="$3"

  echo
  echo "== ${label} =="
  echo "features: ${features}"
  echo "RUSTFLAGS: ${rustflags}"
  echo

  RUSTFLAGS="${rustflags}" \
    "${cargo_bin}" bench \
      -p solana-ed25519 \
      --bench bench \
      --features "${features}" \
      -- \
      --save-baseline "${label}" \
      "${criterion_args[@]}"
}

run_bench avx2 "${avx2_features}" "${avx2_rustflags}"
run_bench avx512 "${avx512_features}" "${avx512_rustflags}"

cat <<'DONE'

Benchmarks complete.
Criterion output is under target/criterion/.
The two runs were saved as baselines named "avx2" and "avx512".
DONE
