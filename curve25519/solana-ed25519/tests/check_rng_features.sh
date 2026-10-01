#!/usr/bin/env bash
set -euo pipefail

crate_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
host_target="$(rustc -vV | sed -n 's/^host: //p')"

check_features() {
    local features="$1"
    local target="$2"
    local forbidden_packages="$3"
    local dependency_tree

    cargo check --manifest-path "$crate_dir/Cargo.toml" --locked --lib \
        --no-default-features --features "$features" --target "$target"

    # Development dependencies must not mask dependencies of the library itself.
    dependency_tree="$(cargo tree --manifest-path "$crate_dir/Cargo.toml" --locked \
        --no-default-features --features "$features" --target "$target" \
        --edges normal,build --prefix none --color never)"
    if grep -Eq "^(${forbidden_packages}) v" <<< "$dependency_tree"; then
        printf 'Unexpected randomness dependency with features %s on %s:\n%s\n' \
            "$features" "$target" "$dependency_tree" >&2
        return 1
    fi
}

check_features default "$host_target" rand
check_features getrandom "$host_target" 'rand|rand_core'

for target in "$host_target" wasm32-unknown-unknown; do
    check_features alloc,precomputed-tables,zeroize,digest,serde "$target" 'rand|rand_core|getrandom'
    check_features rand_core "$target" 'rand|getrandom'
    check_features group "$target" 'rand|getrandom'
done
