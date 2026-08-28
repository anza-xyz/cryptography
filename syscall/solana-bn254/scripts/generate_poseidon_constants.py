#!/usr/bin/env python3
"""Generate src/poseidon/constants.rs for the solana-bn254 crate.

Input:  light-poseidon's light-poseidon/src/parameters/bn254_x5.rs, which holds
        the unoptimized round constants (`ark`) and MDS matrix (`mds`) for each
        state width, as produced by the Poseidon authors' generate_parameters_grain.sage.

Output: Montgomery-form constant tables for the optimized permutation:
        full-round constants (ark, verbatim), one folded constant per partial
        round, the pre-sparse matrix, and one sparse matrix per partial round.

The script refuses to emit anything unless the optimized permutation is proven
equal to light-poseidon's unoptimized permutation at every width, and unless the
published circom test vectors for T = 2 and T = 3 are reproduced.

Usage: generate_poseidon_constants.py <bn254_x5.rs> <out.rs> [widths...]
"""

import re
import random
import sys

R = 0x30644E72E131A029B85045B68181585D2833E84879B9709143E1F593F0000001
MONT = 1 << 256
PARTIAL_ROUNDS = {
    2: 56,
    3: 57,
    4: 56,
    5: 60,
    6: 60,
    7: 63,
    8: 64,
    9: 63,
    10: 60,
    11: 66,
    12: 60,
    13: 65,
}
# github.com/iden3/circomlibjs test vectors
CIRCOM_KAT = {
    2: 18586133768512220936620570745912940619677854269274689475585506675881198879027,
    3: 7853200120776062878684798364095072458815029376092732009249414926327459813530,
}

# --------------------------------------------------------------------------
# field / matrix helpers
# --------------------------------------------------------------------------


def inverse(a):
    return pow(a, R - 2, R)


def matmul(A, B):
    return [
        [sum(A[i][k] * B[k][j] for k in range(len(B))) % R for j in range(len(B[0]))]
        for i in range(len(A))
    ]


def matvec(A, v):
    return [sum(A[i][j] * v[j] for j in range(len(v))) % R for i in range(len(A))]


def mat_inverse(M):
    n = len(M)
    A = [row[:] + [1 if i == j else 0 for j in range(n)] for i, row in enumerate(M)]
    for c in range(n):
        piv = next(r for r in range(c, n) if A[r][c] % R)
        A[c], A[piv] = A[piv], A[c]
        ip = inverse(A[c][c])
        A[c] = [v * ip % R for v in A[c]]
        for r in range(n):
            if r != c and A[r][c]:
                f = A[r][c]
                A[r] = [(A[r][k] - f * A[c][k]) % R for k in range(2 * n)]
    return [row[n:] for row in A]


# --------------------------------------------------------------------------
# parsing
# --------------------------------------------------------------------------

BIGINT = re.compile(
    r"BigInteger256::new\(\[\s*(\d+),\s*(\d+),\s*(\d+),\s*(\d+),?\s*\]\)", re.S
)


def parse(path):
    lines = open(path).read().split("\n")
    starts = {}
    for i, line in enumerate(lines):
        m = re.match(r"\s*\} else if (\d+) == t \{", line)
        if m:
            starts[int(m.group(1))] = i

    def to_int(g):
        return sum(int(g[i]) << (64 * i) for i in range(4))

    out = {}
    for t in sorted(starts):
        end = starts[t + 1] if (t + 1) in starts else len(lines)
        block = "\n".join(lines[starts[t] : end])
        split = block.index("let mds = vec![")
        ark = [
            to_int(m.groups())
            for m in BIGINT.finditer(block[block.index("let ark = vec![") : split])
        ]
        flat = [to_int(m.groups()) for m in BIGINT.finditer(block[split:])]
        partial = PARTIAL_ROUNDS[t]
        assert len(ark) == t * (8 + partial), f"t={t}: {len(ark)} constants"
        assert len(flat) == t * t, f"t={t}: {len(flat)} mds entries"
        assert all(v < R for v in ark + flat), f"t={t}: value >= modulus"
        out[t] = {
            "ark": [ark[r * t : (r + 1) * t] for r in range(8 + partial)],
            "mds": [flat[i * t : (i + 1) * t] for i in range(t)],
            "partial": partial,
        }
    return out


# --------------------------------------------------------------------------
# derivation
# --------------------------------------------------------------------------


def factor(N):
    """Split N = Sp @ M_prime.

    M_prime is identity on row/column 0 and holds N's lower-right block, so it
    commutes with a partial-round S-box and can be absorbed into the preceding
    linear layer. Sp is sparse: one full row, one full column, identity elsewhere.
    """
    t = len(N)
    hat = [row[1:] for row in N[1:]]
    hat_inv = mat_inverse(hat)
    m_prime = [[1] + [0] * (t - 1)] + [[0] + row[:] for row in hat]
    top = [
        sum(N[0][1 + k] * hat_inv[k][j] for k in range(t - 1)) % R for j in range(t - 1)
    ]
    sp = [[1 if i == j else 0 for j in range(t)] for i in range(t)]
    sp[0] = [N[0][0]] + top
    for i in range(1, t):
        sp[i][0] = N[i][0]
    assert matmul(sp, m_prime) == [
        [v % R for v in row] for row in N
    ], "factorization failed"
    return sp, m_prime


def derive(params):
    t = len(params["mds"])
    ark, mds, partial = params["ark"], params["mds"], params["partial"]

    # Fold each partial round's constant vector down to its state[0] component.
    # The remaining components commute with the S-box, so they are pushed
    # forward through the MDS matrix and accumulated.
    folded, carry = [], [0] * t
    for p in range(partial):
        v = [(ark[4 + p][i] + carry[i]) % R for i in range(t)]
        folded.append(v[0])
        carry = matvec(mds, [0] + v[1:])

    second = [ark[4 + partial + r][:] for r in range(4)]
    second[0] = [(second[0][i] + carry[i]) % R for i in range(t)]

    # Peel one sparse factor off per partial round, absorbing each commuting
    # factor into the linear layer to its left. What is left over is the dense
    # matrix applied by the last full round of the first half.
    sparse = [None] * partial
    acc = [row[:] for row in mds]
    for p in reversed(range(partial)):
        sparse[p], m_prime = factor(acc)
        acc = matmul(m_prime, mds)

    return {
        "first": ark[:4],
        "partial_constants": folded,
        "second": second,
        "pre_sparse": acc,
        "sparse": sparse,
    }


# --------------------------------------------------------------------------
# verification
# --------------------------------------------------------------------------


def permute_reference(inputs, params):
    """light-poseidon's permutation: add full-width constants, S-box, MDS."""
    t, mds, partial = len(params["mds"]), params["mds"], params["partial"]
    x = [0] + list(inputs)
    for r in range(8 + partial):
        x = [(x[i] + params["ark"][r][i]) % R for i in range(t)]
        x = (
            [pow(v, 5, R) for v in x]
            if (r < 4 or r >= 4 + partial)
            else [pow(x[0], 5, R)] + x[1:]
        )
        x = matvec(mds, x)
    return x


def permute_optimized(inputs, params, k):
    t, mds, partial = len(params["mds"]), params["mds"], params["partial"]
    x = [0] + list(inputs)
    for r in range(4):
        x = [(x[i] + k["first"][r][i]) % R for i in range(t)]
        x = [pow(v, 5, R) for v in x]
        x = matvec(k["pre_sparse"] if r == 3 else mds, x)
    for p in range(partial):
        x[0] = pow((x[0] + k["partial_constants"][p]) % R, 5, R)
        x = matvec(k["sparse"][p], x)
    for r in range(4):
        x = [(x[i] + k["second"][r][i]) % R for i in range(t)]
        x = [pow(v, 5, R) for v in x]
        x = matvec(mds, x)
    return x


def verify(t, params, k, trials=8):
    rng = random.Random(0x5EED ^ t)
    for _ in range(trials):
        ins = [rng.randrange(R) for _ in range(t - 1)]
        assert permute_optimized(ins, params, k) == permute_reference(
            ins, params
        ), f"t={t}: optimized permutation differs from light-poseidon"
    ins = [0] * (t - 1)
    assert permute_optimized(ins, params, k) == permute_reference(
        ins, params
    ), f"t={t}: all-zero input mismatch"
    if t in CIRCOM_KAT:
        got = permute_optimized(list(range(1, t)), params, k)[0]
        assert got == CIRCOM_KAT[t], f"t={t}: circom test vector mismatch"


# --------------------------------------------------------------------------
# emission
# --------------------------------------------------------------------------

HEADER = """// GENERATED FILE -- do not edit by hand.
//
// Produced by `scripts/generate_poseidon_constants.py` from light-poseidon's
// `light-poseidon/src/parameters/bn254_x5.rs`, whose `ark` and `mds` tables come
// from the Poseidon authors' `generate_parameters_grain.sage`.

//! Default circom-compatible Poseidon parameters over BN254 Fr (x^5 S-box) for
//! the state widths the `sol_poseidon` syscall supports (T = 2..=13).
//!
//! All values are in Montgomery form (R = 2^256).
//!
//! # Provenance
//! Full-round constants are light-poseidon's `ark` vectors verbatim, except the
//! first vector of the second half, which absorbs the carry left over from
//! folding the partial-round constants. Each partial round keeps only the
//! state[0] component of its constant; the other components commute with the
//! S-box and are pushed forward through the MDS matrix. `pre_sparse_matrix` and
//! `sparse_matrices` factor the MDS matrix so partial rounds cost O(T) rather
//! than O(T^2); `pre_sparse_matrix` replaces `mds_matrix` in the final full
//! round of the first half.
//!
//! The generator proves this permutation equal to light-poseidon's unoptimized
//! permutation at every width, and checks the published circom test vectors for
//! T = 2 and T = 3, before writing this file.

use crate::backend::U256;
use crate::poseidon::{PoseidonConstants, SparseMatrix};
"""


def mont(v):
    m = (v * MONT) % R
    return "U256::new([0x%016x, 0x%016x, 0x%016x, 0x%016x])" % tuple(
        (m >> (64 * i)) & 0xFFFFFFFFFFFFFFFF for i in range(4)
    )


def emit(t, params, k):
    partial = params["partial"]
    n = 8 * t + partial
    o = [
        f"\n// ---------------- T = {t} ({t - 1} inputs, {partial} partial rounds) "
        f"----------------\n\n"
    ]

    def rows(vals, indent):
        return "".join(f"{indent}{mont(v)},\n" for v in vals)

    o.append(f"static ROUND_CONSTANTS_{t}: [U256; {n}] = [\n")
    o.append(f"    // first half: 4 full rounds (light-poseidon ark[0..{4 * t}])\n")
    for r in range(4):
        o.append(rows(k["first"][r], "    "))
    o.append(f"    // {partial} partial rounds: one folded constant each\n")
    o.append(rows(k["partial_constants"], "    "))
    o.append(
        "    // second half: 4 full rounds (first vector absorbs the folding carry)\n"
    )
    for r in range(4):
        o.append(rows(k["second"][r], "    "))
    o.append("];\n\n")

    for name, mat in (("MDS", params["mds"]), ("PRE_SPARSE", k["pre_sparse"])):
        o.append(f"static {name}_{t}: [[U256; {t}]; {t}] = [\n")
        for row in mat:
            o.append("    [\n" + rows(row, "        ") + "    ],\n")
        o.append("];\n\n")

    o.append(f"static SPARSE_{t}: [SparseMatrix<{t}>; {partial}] = [\n")
    for sp in k["sparse"]:
        # col[0] is never read by apply_sparse_matrix; row[0] already holds Sp[0][0].
        col = [0] + [sp[i][0] for i in range(1, t)]
        o.append(
            "    SparseMatrix {\n        row: [\n"
            + rows(sp[0], "            ")
            + "        ],\n        col: [\n"
            + rows(col, "            ")
            + "        ],\n    },\n"
        )
    o.append("];\n\n")

    o.append(
        f"/// Circom-compatible BN254 x^5 Poseidon parameters for state width {t}.\n"
    )
    o.append(
        f"pub static BN254_X5_T{t}: PoseidonConstants<{t}> = PoseidonConstants {{\n"
        f"    full_rounds: 8,\n"
        f"    partial_rounds: {partial},\n"
        f"    round_constants: &ROUND_CONSTANTS_{t},\n"
        f"    mds_matrix: &MDS_{t},\n"
        f"    pre_sparse_matrix: &PRE_SPARSE_{t},\n"
        f"    sparse_matrices: &SPARSE_{t},\n}};\n"
    )
    return "".join(o)


def main():
    if len(sys.argv) < 3:
        sys.exit(__doc__)
    src, dst = sys.argv[1], sys.argv[2]
    widths = [int(a) for a in sys.argv[3:]] or None

    parsed = parse(src)
    if widths:
        parsed = {t: parsed[t] for t in widths}

    chunks = [HEADER]
    for t in sorted(parsed):
        k = derive(parsed[t])
        verify(t, parsed[t], k)
        print(
            f"  t={t:<3} verified against light-poseidon"
            + ("  + circom test vector" if t in CIRCOM_KAT else "")
        )
        chunks.append(emit(t, parsed[t], k))

    open(dst, "w").write("".join(chunks))
    print(f"wrote {dst}")


if __name__ == "__main__":
    main()
