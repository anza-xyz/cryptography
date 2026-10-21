// Package merkle is the note commitment tree: a fixed-depth binary Merkle
// tree over BN254 Fr with Poseidon (width 3) nodes, in native form for
// witness generation and as a gadget for membership proofs.
//
//	leaf          = the note commitment, as is
//	node(l, r)    = Poseidon(l, r)
//	empty leaf    = 0
//	empty subtree = Poseidon(empty, empty) at each height
//
// Leaves are appended left to right; the leaf index is the path from the
// root with bit i selecting the right child at height i. The pool program
// keeps the same tree on-chain and can recompute any node with one
// sol_poseidon syscall.
package merkle

import (
	"fmt"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/frontend"

	"github.com/anza-xyz/cryptography/experimental/private-tx/circuits/poseidon"
)

// Depth is the tree height, so a pool holds up to 2^Depth notes. Provisional:
// the spec fixes it (together with the root history window).
const Depth = 32

// Path is a membership witness: the leaf index and the sibling at each
// height, leaf level first.
type Path struct {
	Index    uint64
	Siblings [Depth]fr.Element
}

var zeros = func() [Depth + 1]fr.Element {
	var z [Depth + 1]fr.Element // z[0] = 0, the empty leaf
	for i := 0; i < Depth; i++ {
		z[i+1] = poseidon.MustHash(z[i], z[i])
	}
	return z
}()

// EmptyRoot is the root of a tree with no leaves.
func EmptyRoot() fr.Element { return zeros[Depth] }

// Tree is an in-memory append-only tree.
type Tree struct {
	leaves []fr.Element
}

// Append adds a leaf and returns its index.
func (t *Tree) Append(leaf fr.Element) (uint64, error) {
	if uint64(len(t.leaves)) >= 1<<Depth {
		return 0, fmt.Errorf("merkle: tree is full (%d leaves)", len(t.leaves))
	}
	t.leaves = append(t.leaves, leaf)
	return uint64(len(t.leaves) - 1), nil
}

// Len is the number of leaves.
func (t *Tree) Len() int { return len(t.leaves) }

// Leaves returns the leaves in insertion order.
func (t *Tree) Leaves() []fr.Element { return append([]fr.Element(nil), t.leaves...) }

// levels returns every level of the occupied part of the tree, leaves first;
// positions past each level's length are the empty subtree of that height.
func (t *Tree) levels() [][]fr.Element {
	levels := make([][]fr.Element, Depth+1)
	levels[0] = t.leaves
	for h := 0; h < Depth; h++ {
		cur := levels[h]
		next := make([]fr.Element, (len(cur)+1)/2)
		for i := range next {
			left := cur[2*i]
			right := zeros[h]
			if 2*i+1 < len(cur) {
				right = cur[2*i+1]
			}
			next[i] = poseidon.MustHash(left, right)
		}
		levels[h+1] = next
	}
	return levels
}

// Root returns the current root.
func (t *Tree) Root() fr.Element {
	top := t.levels()[Depth]
	if len(top) == 0 {
		return zeros[Depth]
	}
	return top[0]
}

// Path returns the membership witness of leaf index.
func (t *Tree) Path(index uint64) (Path, error) {
	if index >= uint64(len(t.leaves)) {
		return Path{}, fmt.Errorf("merkle: index %d out of range (%d leaves)", index, len(t.leaves))
	}
	levels := t.levels()
	p := Path{Index: index}
	for h := 0; h < Depth; h++ {
		sib := (index >> h) ^ 1
		p.Siblings[h] = zeros[h]
		if sib < uint64(len(levels[h])) {
			p.Siblings[h] = levels[h][sib]
		}
	}
	return p, nil
}

// Root recomputes the root from a leaf and its path, natively.
func (p *Path) Root(leaf fr.Element) fr.Element {
	cur := leaf
	for h := 0; h < Depth; h++ {
		if (p.Index>>h)&1 == 1 {
			cur = poseidon.MustHash(p.Siblings[h], cur)
		} else {
			cur = poseidon.MustHash(cur, p.Siblings[h])
		}
	}
	return cur
}

// PathVars is Path as circuit variables.
type PathVars struct {
	Index    frontend.Variable
	Siblings [Depth]frontend.Variable
}

// Vars converts a native path to witness variables.
func (p *Path) Vars() PathVars {
	v := PathVars{Index: p.Index}
	for i := range p.Siblings {
		v.Siblings[i] = p.Siblings[i]
	}
	return v
}

// RootGadget constrains and returns the root of leaf at path. The index is
// decomposed into Depth bits, which also bounds it to the tree.
func RootGadget(api frontend.API, leaf frontend.Variable, path PathVars) (frontend.Variable, error) {
	bits := api.ToBinary(path.Index, Depth)
	cur := leaf
	for h := 0; h < Depth; h++ {
		left := api.Select(bits[h], path.Siblings[h], cur)
		right := api.Select(bits[h], cur, path.Siblings[h])
		var err error
		if cur, err = poseidon.HashGadget(api, left, right); err != nil {
			return nil, err
		}
	}
	return cur, nil
}
