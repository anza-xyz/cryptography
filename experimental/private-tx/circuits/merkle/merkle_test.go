package merkle

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

type membership struct {
	Root frontend.Variable `gnark:",public"`
	Leaf frontend.Variable
	Path PathVars
}

func (c *membership) Define(api frontend.API) error {
	root, err := RootGadget(api, c.Leaf, c.Path)
	if err != nil {
		return err
	}
	api.AssertIsEqual(root, c.Root)
	return nil
}

func leaf(i uint64) fr.Element {
	var e fr.Element
	e.SetUint64(1000 + i)
	return e
}

func TestNativePathMatchesRoot(t *testing.T) {
	var tr Tree
	if got, want := tr.Root(), EmptyRoot(); !got.Equal(&want) {
		t.Fatal("empty tree root != EmptyRoot")
	}
	for i := uint64(0); i < 5; i++ {
		if idx, err := tr.Append(leaf(i)); err != nil || idx != i {
			t.Fatalf("append %d: idx %d err %v", i, idx, err)
		}
		root := tr.Root()
		for j := uint64(0); j <= i; j++ {
			p, err := tr.Path(j)
			if err != nil {
				t.Fatal(err)
			}
			if got := p.Root(leaf(j)); !got.Equal(&root) {
				t.Fatalf("after %d leaves, path of leaf %d gives the wrong root", i+1, j)
			}
			if got := p.Root(leaf(j + 100)); got.Equal(&root) {
				t.Fatalf("wrong leaf %d accepted", j)
			}
		}
	}
	if _, err := tr.Path(5); err == nil {
		t.Fatal("path of a missing leaf")
	}
}

func TestGadgetMatchesNative(t *testing.T) {
	var tr Tree
	for i := uint64(0); i < 3; i++ {
		if _, err := tr.Append(leaf(i)); err != nil {
			t.Fatal(err)
		}
	}
	root := tr.Root()
	p, err := tr.Path(2)
	if err != nil {
		t.Fatal(err)
	}
	valid := &membership{Root: root, Leaf: leaf(2), Path: p.Vars()}

	wrongIndex := &membership{Root: root, Leaf: leaf(2), Path: p.Vars()}
	wrongIndex.Path.Index = 1

	wrongSibling := &membership{Root: root, Leaf: leaf(2), Path: p.Vars()}
	wrongSibling.Path.Siblings[Depth-1] = leaf(7)

	wrongLeaf := &membership{Root: root, Leaf: leaf(1), Path: p.Vars()}

	assert := test.NewAssert(t)
	assert.CheckCircuit(&membership{},
		test.WithValidAssignment(valid),
		test.WithInvalidAssignment(wrongIndex),
		test.WithInvalidAssignment(wrongSibling),
		test.WithInvalidAssignment(wrongLeaf),
		test.WithCurves(ecc.BN254),
		test.NoFuzzing(),
	)
}
