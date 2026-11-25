package merkle

import (
	"crypto/sha256"
	"testing"
)

func leaves(n int) [][32]byte {
	var out [][32]byte
	for i := 0; i < n; i++ {
		out = append(out, sha256.Sum256([]byte{byte(i)}))
	}
	return out
}

func TestProofs(t *testing.T) {
	for _, n := range []int{1, 2, 3, 5, 8} {
		ls := leaves(n)
		tr := Build(ls)
		root := tr.Root()
		for i := 0; i < n; i++ {
			proof, err := tr.Proof(i)
			if err != nil {
				t.Fatal(err)
			}
			if !Verify(root, ls[i], i, proof) {
				t.Fatalf("n=%d i=%d proof failed", n, i)
			}
		}
	}
}

func TestTamperedLeaf(t *testing.T) {
	ls := leaves(4)
	tr := Build(ls)
	proof, _ := tr.Proof(1)
	bad := ls[1]
	bad[0] ^= 1
	if Verify(tr.Root(), bad, 1, proof) {
		t.Fatal("tampered leaf should fail")
	}
}

func TestIndexOutOfRange(t *testing.T) {
	tr := Build(leaves(2))
	if _, err := tr.Proof(2); err == nil {
		t.Fatal("expected error")
	}
}
