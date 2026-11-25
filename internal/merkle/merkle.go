package merkle

import (
	"crypto/sha256"
	"errors"
)

type Tree struct {
	levels [][][32]byte
}

func Build(leaves [][32]byte) *Tree {
	if len(leaves) == 0 {
		return &Tree{levels: [][][32]byte{{}}}
	}
	level := append([][32]byte(nil), leaves...)
	t := &Tree{}
	t.levels = append(t.levels, level)
	for len(level) > 1 {
		var next [][32]byte
		for i := 0; i < len(level); i += 2 {
			right := level[i]
			if i+1 < len(level) {
				right = level[i+1]
			}
			h := sha256.New()
			h.Write(level[i][:])
			h.Write(right[:])
			var out [32]byte
			copy(out[:], h.Sum(nil))
			next = append(next, out)
		}
		t.levels = append(t.levels, next)
		level = next
	}
	return t
}

func (t *Tree) Root() [32]byte {
	if len(t.levels) == 0 || len(t.levels[len(t.levels)-1]) == 0 {
		return [32]byte{}
	}
	return t.levels[len(t.levels)-1][0]
}

func (t *Tree) Proof(index int) ([][32]byte, error) {
	if index < 0 || len(t.levels) == 0 || index >= len(t.levels[0]) {
		return nil, errors.New("index out of range")
	}
	var proof [][32]byte
	idx := index
	for level := 0; level < len(t.levels)-1; level++ {
		sib := idx ^ 1
		if sib >= len(t.levels[level]) {
			sib = idx
		}
		proof = append(proof, t.levels[level][sib])
		idx /= 2
	}
	return proof, nil
}

func Verify(root, leaf [32]byte, index int, proof [][32]byte) bool {
	cur := leaf
	idx := index
	for _, sib := range proof {
		h := sha256.New()
		if idx%2 == 0 {
			h.Write(cur[:])
			h.Write(sib[:])
		} else {
			h.Write(sib[:])
			h.Write(cur[:])
		}
		copy(cur[:], h.Sum(nil))
		idx /= 2
	}
	return cur == root
}
