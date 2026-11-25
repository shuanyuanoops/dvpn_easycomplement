package onion

import (
	"bytes"
	"testing"

	"dvpn-sim/internal/model"
)

func TestBuildPeel(t *testing.T) {
	path := []model.NodeID{"entry-0", "middle-0", "exit-0"}
	keys := map[model.NodeID][]byte{}
	for _, id := range path {
		k := make([]byte, 32)
		for i := range k {
			k[i] = byte(len(id) + i)
		}
		keys[id] = k
	}
	payload := bytes.Repeat([]byte{0x42}, 100)

	cell, err := Build(path, payload, keys, 1024)
	if err != nil {
		t.Fatal(err)
	}
	if len(cell) != 1024 {
		t.Fatalf("cell len=%d", len(cell))
	}

	cur := cell
	for i, id := range path {
		next, inner, err := Peel(cur, keys[id])
		if err != nil {
			t.Fatalf("peel %d: %v", i, err)
		}
		want := model.NodeID("dest")
		if i < len(path)-1 {
			want = path[i+1]
		}
		if next != want {
			t.Fatalf("peel %d next=%s want=%s", i, next, want)
		}
		cur = inner
	}
	if !bytes.Equal(cur[:100], payload) {
		t.Fatal("payload mismatch")
	}
}

func TestTamperFails(t *testing.T) {
	path := []model.NodeID{"entry-0"}
	keys := map[model.NodeID][]byte{"entry-0": bytes.Repeat([]byte{7}, 32)}
	cell, err := Build(path, []byte("x"), keys, 256)
	if err != nil {
		t.Fatal(err)
	}
	cell[20] ^= 0xff
	if _, _, err := Peel(cell, keys["entry-0"]); err == nil {
		t.Fatal("tampered cell should fail")
	}
}
