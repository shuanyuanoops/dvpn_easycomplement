package audit

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"dvpn-sim/internal/receipt"
)

func key(t *testing.T) ed25519.PrivateKey {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return priv
}

func mk(t *testing.T, name, role string, packets, in, out int64) *receipt.Receipt {
	return receipt.New(name, role, "run", time.Now(), time.Now(), packets, in, out, key(t))
}

func TestHonestChain(t *testing.T) {
	rs := []*receipt.Receipt{
		mk(t, "client", "client", 10, 0, 1000),
		mk(t, "entry", "entry", 10, 1000, 1000),
		mk(t, "middle", "middle", 10, 1000, 1000),
		mk(t, "exit", "exit", 10, 1000, 800),
		mk(t, "sink", "sink", 10, 800, 0),
	}
	rep, err := Run(rs, 0.01)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Failed || len(rep.Checks) != 4 {
		t.Fatalf("failed=%v checks=%d", rep.Failed, len(rep.Checks))
	}
}

func TestMismatch(t *testing.T) {
	rs := []*receipt.Receipt{
		mk(t, "client", "client", 10, 0, 1000),
		mk(t, "entry", "entry", 10, 900, 1000),
		mk(t, "middle", "middle", 10, 1000, 1000),
		mk(t, "exit", "exit", 10, 1000, 800),
		mk(t, "sink", "sink", 10, 800, 0),
	}
	rep, err := Run(rs, 0.01)
	if err != nil {
		t.Fatal(err)
	}
	if !rep.Failed {
		t.Fatal("expected mismatch")
	}
}

func TestBadSignature(t *testing.T) {
	r := mk(t, "client", "client", 10, 0, 1000)
	r.BytesOut++
	if _, err := Run([]*receipt.Receipt{r}, 0.01); err == nil {
		t.Fatal("expected bad signature error")
	}
}
