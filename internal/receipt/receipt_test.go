package receipt

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"
)

func TestSignVerify(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	r := New("n", "entry", "run", time.Now(), time.Now(), 10, 100, 200, priv)
	if !r.Verify() {
		t.Fatal("fresh receipt should verify")
	}
	r.BytesIn++
	if r.Verify() {
		t.Fatal("tampered receipt should not verify")
	}
}
