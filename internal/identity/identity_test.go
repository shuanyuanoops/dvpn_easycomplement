package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
)

func TestSignVerify(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	x := make([]byte, 32)
	rand.Read(x)
	d := Sign("entry-0", x, pub, priv)
	gotX, gotE, err := d.Verify()
	if err != nil {
		t.Fatal(err)
	}
	if string(gotX) != string(x) || string(gotE) != string(pub) {
		t.Fatal("mismatch")
	}
}

func TestTamperFails(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	x := make([]byte, 32)
	rand.Read(x)
	d := Sign("entry-0", x, pub, priv)
	d.X25519 = "00" + d.X25519[2:]
	if _, _, err := d.Verify(); err == nil {
		t.Fatal("tampered document must fail")
	}
}
