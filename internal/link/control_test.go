package link

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
)

func TestHalfSign(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	h := Half{Tag: "t1", From: "entry", To: "middle", Role: "sender", Packets: 10, Bytes: 1000, Pub: hexKey(pub)}
	SignHalf(&h, priv)
	if !VerifyHalf(h) {
		t.Fatal("valid half must verify")
	}
	h.Bytes++
	if VerifyHalf(h) {
		t.Fatal("tampered half must fail")
	}
}

func TestHashProof(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	p := HashProof{Tag: "t1", Seq: 3, Hash: "abcd", Pub: hexKey(pub)}
	SignHash(&p, priv)
	if !VerifyHash(p) {
		t.Fatal("valid proof must verify")
	}
	p.Seq++
	if VerifyHash(p) {
		t.Fatal("tampered proof must fail")
	}
}

func hexKey(pub ed25519.PublicKey) string {
	const hexdigits = "0123456789abcdef"
	out := make([]byte, len(pub)*2)
	for i, b := range pub {
		out[i*2] = hexdigits[b>>4]
		out[i*2+1] = hexdigits[b&0xf]
	}
	return string(out)
}
