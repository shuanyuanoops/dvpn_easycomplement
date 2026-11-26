package handshake

import (
	"bytes"
	"testing"
)

func TestSealOpen(t *testing.T) {
	pub, priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	msg := bytes.Repeat([]byte{0x42}, KeySize)
	sealed, err := Seal(pub, msg)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Open(priv, sealed)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatal("mismatch")
	}
}

func TestTamperFails(t *testing.T) {
	pub, priv, _ := GenerateKeyPair()
	sealed, _ := Seal(pub, []byte("secret"))
	sealed[len(sealed)-1] ^= 0xff
	if _, err := Open(priv, sealed); err == nil {
		t.Fatal("tampered box should fail")
	}
}

func TestWrongKeyFails(t *testing.T) {
	pub, _, _ := GenerateKeyPair()
	_, otherPriv, _ := GenerateKeyPair()
	sealed, _ := Seal(pub, []byte("secret"))
	if _, err := Open(otherPriv, sealed); err == nil {
		t.Fatal("wrong key should fail")
	}
}

func TestSealOpenPayload(t *testing.T) {
	key := bytes.Repeat([]byte{9}, KeySize)
	msg := []byte("ack-nonce")
	sealed, err := SealPayload(key, msg)
	if err != nil {
		t.Fatal(err)
	}
	got, err := OpenPayload(key, sealed)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatal("mismatch")
	}
}
