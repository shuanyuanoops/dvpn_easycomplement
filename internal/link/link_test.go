package link

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
)

func pair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func TestSignVerify(t *testing.T) {
	senderPub, senderPriv := pair(t)
	receiverPub, receiverPriv := pair(t)
	r := Sign("s1", "entry", "middle", 10, 9, 1000, 900, senderPriv, receiverPriv)
	if !r.Verify(senderPub, receiverPub) {
		t.Fatal("honest link receipt must verify")
	}
}

func TestTamperFails(t *testing.T) {
	senderPub, senderPriv := pair(t)
	receiverPub, receiverPriv := pair(t)
	r := Sign("s1", "entry", "middle", 10, 9, 1000, 900, senderPriv, receiverPriv)
	r.SentBytes++
	if r.Verify(senderPub, receiverPub) {
		t.Fatal("tampered receipt must fail")
	}
}

func TestWrongKeyFails(t *testing.T) {
	_, senderPriv := pair(t)
	_, receiverPriv := pair(t)
	otherPub, _ := pair(t)
	r := Sign("s1", "entry", "middle", 10, 9, 1000, 900, senderPriv, receiverPriv)
	if r.Verify(otherPub, otherPub) {
		t.Fatal("wrong keys must fail")
	}
}

func TestChallenge(t *testing.T) {
	hashes := map[int][32]byte{
		3: PacketHash("s1", 3, 1200),
	}
	if !NewChallenge("s1", 3, 1200).Check(hashes) {
		t.Fatal("existing packet must pass")
	}
	if NewChallenge("s1", 4, 1200).Check(hashes) {
		t.Fatal("missing packet must fail")
	}
	if NewChallenge("s1", 3, 999).Check(hashes) {
		t.Fatal("wrong byte count must fail")
	}
}
