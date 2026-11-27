package usage

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
)

func keys(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func TestSettleCapsOverclaim(t *testing.T) {
	cpub, cpriv := keys(t)
	npub, npriv := keys(t)
	g := Grant{Session: "s1", Client: "c", Node: "n", Epoch: 1, Bytes: 1000, Packets: 10, Pub: cpub}
	SignGrant(&g, cpriv)
	c := Claim{Session: "s1", Node: "n", Epoch: 1, Bytes: 1500, Packets: 15, Pub: npub}
	SignClaim(&c, npriv)
	paid, pkts, cost, err := Settle(g, c, 2)
	if err != nil {
		t.Fatal(err)
	}
	if paid != 1000 || pkts != 10 || cost != 2000 {
		t.Fatalf("paid=%d pkts=%d cost=%d", paid, pkts, cost)
	}
}

func TestSettleUnderclaim(t *testing.T) {
	cpub, cpriv := keys(t)
	npub, npriv := keys(t)
	g := Grant{Session: "s1", Client: "c", Node: "n", Epoch: 1, Bytes: 1000, Packets: 10, Pub: cpub}
	SignGrant(&g, cpriv)
	c := Claim{Session: "s1", Node: "n", Epoch: 1, Bytes: 800, Packets: 8, Pub: npub}
	SignClaim(&c, npriv)
	paid, pkts, cost, err := Settle(g, c, 1)
	if err != nil {
		t.Fatal(err)
	}
	if paid != 800 || pkts != 8 || cost != 800 {
		t.Fatalf("paid=%d pkts=%d cost=%d", paid, pkts, cost)
	}
}

func TestSettleTamper(t *testing.T) {
	cpub, cpriv := keys(t)
	npub, npriv := keys(t)
	g := Grant{Session: "s1", Client: "c", Node: "n", Epoch: 1, Bytes: 1000, Packets: 10, Pub: cpub}
	SignGrant(&g, cpriv)
	c := Claim{Session: "s1", Node: "n", Epoch: 1, Bytes: 1000, Packets: 10, Pub: npub}
	SignClaim(&c, npriv)
	c.Bytes++
	if _, _, _, err := Settle(g, c, 1); err == nil {
		t.Fatal("tampered claim must fail")
	}
}
