package usage

import (
	"crypto/ed25519"
	"errors"
	"fmt"
)

// Grant is the client's signed authorization: "at most Bytes/Packets for this
// session/node/epoch". A node may claim less, never more.
type Grant struct {
	Session string `json:"session"`
	Client  string `json:"client"`
	Node    string `json:"node"`
	Epoch   int64  `json:"epoch"`
	Bytes   int64  `json:"bytes"`
	Packets int64  `json:"packets"`
	Pub     []byte `json:"pub"`
	Sig     []byte `json:"sig"`
}

func (g Grant) message() []byte {
	return []byte(fmt.Sprintf("usage-grant-v1|%s|%s|%s|%d|%d|%d",
		g.Session, g.Client, g.Node, g.Epoch, g.Bytes, g.Packets))
}

func SignGrant(g *Grant, priv ed25519.PrivateKey) {
	g.Sig = ed25519.Sign(priv, g.message())
}

func VerifyGrant(g Grant) bool {
	if len(g.Pub) != ed25519.PublicKeySize || len(g.Sig) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(g.Pub), g.message(), g.Sig)
}

// Claim is the node's signed statement of what it delivered.
type Claim struct {
	Session string `json:"session"`
	Node    string `json:"node"`
	Epoch   int64  `json:"epoch"`
	Bytes   int64  `json:"bytes"`
	Packets int64  `json:"packets"`
	Pub     []byte `json:"pub"`
	Sig     []byte `json:"sig"`
}

func (c Claim) message() []byte {
	return []byte(fmt.Sprintf("usage-claim-v1|%s|%s|%d|%d|%d",
		c.Session, c.Node, c.Epoch, c.Bytes, c.Packets))
}

func SignClaim(c *Claim, priv ed25519.PrivateKey) {
	c.Sig = ed25519.Sign(priv, c.message())
}

func VerifyClaim(c Claim) bool {
	if len(c.Pub) != ed25519.PublicKeySize || len(c.Sig) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(c.Pub), c.message(), c.Sig)
}

// Settle verifies the client grant and node claim and pays at most the grant.
// The node cannot overcharge by claiming more than the client signed.
func Settle(g Grant, c Claim, price int64) (paidBytes, paidPackets, cost int64, err error) {
	if !VerifyGrant(g) {
		return 0, 0, 0, errors.New("bad client grant signature")
	}
	if !VerifyClaim(c) {
		return 0, 0, 0, errors.New("bad node claim signature")
	}
	if g.Session != c.Session || g.Node != c.Node || g.Epoch != c.Epoch {
		return 0, 0, 0, errors.New("grant/claim mismatch")
	}
	if g.Bytes < 0 || g.Packets < 0 || c.Bytes < 0 || c.Packets < 0 {
		return 0, 0, 0, errors.New("negative usage")
	}
	paidBytes = c.Bytes
	if paidBytes > g.Bytes {
		paidBytes = g.Bytes
	}
	paidPackets = c.Packets
	if paidPackets > g.Packets {
		paidPackets = g.Packets
	}
	if price < 0 {
		return 0, 0, 0, errors.New("negative price")
	}
	cost = paidBytes * price
	return paidBytes, paidPackets, cost, nil
}
