package link

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
)

// Half is one endpoint's signed view of a link. The sender signs its sent
// count; the receiver signs its received count. An auditor pairs the two by Tag.
type Half struct {
	Tag     string `json:"tag"`
	From    string `json:"from"`
	To      string `json:"to"`
	Role    string `json:"role"` // sender|receiver
	Packets int64  `json:"packets"`
	Bytes   int64  `json:"bytes"`
	Pub     string `json:"pub"`
	Sig     string `json:"sig"`
}

func (h Half) message() []byte {
	return []byte(fmt.Sprintf("link-half-v1|%s|%s|%s|%s|%d|%d",
		h.Tag, h.From, h.To, h.Role, h.Packets, h.Bytes))
}

func SignHalf(h *Half, priv ed25519.PrivateKey) {
	sig := ed25519.Sign(priv, h.message())
	h.Sig = hex.EncodeToString(sig)
}

func VerifyHalf(h Half) bool {
	pub, err := hex.DecodeString(h.Pub)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return false
	}
	sig, err := hex.DecodeString(h.Sig)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(pub), h.message(), sig)
}

// HashProof proves a relay saw a specific packet on a link.
type HashProof struct {
	Tag  string `json:"tag"`
	Seq  int    `json:"seq"`
	Hash string `json:"hash"`
	Pub  string `json:"pub"`
	Sig  string `json:"sig"`
}

func (p HashProof) message() []byte {
	return []byte(fmt.Sprintf("link-hash-v1|%s|%d|%s", p.Tag, p.Seq, p.Hash))
}

func SignHash(p *HashProof, priv ed25519.PrivateKey) {
	sig := ed25519.Sign(priv, p.message())
	p.Sig = hex.EncodeToString(sig)
}

func VerifyHash(p HashProof) bool {
	pub, err := hex.DecodeString(p.Pub)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return false
	}
	sig, err := hex.DecodeString(p.Sig)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(pub), p.message(), sig)
}
