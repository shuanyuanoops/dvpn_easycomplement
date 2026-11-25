package link

import (
	"crypto/ed25519"
	"crypto/sha256"
	"fmt"
)

// Receipt is a link-level record co-signed by the sender and receiver.
type Receipt struct {
	Session      string
	From         string
	To           string
	SeqStart     int
	SeqEnd       int
	PayloadBytes int64
	SenderSig    []byte
	ReceiverSig  []byte
}

func message(session, from, to string, seqStart, seqEnd int, bytes int64) []byte {
	return []byte(fmt.Sprintf("%s|%s|%s|%d|%d|%d", session, from, to, seqStart, seqEnd, bytes))
}

// Sign creates a link receipt signed by both endpoints.
func Sign(session, from, to string, seqStart, seqEnd int, bytes int64, senderPriv, receiverPriv ed25519.PrivateKey) *Receipt {
	m := message(session, from, to, seqStart, seqEnd, bytes)
	return &Receipt{
		Session:      session,
		From:         from,
		To:           to,
		SeqStart:     seqStart,
		SeqEnd:       seqEnd,
		PayloadBytes: bytes,
		SenderSig:    ed25519.Sign(senderPriv, m),
		ReceiverSig:  ed25519.Sign(receiverPriv, m),
	}
}

// Verify checks both signatures against the endpoints' public keys.
func (r *Receipt) Verify(senderPub, receiverPub ed25519.PublicKey) bool {
	m := message(r.Session, r.From, r.To, r.SeqStart, r.SeqEnd, r.PayloadBytes)
	return ed25519.Verify(senderPub, m, r.SenderSig) &&
		ed25519.Verify(receiverPub, m, r.ReceiverSig)
}

// Hash returns the canonical hash of a link receipt.
func Hash(r *Receipt) [32]byte {
	return sha256.Sum256(message(r.Session, r.From, r.To, r.SeqStart, r.SeqEnd, r.PayloadBytes))
}

// PacketHash is the per-packet evidence a relay must hold if it forwarded seq.
func PacketHash(session string, seq int, bytes int64) [32]byte {
	return sha256.Sum256([]byte(fmt.Sprintf("%s|%d|%d", session, seq, bytes)))
}

// Challenge asks a relay to prove it saw a specific packet.
type Challenge struct {
	Session string
	Seq     int
	Bytes   int64
}

func NewChallenge(session string, seq int, bytes int64) Challenge {
	return Challenge{Session: session, Seq: seq, Bytes: bytes}
}

func (c Challenge) Check(hashes map[int][32]byte) bool {
	h, ok := hashes[c.Seq]
	if !ok {
		return false
	}
	return h == PacketHash(c.Session, c.Seq, c.Bytes)
}
