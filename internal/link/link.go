package link

import (
	"crypto/ed25519"
	"crypto/sha256"
	"fmt"
)

// Receipt is a link-level record co-signed by the sender and receiver.
// The sender attests SentPackets/SentBytes; the receiver attests
// RecvPackets/RecvBytes. Both sign the same record.
type Receipt struct {
	Session     string
	From        string
	To          string
	SentPackets int
	RecvPackets int
	SentBytes   int64
	RecvBytes   int64
	SenderSig   []byte
	ReceiverSig []byte
}

func message(r *Receipt) []byte {
	return []byte(fmt.Sprintf("%s|%s|%s|%d|%d|%d|%d",
		r.Session, r.From, r.To, r.SentPackets, r.RecvPackets, r.SentBytes, r.RecvBytes))
}

// Sign creates a link receipt signed by both endpoints.
func Sign(session, from, to string, sentPackets, recvPackets int, sentBytes, recvBytes int64, senderPriv, receiverPriv ed25519.PrivateKey) *Receipt {
	r := &Receipt{
		Session:     session,
		From:        from,
		To:          to,
		SentPackets: sentPackets,
		RecvPackets: recvPackets,
		SentBytes:   sentBytes,
		RecvBytes:   recvBytes,
	}
	m := message(r)
	r.SenderSig = ed25519.Sign(senderPriv, m)
	r.ReceiverSig = ed25519.Sign(receiverPriv, m)
	return r
}

// Verify checks both signatures against the endpoints' public keys.
func (r *Receipt) Verify(senderPub, receiverPub ed25519.PublicKey) bool {
	m := message(r)
	return ed25519.Verify(senderPub, m, r.SenderSig) &&
		ed25519.Verify(receiverPub, m, r.ReceiverSig)
}

// Hash returns the canonical hash of a link receipt.
func Hash(r *Receipt) [32]byte {
	return sha256.Sum256(message(r))
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
