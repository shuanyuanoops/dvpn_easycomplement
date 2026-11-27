package assign

import (
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"fmt"

	"dvpn-sim/internal/handshake"
	"dvpn-sim/internal/registry"
)

// Telescope models circuit extension: the client knows only its entry, and each
// relay learns its next hop from the board. The client derives one session key
// per hop but never learns middle/exit identities.
type Telescope struct {
	Client *TelescopeClient
	Entry  *RelayAgent
}

// TelescopeClient is the client's entire view plus derived keys.
type TelescopeClient struct {
	Entry registry.Relay `json:"entry"`
	Token string         `json:"token"`
	keys  [][]byte
}

// RelayAgent is one hop in the simulated circuit. Its identity is visible only
// to the board/tests, not to the client.
type RelayAgent struct {
	Relay registry.Relay
	idx   int
	key   []byte
	next  *RelayAgent
}

// NewTelescope builds agents from a ticket. The client receives only the
// ClientView; it never sees middle/exit relay records.
func NewTelescope(t Ticket) *Telescope {
	entry := &RelayAgent{Relay: t.Entry, idx: 0}
	middle := &RelayAgent{Relay: t.Middle, idx: 1}
	exit := &RelayAgent{Relay: t.Exit, idx: 2}
	entry.next = middle
	middle.next = exit
	return &Telescope{
		Client: &TelescopeClient{Entry: t.Entry, Token: t.clientToken},
		Entry:  entry,
	}
}

// Build performs the telescope extension. It returns the number of hops so the
// caller can see the client learned keys, not identities.
func (c *TelescopeClient) Build(entry *RelayAgent) (int, error) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return 0, err
	}
	pubs, err := entry.Extend(priv.PublicKey().Bytes())
	if err != nil {
		return 0, err
	}
	c.keys = c.keys[:0]
	for i, pub := range pubs {
		peer, err := ecdh.X25519().NewPublicKey(pub)
		if err != nil {
			return 0, err
		}
		shared, err := priv.ECDH(peer)
		if err != nil {
			return 0, err
		}
		key, err := derive(shared, i)
		if err != nil {
			return 0, err
		}
		c.keys = append(c.keys, key)
	}
	return len(c.keys), nil
}

// Extend is called by the previous hop (or the client for the entry). It
// generates this hop's ephemeral key and recursively extends to the next hop.
func (a *RelayAgent) Extend(clientPub []byte) ([][]byte, error) {
	peer, err := ecdh.X25519().NewPublicKey(clientPub)
	if err != nil {
		return nil, err
	}
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	shared, err := priv.ECDH(peer)
	if err != nil {
		return nil, err
	}
	key, err := derive(shared, a.idx)
	if err != nil {
		return nil, err
	}
	a.key = key
	pubs := [][]byte{priv.PublicKey().Bytes()}
	if a.next != nil {
		more, err := a.next.Extend(clientPub)
		if err != nil {
			return nil, err
		}
		pubs = append(pubs, more...)
	}
	return pubs, nil
}

// Seal encrypts payload in reverse hop order, so entry peels first and exit
// gets the plaintext.
func (c *TelescopeClient) Seal(payload []byte) ([]byte, error) {
	out := append([]byte(nil), payload...)
	for i := len(c.keys) - 1; i >= 0; i-- {
		var err error
		out, err = handshake.SealPayload(c.keys[i], out)
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}

// Peel removes one layer and forwards to the next hop; the exit returns the
// plaintext.
func (a *RelayAgent) Peel(cell []byte) ([]byte, error) {
	if a.key == nil {
		return nil, fmt.Errorf("assign: hop %s has no key", a.Relay.ID)
	}
	plain, err := handshake.OpenPayload(a.key, cell)
	if err != nil {
		return nil, err
	}
	if a.next != nil {
		return a.next.Peel(plain)
	}
	return plain, nil
}

func derive(shared []byte, idx int) ([]byte, error) {
	return hkdf.Key(sha256.New, shared, nil, fmt.Sprintf("dvpn-telescope-%d", idx), 32)
}
