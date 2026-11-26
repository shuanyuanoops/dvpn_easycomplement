package identity

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
)

// Document binds a relay's X25519 transport key to its Ed25519 identity key.
type Document struct {
	ID      string `json:"id"`
	X25519  string `json:"x25519"`
	Ed25519 string `json:"ed25519"`
	Sig     string `json:"sig"`
}

func Sign(id string, x25519Pub, ed25519Pub []byte, ed25519Priv ed25519.PrivateKey) Document {
	msg := []byte(id + "|" + hex.EncodeToString(x25519Pub))
	sig := ed25519.Sign(ed25519Priv, msg)
	return Document{
		ID:      id,
		X25519:  hex.EncodeToString(x25519Pub),
		Ed25519: hex.EncodeToString(ed25519Pub),
		Sig:     hex.EncodeToString(sig),
	}
}

func (d Document) Verify() (x25519Pub, ed25519Pub []byte, err error) {
	x, err := hex.DecodeString(d.X25519)
	if err != nil || len(x) != 32 {
		return nil, nil, errors.New("bad x25519 key")
	}
	e, err := hex.DecodeString(d.Ed25519)
	if err != nil || len(e) != ed25519.PublicKeySize {
		return nil, nil, errors.New("bad ed25519 key")
	}
	s, err := hex.DecodeString(d.Sig)
	if err != nil || len(s) != ed25519.SignatureSize {
		return nil, nil, errors.New("bad signature")
	}
	msg := []byte(d.ID + "|" + d.X25519)
	if !ed25519.Verify(ed25519.PublicKey(e), msg, s) {
		return nil, nil, errors.New("signature mismatch")
	}
	return x, e, nil
}

func Write(path string, d Document) error {
	b, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o600)
}

func Read(path string) (Document, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Document{}, err
	}
	var d Document
	if err := json.Unmarshal(b, &d); err != nil {
		return Document{}, err
	}
	return d, nil
}
