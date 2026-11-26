package handshake

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"
)

const (
	PubSize   = 32
	NonceSize = 12
	KeySize   = 32
	Overhead  = PubSize + NonceSize + 16
)

// GenerateKeyPair returns an X25519 public/private pair.
func GenerateKeyPair() (pub, priv []byte, err error) {
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return k.PublicKey().Bytes(), k.Bytes(), nil
}

// Seal encrypts msg to an X25519 public key using an ephemeral key and
// HKDF-SHA256. Output: ephemeral pubkey || nonce || ciphertext.
func Seal(recipientPub, msg []byte) ([]byte, error) {
	curve := ecdh.X25519()
	pub, err := curve.NewPublicKey(recipientPub)
	if err != nil {
		return nil, err
	}
	eph, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	shared, err := eph.ECDH(pub)
	if err != nil {
		return nil, err
	}
	key, err := hkdf.Key(sha256.New, shared, nil, "dvpn-handshake-v1", KeySize)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, NonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	out := make([]byte, 0, PubSize+NonceSize+len(msg)+gcm.Overhead())
	out = append(out, eph.PublicKey().Bytes()...)
	out = append(out, nonce...)
	out = gcm.Seal(out, nonce, msg, nil)
	return out, nil
}

// SealPayload encrypts msg with a raw 32-byte key (nonce||ciphertext).
func SealPayload(key, msg []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, NonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	out := make([]byte, 0, NonceSize+len(msg)+gcm.Overhead())
	out = append(out, nonce...)
	out = gcm.Seal(out, nonce, msg, nil)
	return out, nil
}

// OpenPayload decrypts a SealPayload box.
func OpenPayload(key, sealed []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(sealed) < gcm.NonceSize()+gcm.Overhead() {
		return nil, errors.New("sealed payload too short")
	}
	return gcm.Open(nil, sealed[:gcm.NonceSize()], sealed[gcm.NonceSize():], nil)
}

// Open decrypts a sealed box with the X25519 private key.
func Open(priv, sealed []byte) ([]byte, error) {
	if len(sealed) < Overhead {
		return nil, errors.New("sealed key too short")
	}
	curve := ecdh.X25519()
	k, err := curve.NewPrivateKey(priv)
	if err != nil {
		return nil, err
	}
	ephPub, err := curve.NewPublicKey(sealed[:PubSize])
	if err != nil {
		return nil, err
	}
	shared, err := k.ECDH(ephPub)
	if err != nil {
		return nil, err
	}
	key, err := hkdf.Key(sha256.New, shared, nil, "dvpn-handshake-v1", KeySize)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := sealed[PubSize : PubSize+NonceSize]
	return gcm.Open(nil, nonce, sealed[PubSize+NonceSize:], nil)
}
