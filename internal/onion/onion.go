package onion

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"

	"dvpn-sim/internal/model"
)

const (
	NextFieldSize = 16
	NonceSize     = 12
	TagSize       = 16
	LayerOverhead = NextFieldSize + NonceSize + TagSize
)

// Capacity returns the payload bytes that fit in a cell for a path of n hops.
func Capacity(cellSize, hops int) int {
	return cellSize - hops*LayerOverhead
}

// Build creates a fixed-size onion cell. keys must contain a 32-byte key for
// every hop. The payload is padded to the cell's payload capacity.
func Build(path []model.NodeID, payload []byte, keys map[model.NodeID][]byte, cellSize int) ([]byte, error) {
	capacity := Capacity(cellSize, len(path))
	if capacity <= 0 {
		return nil, fmt.Errorf("cell too small: %d", cellSize)
	}
	if len(payload) > capacity {
		return nil, fmt.Errorf("payload %d > capacity %d", len(payload), capacity)
	}
	inner := make([]byte, capacity)
	copy(inner, payload)

	for i := len(path) - 1; i >= 0; i-- {
		next := model.NodeID("dest")
		if i < len(path)-1 {
			next = path[i+1]
		}
		key, ok := keys[path[i]]
		if !ok {
			return nil, fmt.Errorf("missing key for %s", path[i])
		}
		plain, err := encode(next, inner)
		if err != nil {
			return nil, err
		}
		sealed, err := seal(key, plain)
		if err != nil {
			return nil, err
		}
		inner = sealed
	}

	if len(inner) != cellSize {
		return nil, fmt.Errorf("built cell %d != %d", len(inner), cellSize)
	}
	return inner, nil
}

// Peel removes one layer. It returns the next hop ("dest" at the exit) and the
// inner cell.
func Peel(cell []byte, key []byte) (model.NodeID, []byte, error) {
	plain, err := open(key, cell)
	if err != nil {
		return "", nil, err
	}
	return decode(plain)
}

func encode(next model.NodeID, payload []byte) ([]byte, error) {
	if len(next) > NextFieldSize {
		return nil, errors.New("next hop name too long")
	}
	out := make([]byte, NextFieldSize+len(payload))
	copy(out[:NextFieldSize], next)
	copy(out[NextFieldSize:], payload)
	return out, nil
}

func decode(plain []byte) (model.NodeID, []byte, error) {
	if len(plain) < NextFieldSize {
		return "", nil, errors.New("short plaintext")
	}
	raw := plain[:NextFieldSize]
	n := 0
	for n < len(raw) && raw[n] != 0 {
		n++
	}
	return model.NodeID(raw[:n]), plain[NextFieldSize:], nil
}

func seal(key, plain []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	out := make([]byte, 0, len(nonce)+len(plain)+gcm.Overhead())
	out = append(out, nonce...)
	out = gcm.Seal(out, nonce, plain, nil)
	return out, nil
}

func open(key, sealed []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(sealed) < gcm.NonceSize()+gcm.Overhead() {
		return nil, errors.New("sealed cell too short")
	}
	nonce := sealed[:gcm.NonceSize()]
	return gcm.Open(nil, nonce, sealed[gcm.NonceSize():], nil)
}
