package ech

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/binary"
	"fmt"
)

// Config holds a single ECHConfig (for the server) and the corresponding
// ECHConfigList (for clients).
type Config struct {
	List    []byte
	Server  []byte
	Private []byte
}

// Generate creates an X25519/HKDF-SHA256/AES-128-GCM ECH config.
func Generate(publicName string) (Config, error) {
	if len(publicName) == 0 || len(publicName) > 255 {
		return Config{}, fmt.Errorf("bad public name")
	}
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return Config{}, err
	}
	pub := key.PublicKey().Bytes()

	var body []byte
	body = append(body, 0)                             // config_id
	body = binary.BigEndian.AppendUint16(body, 0x0020) // DHKEM(X25519, HKDF-SHA256)
	body = appendOpaque16(body, pub)
	body = appendOpaque16(body, []byte{0x00, 0x01, 0x00, 0x01}) // HKDF-SHA256, AES-128-GCM
	body = append(body, 64)                                     // maximum_name_length
	body = appendOpaque8(body, []byte(publicName))
	body = append(body, 0, 0) // no extensions

	var server []byte
	server = binary.BigEndian.AppendUint16(server, 0xfe0d) // ECHConfig version
	server = binary.BigEndian.AppendUint16(server, uint16(len(body)))
	server = append(server, body...)

	list := binary.BigEndian.AppendUint16(nil, uint16(len(server)))
	list = append(list, server...)

	return Config{List: list, Server: server, Private: key.Bytes()}, nil
}

func appendOpaque16(dst, v []byte) []byte {
	dst = binary.BigEndian.AppendUint16(dst, uint16(len(v)))
	return append(dst, v...)
}

func appendOpaque8(dst, v []byte) []byte {
	dst = append(dst, byte(len(v)))
	return append(dst, v...)
}
