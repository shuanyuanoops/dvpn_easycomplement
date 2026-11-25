package frame

import (
	"encoding/binary"
	"errors"
)

// Encode wraps an inner cell into a fixed-size wire frame:
//
//	[2-byte length][inner][zero padding]
func Encode(inner []byte, size int) ([]byte, error) {
	if size < 2 {
		return nil, errors.New("frame size too small")
	}
	if len(inner)+2 > size {
		return nil, errors.New("inner too large for frame")
	}
	b := make([]byte, size)
	binary.BigEndian.PutUint16(b[:2], uint16(len(inner)))
	copy(b[2:], inner)
	return b, nil
}

// Decode strips the length prefix and padding.
func Decode(buf []byte) ([]byte, error) {
	if len(buf) < 2 {
		return nil, errors.New("short frame")
	}
	n := int(binary.BigEndian.Uint16(buf[:2]))
	if n > len(buf)-2 {
		return nil, errors.New("length exceeds frame")
	}
	return buf[2 : 2+n], nil
}
