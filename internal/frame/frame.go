package frame

import (
	"encoding/binary"
	"errors"
)

const (
	TypeForward   byte = 0
	TypeReply     byte = 1
	TypeHandshake byte = 2
	TypeAck       byte = 3
	HeaderSize         = 19 // 2 length + 1 type + 8 tag + 8 seq
)

// Encode wraps an inner cell into a fixed-size wire frame:
//
//	[2-byte length][1-byte type][8-byte circuit][inner][zero padding]
func Encode(inner []byte, size int, typ byte, tag, seq uint64) ([]byte, error) {
	if size < HeaderSize {
		return nil, errors.New("frame size too small")
	}
	if len(inner)+HeaderSize > size {
		return nil, errors.New("inner too large for frame")
	}
	b := make([]byte, size)
	binary.BigEndian.PutUint16(b[:2], uint16(len(inner)))
	b[2] = typ
	binary.BigEndian.PutUint64(b[3:11], tag)
	binary.BigEndian.PutUint64(b[11:19], seq)
	copy(b[HeaderSize:], inner)
	return b, nil
}

// Decode strips the header and padding.
func Decode(buf []byte) (inner []byte, typ byte, tag, seq uint64, err error) {
	if len(buf) < HeaderSize {
		return nil, 0, 0, 0, errors.New("short frame")
	}
	n := int(binary.BigEndian.Uint16(buf[:2]))
	if n > len(buf)-HeaderSize {
		return nil, 0, 0, 0, errors.New("length exceeds frame")
	}
	return buf[HeaderSize : HeaderSize+n], buf[2], binary.BigEndian.Uint64(buf[3:11]), binary.BigEndian.Uint64(buf[11:19]), nil
}
