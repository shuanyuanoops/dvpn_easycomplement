package transport

import (
	"crypto/tls"
	"io"
	"net"
)

// FrameConn carries fixed-size frames. UDP keeps datagram boundaries; TLS is a
// stream, so it uses io.ReadFull/WriteFull with the same frame size.
type FrameConn interface {
	ReadFrame() ([]byte, error)
	WriteFrame([]byte) error
	Close() error
}

type udpConn struct {
	c   *net.UDPConn
	buf []byte
}

func DialUDP(addr string, frameSize int) (*udpConn, error) {
	a, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	c, err := net.DialUDP("udp", nil, a)
	if err != nil {
		return nil, err
	}
	return &udpConn{c: c, buf: make([]byte, frameSize)}, nil
}

func (u *udpConn) ReadFrame() ([]byte, error) {
	n, err := u.c.Read(u.buf)
	if err != nil {
		return nil, err
	}
	return u.buf[:n], nil
}

func (u *udpConn) WriteFrame(b []byte) error {
	_, err := u.c.Write(b)
	return err
}

func (u *udpConn) Close() error { return u.c.Close() }

type tlsConn struct {
	c   *tls.Conn
	buf []byte
}

func DialTLS(addr, serverName string, insecure bool, frameSize int) (*tlsConn, error) {
	return DialTLSECH(addr, serverName, insecure, frameSize, nil)
}

// DialTLSECH is DialTLS with an optional serialized ECHConfigList.
func DialTLSECH(addr, serverName string, insecure bool, frameSize int, echConfig []byte) (*tlsConn, error) {
	cfg := &tls.Config{
		MinVersion:         tls.VersionTLS13,
		ServerName:         serverName,
		InsecureSkipVerify: insecure,
	}
	if len(echConfig) > 0 {
		cfg.EncryptedClientHelloConfigList = echConfig
	}
	c, err := tls.Dial("tcp", addr, cfg)
	if err != nil {
		return nil, err
	}
	return &tlsConn{c: c, buf: make([]byte, frameSize)}, nil
}

func (t *tlsConn) ReadFrame() ([]byte, error) {
	if _, err := io.ReadFull(t.c, t.buf); err != nil {
		return nil, err
	}
	return t.buf, nil
}

func (t *tlsConn) WriteFrame(b []byte) error {
	for len(b) > 0 {
		n, err := t.c.Write(b)
		if err != nil {
			return err
		}
		b = b[n:]
	}
	return nil
}

func (t *tlsConn) Close() error { return t.c.Close() }
