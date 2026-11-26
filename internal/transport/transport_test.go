package transport

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

func selfSigned(t *testing.T) tls.Certificate {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "dvpn.local"},
		DNSNames:     []string{"dvpn.local"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func TestTLSFrames(t *testing.T) {
	cert := selfSigned(t)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	done := make(chan error, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			done <- err
			return
		}
		defer c.Close()
		buf := make([]byte, 64)
		if _, err := c.Read(buf); err != nil {
			done <- err
			return
		}
		_, err = c.Write(buf)
		done <- err
	}()

	c, err := DialTLS(ln.Addr().String(), "dvpn.local", true, 64)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	msg := make([]byte, 64)
	copy(msg, "hello")
	if err := c.WriteFrame(msg); err != nil {
		t.Fatal(err)
	}
	got, err := c.ReadFrame()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatalf("got %x", got)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
