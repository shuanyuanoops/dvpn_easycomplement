package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"os"
	"sync"
	"time"

	"dvpn-sim/internal/ech"
)

func selfSigned(name string) (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: name},
		DNSNames:     []string{name},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}

func main() {
	listen := flag.String("listen", "127.0.0.1:17443", "TLS listen address")
	entry := flag.String("entry", "127.0.0.1:17101", "UDP entry address")
	frameSize := flag.Int("frame", 1024, "fixed frame size")
	certFile := flag.String("cert", "", "TLS certificate (PEM)")
	keyFile := flag.String("key", "", "TLS private key (PEM)")
	tlsName := flag.String("tls-name", "dvpn.local", "self-signed certificate SAN")
	echMode := flag.Bool("ech", false, "generate an ECH key/config and require ECH")
	echOut := flag.String("ech-out", "", "write the ECHConfigList here for clients")
	flag.Parse()

	var cert tls.Certificate
	var err error
	if *certFile != "" && *keyFile != "" {
		cert, err = tls.LoadX509KeyPair(*certFile, *keyFile)
	} else {
		cert, err = selfSigned(*tlsName)
	}
	if err != nil {
		log.Fatal(err)
	}
	cfg := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
	}
	if *echMode {
		ec, err := ech.Generate(*tlsName)
		if err != nil {
			log.Fatal(err)
		}
		cfg.EncryptedClientHelloKeys = []tls.EncryptedClientHelloKey{
			{Config: ec.Server, PrivateKey: ec.Private},
		}
		if *echOut != "" {
			if err := os.WriteFile(*echOut, ec.List, 0o600); err != nil {
				log.Fatal(err)
			}
		}
		fmt.Printf("ech enabled public_name=%s config=%d bytes\n", *tlsName, len(ec.List))
	}
	ln, err := tls.Listen("tcp", *listen, cfg)
	if err != nil {
		log.Fatal(err)
	}
	defer ln.Close()
	fmt.Printf("tlsgate listening on %s -> udp %s\n", *listen, *entry)

	for {
		c, err := ln.Accept()
		if err != nil {
			log.Printf("accept: %v", err)
			continue
		}
		go handle(c, *entry, *frameSize)
	}
}

func handle(c net.Conn, entry string, frameSize int) {
	defer c.Close()
	if tc, ok := c.(*tls.Conn); ok {
		if err := tc.Handshake(); err != nil {
			log.Printf("tls handshake: %v", err)
			return
		}
		st := tc.ConnectionState()
		log.Printf("tls version=0x%x ech=%v", st.Version, st.ECHAccepted)
	}
	addr, err := net.ResolveUDPAddr("udp", entry)
	if err != nil {
		log.Printf("resolve entry: %v", err)
		return
	}
	u, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		log.Printf("dial entry: %v", err)
		return
	}
	defer u.Close()

	var once sync.Once
	closeBoth := func() {
		once.Do(func() {
			c.Close()
			u.Close()
		})
	}

	go func() {
		buf := make([]byte, frameSize)
		for {
			if _, err := io.ReadFull(c, buf); err != nil {
				closeBoth()
				return
			}
			if _, err := u.Write(buf); err != nil {
				closeBoth()
				return
			}
		}
	}()

	buf := make([]byte, frameSize)
	for {
		n, err := u.Read(buf)
		if err != nil {
			closeBoth()
			return
		}
		for off := 0; off < n; {
			w, err := c.Write(buf[off:n])
			if err != nil {
				closeBoth()
				return
			}
			off += w
		}
	}
}
