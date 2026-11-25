package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"net"
	"time"

	"dvpn-sim/internal/receipt"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:17004", "UDP listen address")
	duration := flag.Duration("duration", 3*time.Second, "how long to listen")
	name := flag.String("name", "sink", "receipt name")
	runID := flag.String("run-id", "test", "run id for receipts")
	receiptPath := flag.String("receipt", "", "write a signed receipt JSON here")
	flag.Parse()

	addr, err := net.ResolveUDPAddr("udp", *listen)
	if err != nil {
		log.Fatal(err)
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(*duration))

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	start := time.Now()
	var packets, bytes int64
	var minLat, maxLat, sumLat time.Duration
	buf := make([]byte, 4096)
	for {
		n, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			break
		}
		packets++
		bytes += int64(n)
		if n >= 8 {
			ts := int64(binary.BigEndian.Uint64(buf[:8]))
			if ts > 0 {
				lat := time.Since(time.Unix(0, ts))
				if lat < 0 {
					lat = 0
				}
				if minLat == 0 || lat < minLat {
					minLat = lat
				}
				if lat > maxLat {
					maxLat = lat
				}
				sumLat += lat
			}
		}
	}

	avg := time.Duration(0)
	if packets > 0 {
		avg = sumLat / time.Duration(packets)
	}
	if *receiptPath != "" {
		r := receipt.New(*name, "sink", *runID, start, time.Now(), packets, bytes, 0, priv)
		if err := receipt.Write(*receiptPath, r); err != nil {
			log.Printf("receipt: %v", err)
		}
	}
	fmt.Printf("sink packets=%d payload_bytes=%d min=%s avg=%s max=%s\n",
		packets, bytes, minLat.Round(time.Microsecond), avg.Round(time.Microsecond), maxLat.Round(time.Microsecond))
}
