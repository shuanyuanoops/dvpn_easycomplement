package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"

	"dvpn-sim/internal/frame"
	"dvpn-sim/internal/onion"
)

func main() {
	id := flag.String("id", "", "this relay's node id")
	keyHex := flag.String("key", "", "32-byte AES key, hex")
	listen := flag.String("listen", "127.0.0.1:17001", "UDP listen address")
	nextID := flag.String("next-id", "", "expected next hop id (empty for exit)")
	nextAddr := flag.String("next-addr", "", "next hop UDP address")
	destAddr := flag.String("dest", "", "destination UDP address (exit only)")
	frameSize := flag.Int("frame", 1024, "fixed wire frame size")
	flag.Parse()

	if *id == "" || *keyHex == "" {
		log.Fatal("-id and -key are required")
	}
	key, err := hex.DecodeString(*keyHex)
	if err != nil || len(key) != 32 {
		log.Fatal("-key must be 32 bytes hex")
	}

	laddr, err := net.ResolveUDPAddr("udp", *listen)
	if err != nil {
		log.Fatal(err)
	}
	conn, err := net.ListenUDP("udp", laddr)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	var next *net.UDPAddr
	if *nextAddr != "" {
		next, err = net.ResolveUDPAddr("udp", *nextAddr)
		if err != nil {
			log.Fatal(err)
		}
	}
	var dest *net.UDPAddr
	if *destAddr != "" {
		dest, err = net.ResolveUDPAddr("udp", *destAddr)
		if err != nil {
			log.Fatal(err)
		}
	}

	var packets, bytesIn, bytesOut atomic.Uint64
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-stop
		fmt.Printf("relay %s packets=%d in=%d out=%d\n", *id, packets.Load(), bytesIn.Load(), bytesOut.Load())
		conn.Close()
		os.Exit(0)
	}()

	fmt.Printf("relay %s listening on %s\n", *id, *listen)
	buf := make([]byte, 4096)
	for {
		n, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		inner, err := frame.Decode(buf[:n])
		if err != nil {
			log.Printf("bad frame: %v", err)
			continue
		}
		nextHop, payload, err := onion.Peel(inner, key)
		if err != nil {
			log.Printf("peel: %v", err)
			continue
		}
		packets.Add(1)
		bytesIn.Add(uint64(n))

		if nextHop == "dest" {
			if dest == nil {
				log.Printf("no -dest configured, dropping payload")
				continue
			}
			if _, err := conn.WriteToUDP(payload, dest); err != nil {
				log.Printf("write dest: %v", err)
			} else {
				bytesOut.Add(uint64(len(payload)))
			}
			continue
		}
		if next == nil {
			log.Printf("no -next-addr configured")
			continue
		}
		if *nextID != "" && string(nextHop) != *nextID {
			log.Printf("next hop mismatch: got %s want %s", nextHop, *nextID)
			continue
		}
		out, err := frame.Encode(payload, *frameSize)
		if err != nil {
			log.Printf("encode: %v", err)
			continue
		}
		if _, err := conn.WriteToUDP(out, next); err != nil {
			log.Printf("forward: %v", err)
			continue
		}
		bytesOut.Add(uint64(len(out)))
	}
}
