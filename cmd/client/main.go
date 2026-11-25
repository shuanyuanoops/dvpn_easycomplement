package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"dvpn-sim/internal/frame"
	"dvpn-sim/internal/model"
	"dvpn-sim/internal/onion"
	"dvpn-sim/internal/receipt"
)

func main() {
	entry := flag.String("entry", "127.0.0.1:17001", "entry relay UDP address")
	pathStr := flag.String("path", "entry-0,middle-0,exit-0", "comma-separated hop ids")
	kEntry := flag.String("k-entry", "", "entry AES key hex")
	kMiddle := flag.String("k-middle", "", "middle AES key hex")
	kExit := flag.String("k-exit", "", "exit AES key hex")
	n := flag.Int("n", 4000, "number of cells to send")
	rate := flag.Int("rate", 4000, "cells per second")
	cellSize := flag.Int("cell", 1010, "onion cell size")
	frameSize := flag.Int("frame", 1024, "fixed wire frame size")
	name := flag.String("name", "client", "receipt name")
	runID := flag.String("run-id", "test", "run id for receipts")
	receiptPath := flag.String("receipt", "", "write a signed receipt JSON here")
	flag.Parse()

	ids := strings.Split(*pathStr, ",")
	if len(ids) != 3 {
		log.Fatal("-path needs exactly 3 ids")
	}
	keyHex := []string{*kEntry, *kMiddle, *kExit}
	keys := map[model.NodeID][]byte{}
	for i, id := range ids {
		k, err := hex.DecodeString(keyHex[i])
		if err != nil || len(k) != 32 {
			log.Fatalf("key %d must be 32 bytes hex", i)
		}
		keys[model.NodeID(id)] = k
	}

	addr, err := net.ResolveUDPAddr("udp", *entry)
	if err != nil {
		log.Fatal(err)
	}
	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	var cidBuf [8]byte
	if _, err := rand.Read(cidBuf[:]); err != nil {
		log.Fatal(err)
	}
	circuit := binary.BigEndian.Uint64(cidBuf[:])

	var mu sync.Mutex
	var rtts []time.Duration
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := conn.Read(buf)
			if err != nil {
				return
			}
			inner, typ, cid, err := frame.Decode(buf[:n])
			if err != nil || typ != frame.TypeReply || cid != circuit || len(inner) < 16 {
				continue
			}
			ts := int64(binary.BigEndian.Uint64(inner[:8]))
			if ts <= 0 {
				continue
			}
			rtt := time.Since(time.Unix(0, ts))
			if rtt < 0 {
				rtt = 0
			}
			mu.Lock()
			rtts = append(rtts, rtt)
			mu.Unlock()
		}
	}()

	payloadSize := onion.Capacity(*cellSize, len(ids))
	if payloadSize < 16 {
		log.Fatalf("cell too small: payload=%d", payloadSize)
	}
	payload := make([]byte, payloadSize)

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatal(err)
	}

	perTick := *rate / 1000
	if perTick < 1 {
		perTick = 1
	}
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()

	path := []model.NodeID{model.NodeID(ids[0]), model.NodeID(ids[1]), model.NodeID(ids[2])}
	start := time.Now()
	sent := 0
	var wireBytes int64
	for sent < *n {
		for j := 0; j < perTick && sent < *n; j++ {
			binary.BigEndian.PutUint64(payload[:8], uint64(time.Now().UnixNano()))
			binary.BigEndian.PutUint64(payload[8:16], uint64(sent))

			cell, err := onion.Build(path, payload, keys, *cellSize)
			if err != nil {
				log.Fatal(err)
			}
			out, err := frame.Encode(cell, *frameSize, frame.TypeForward, circuit)
			if err != nil {
				log.Fatal(err)
			}
			if _, err := conn.Write(out); err != nil {
				log.Fatal(err)
			}
			wireBytes += int64(len(out))
			sent++
		}
		<-ticker.C
	}

	time.Sleep(300 * time.Millisecond)
	elapsed := time.Since(start)

	mu.Lock()
	got := append([]time.Duration(nil), rtts...)
	mu.Unlock()
	var minRTT, maxRTT, sumRTT time.Duration
	for _, r := range got {
		if minRTT == 0 || r < minRTT {
			minRTT = r
		}
		if r > maxRTT {
			maxRTT = r
		}
		sumRTT += r
	}
	avgRTT := time.Duration(0)
	if len(got) > 0 {
		avgRTT = sumRTT / time.Duration(len(got))
	}

	if *receiptPath != "" {
		r := receipt.New(*name, "client", *runID, start, time.Now(), int64(sent), 0, wireBytes, priv)
		if err := receipt.Write(*receiptPath, r); err != nil {
			log.Printf("receipt: %v", err)
		}
	}

	loss := 0.0
	if sent > 0 {
		loss = 100 * float64(sent-len(got)) / float64(sent)
	}
	fmt.Printf("client circuit=%d sent=%d replies=%d loss=%.2f%% payload=%dB cell=%dB frame=%dB elapsed=%s rate=%.0f pps\n",
		circuit, sent, len(got), loss, payloadSize, *cellSize, *frameSize, elapsed.Round(time.Millisecond), float64(sent)/elapsed.Seconds())
	fmt.Printf("rtt min=%s avg=%s max=%s\n",
		minRTT.Round(time.Microsecond), avgRTT.Round(time.Microsecond), maxRTT.Round(time.Microsecond))
}
