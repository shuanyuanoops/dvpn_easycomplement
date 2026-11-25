package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"net"
	"time"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:17004", "UDP listen address")
	duration := flag.Duration("duration", 3*time.Second, "how long to listen")
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
	fmt.Printf("sink packets=%d payload_bytes=%d min=%s avg=%s max=%s\n",
		packets, bytes, minLat.Round(time.Microsecond), avg.Round(time.Microsecond), maxLat.Round(time.Microsecond))
}
