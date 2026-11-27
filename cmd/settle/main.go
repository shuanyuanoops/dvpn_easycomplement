package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"

	"dvpn-sim/internal/usage"
)

func key() (ed25519.PublicKey, ed25519.PrivateKey) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	return pub, priv
}

func main() {
	grantPath := flag.String("grant", "", "client-signed grant JSON")
	claimPath := flag.String("claim", "", "node-signed claim JSON")
	price := flag.Int64("price", 1, "price per byte")
	flag.Parse()

	if *grantPath == "" || *claimPath == "" {
		demo()
		return
	}
	var g usage.Grant
	var c usage.Claim
	gb, err := os.ReadFile(*grantPath)
	if err != nil {
		log.Fatal(err)
	}
	cb, err := os.ReadFile(*claimPath)
	if err != nil {
		log.Fatal(err)
	}
	if err := json.Unmarshal(gb, &g); err != nil {
		log.Fatal(err)
	}
	if err := json.Unmarshal(cb, &c); err != nil {
		log.Fatal(err)
	}
	paid, pkts, cost, err := usage.Settle(g, c, *price)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("grant_bytes=%d claim_bytes=%d paid_bytes=%d paid_packets=%d cost=%d\n",
		g.Bytes, c.Bytes, paid, pkts, cost)
}

func demo() {
	cpub, cpriv := key()
	npub, npriv := key()
	g := usage.Grant{
		Session: "demo-session", Client: "client", Node: "exit-0",
		Epoch: 1, Bytes: 1000, Packets: 10, Pub: cpub,
	}
	usage.SignGrant(&g, cpriv)
	c := usage.Claim{
		Session: g.Session, Node: g.Node, Epoch: g.Epoch,
		Bytes: 1500, Packets: 15, Pub: npub,
	}
	usage.SignClaim(&c, npriv)
	paid, pkts, cost, err := usage.Settle(g, c, 1)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("client grant: bytes=%d packets=%d\n", g.Bytes, g.Packets)
	fmt.Printf("node claim:   bytes=%d packets=%d\n", c.Bytes, c.Packets)
	fmt.Printf("settled:      bytes=%d packets=%d cost=%d (capped at grant)\n", paid, pkts, cost)
}
