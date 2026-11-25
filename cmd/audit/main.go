package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"dvpn-sim/internal/audit"
	"dvpn-sim/internal/receipt"
)

func main() {
	list := flag.String("receipts", "", "comma-separated receipt JSON files")
	epsilon := flag.Float64("epsilon", 0.01, "relative mismatch allowed")
	flag.Parse()
	if *list == "" {
		log.Fatal("-receipts is required")
	}

	var rs []*receipt.Receipt
	for _, path := range strings.Split(*list, ",") {
		if path == "" {
			continue
		}
		r, err := receipt.Read(path)
		if err != nil {
			log.Fatalf("%s: %v", path, err)
		}
		rs = append(rs, r)
	}
	rep, err := audit.Run(rs, *epsilon)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("%-8s %-8s %10s %12s %12s\n", "role", "name", "packets", "bytes_in", "bytes_out")
	for _, r := range rep.Receipts {
		fmt.Printf("%-8s %-8s %10d %12d %12d\n", r.Role, r.Name, r.Packets, r.BytesIn, r.BytesOut)
	}
	for _, c := range rep.Checks {
		status := "ok"
		if !c.OK {
			status = "MISMATCH"
		}
		fmt.Printf("%-8s -> %-8s  %d vs %d  diff=%.4f%%  %s\n",
			c.From, c.To, c.A, c.B, c.Diff*100, status)
	}
	if rep.Failed {
		os.Exit(1)
	}
}
