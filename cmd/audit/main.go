package main

import (
	"flag"
	"fmt"
	"log"
	"os"

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
	for _, path := range split(*list) {
		r, err := receipt.Read(path)
		if err != nil {
			log.Fatalf("%s: %v", path, err)
		}
		if !r.Verify() {
			log.Fatalf("%s: bad signature", path)
		}
		rs = append(rs, r)
	}

	fmt.Printf("%-8s %-8s %10s %12s %12s\n", "role", "name", "packets", "bytes_in", "bytes_out")
	byRole := map[string]*receipt.Receipt{}
	for _, r := range rs {
		fmt.Printf("%-8s %-8s %10d %12d %12d\n", r.Role, r.Name, r.Packets, r.BytesIn, r.BytesOut)
		byRole[r.Role] = r
	}

	checks := []struct {
		from, to string
	}{
		{"client", "entry"},
		{"entry", "middle"},
		{"middle", "exit"},
		{"exit", "sink"},
	}
	failed := false
	for _, c := range checks {
		a, b := byRole[c.from], byRole[c.to]
		if a == nil || b == nil {
			fmt.Printf("skip %s->%s (missing receipt)\n", c.from, c.to)
			continue
		}
		diff := relDiff(float64(a.BytesOut), float64(b.BytesIn))
		status := "ok"
		if diff > *epsilon {
			status = "MISMATCH"
			failed = true
		}
		fmt.Printf("%-8s -> %-8s  %d vs %d  diff=%.4f%%  %s\n",
			c.from, c.to, a.BytesOut, b.BytesIn, diff*100, status)
	}
	if failed {
		os.Exit(1)
	}
}

func split(s string) []string {
	var out []string
	cur := ""
	for _, r := range s {
		if r == ',' {
			if cur != "" {
				out = append(out, cur)
			}
			cur = ""
			continue
		}
		cur += string(r)
	}
	if cur != "" {
		out = append(out, cur)
	}
	return out
}

func relDiff(a, b float64) float64 {
	if a == 0 && b == 0 {
		return 0
	}
	d := a - b
	if d < 0 {
		d = -d
	}
	m := a
	if b > m {
		m = b
	}
	return d / m
}
