package main

import (
	"fmt"
	"os"

	"dvpn-sim/internal/sim"
)

type row struct {
	hops, cell, cover  int
	avgHops            float64
	latency, mbps      float64
	anon, link         float64
	linkFail, chalFail int
}

func main() {
	var rows []row
	for _, h := range []int{2, 3, 4, 5} {
		for _, c := range []int{512, 1024, 1500} {
			for _, cov := range []int{0, 100} {
				cfg := sim.Config{
					Seed:              42,
					Clients:           40,
					NodesPerRole:      3,
					PacketsPerSession: 20,
					Hops:              h,
					CellSize:          c,
					CoverSessions:     cov,
					DNSMode:           "local",
					LinkLatencyMs:     20,
					LinkBandwidthBps:  100 * 1024 * 1024,
					AuditProb:         0.2,
					Epsilon:           0.01,
					CheatFactor:       1,
					ClientCheatFactor: 1,
				}
				r := sim.New(cfg).Run()
				rows = append(rows, row{
					hops: h, cell: c, cover: cov,
					avgHops:  r.AvgHops,
					latency:  r.AvgLatencyMs(),
					mbps:     r.ThroughputMBps(),
					anon:     r.AnonymitySet,
					link:     r.Linkability,
					linkFail: r.LinkFailed,
					chalFail: r.ChallengeFailed,
				})
			}
		}
	}

	if err := os.MkdirAll("results", 0o755); err != nil {
		panic(err)
	}
	f, err := os.Create("results/bench.csv")
	if err != nil {
		panic(err)
	}
	defer f.Close()
	fmt.Fprintln(f, "hops,cell,cover,avg_hops,latency_ms,mbps,anon,link,link_failed,challenge_failed")
	for _, r := range rows {
		fmt.Fprintf(f, "%d,%d,%d,%.2f,%.2f,%.2f,%.2f,%.2f,%d,%d\n",
			r.hops, r.cell, r.cover, r.avgHops, r.latency, r.mbps, r.anon, r.link, r.linkFail, r.chalFail)
	}

	fmt.Println("| hops | cell | cover | avg_hops | latency_ms | MB/s | anon | link | link_fail | chal_fail |")
	fmt.Println("|---|---|---|---|---|---|---|---|---|---|")
	for _, r := range rows {
		fmt.Printf("| %d | %d | %d | %.2f | %.2f | %.2f | %.2f | %.2f | %d | %d |\n",
			r.hops, r.cell, r.cover, r.avgHops, r.latency, r.mbps, r.anon, r.link, r.linkFail, r.chalFail)
	}
}
