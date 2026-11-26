package main

import (
	"fmt"
	"math"
	"os"

	"dvpn-sim/internal/sim"
)

type row struct {
	hops, cell, cover int
	lat, latCI        float64
	mbps, mbpsCI      float64
	anon, link        float64
	linkFail          int
}

func meanCI(v []float64) (float64, float64) {
	if len(v) == 0 {
		return 0, 0
	}
	var sum float64
	for _, x := range v {
		sum += x
	}
	mean := sum / float64(len(v))
	var sq float64
	for _, x := range v {
		d := x - mean
		sq += d * d
	}
	std := math.Sqrt(sq / float64(len(v)))
	return mean, 1.96 * std / math.Sqrt(float64(len(v)))
}

func main() {
	var rows []row
	seeds := []int64{1, 2, 3, 4, 5}
	for _, h := range []int{2, 3, 4, 5} {
		for _, c := range []int{512, 1024, 1500} {
			for _, cov := range []int{0, 100} {
				var lats, mbps, anons, links []float64
				linkFail := 0
				for _, seed := range seeds {
					cfg := sim.Config{
						Seed:              seed,
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
						BurstLoss:         3,
						JitterMs:          2,
						CheatFactor:       1,
						ClientCheatFactor: 1,
					}
					r := sim.New(cfg).Run()
					lats = append(lats, r.AvgLatencyMs())
					mbps = append(mbps, r.ThroughputMBps())
					anons = append(anons, r.AnonymitySet)
					links = append(links, r.Linkability)
					if r.LinkFailed > linkFail {
						linkFail = r.LinkFailed
					}
				}
				lat, latCI := meanCI(lats)
				mb, mbCI := meanCI(mbps)
				an, _ := meanCI(anons)
				li, _ := meanCI(links)
				rows = append(rows, row{h, c, cov, lat, latCI, mb, mbCI, an, li, linkFail})
			}
		}
	}

	_ = os.MkdirAll("results", 0o755)
	f, err := os.Create("results/bench.csv")
	if err != nil {
		panic(err)
	}
	defer f.Close()
	fmt.Fprintln(f, "hops,cell,cover,latency_ms,latency_ci,mbps,mbps_ci,anon,link,link_failed")
	for _, r := range rows {
		fmt.Fprintf(f, "%d,%d,%d,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%d\n",
			r.hops, r.cell, r.cover, r.lat, r.latCI, r.mbps, r.mbpsCI, r.anon, r.link, r.linkFail)
	}

	fmt.Println("| hops | cell | cover | latency_ms | ±95% | MB/s | ±95% | anon | link | link_fail |")
	fmt.Println("|---|---|---|---|---|---|---|---|---|---|")
	for _, r := range rows {
		fmt.Printf("| %d | %d | %d | %.2f | %.2f | %.2f | %.2f | %.2f | %.2f | %d |\n",
			r.hops, r.cell, r.cover, r.lat, r.latCI, r.mbps, r.mbpsCI, r.anon, r.link, r.linkFail)
	}
}
