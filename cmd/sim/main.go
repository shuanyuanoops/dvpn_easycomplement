package main

import (
	"flag"
	"fmt"
	"os"

	"dvpn-sim/internal/sim"
)

func main() {
	scenario := flag.String("scenario", "all", "honest|overreport|underreport|all")
	clients := flag.Int("clients", 60, "number of clients/sessions")
	packets := flag.Int("packets", 50, "packets per session")
	hops := flag.Int("hops", 3, "2, 3 or 4")
	cell := flag.Int("cell", 1024, "cell size in bytes")
	seed := flag.Int64("seed", 42, "random seed")
	dnsMode := flag.String("dns", "tunnel", "tunnel|local")
	flag.Parse()

	base := sim.Config{
		Seed:              *seed,
		Clients:           *clients,
		NodesPerRole:      3,
		PacketsPerSession: *packets,
		Hops:              *hops,
		CellSize:          *cell,
		DNSSize:           200,
		DNSMode:           *dnsMode,
		LinkLatencyMs:     20,
		LinkBandwidthBps:  100 * 1024 * 1024,
		AuditProb:         0.2,
		Epsilon:           0.01,
		CheatFactor:       1,
		ClientCheatFactor: 1,
	}

	printPrivacyMatrix()

	run := func(name string, cfg sim.Config) {
		r := sim.New(cfg).Run()
		fmt.Printf("\n=== scenario=%s ===\n", name)
		fmt.Printf("sessions=%d hops=%d packets=%d delivered=%d\n", r.Sessions, r.Hops, r.Packets, r.Delivered)
		fmt.Printf("avg_latency_ms=%.2f throughput_mbps=%.2f\n", r.AvgLatencyMs(), r.ThroughputMBps())
		fmt.Printf("payload_mb=%.2f wire_mb=%.2f\n", float64(r.TotalBytes)/1e6, float64(r.WireBytes)/1e6)
		fmt.Printf("dns_packets=%d local_dns_leaks=%d\n", r.DNSPackets, r.LocalDNSLeaks)
		fmt.Printf("link_receipts=%d link_failed=%d challenges=%d challenge_failed=%d\n",
			r.LinkReceipts, r.LinkFailed, r.Challenges, r.ChallengeFailed)
		fmt.Printf("audits=%d flagged=%d client_flagged=%d slashed=%.2f\n", r.Audits, r.Flagged, r.ClientFlagged, r.Slashed)
		fmt.Printf("cheat_sessions=%d audited_cheat=%d detected_cheat=%d detection_rate=%.2f\n",
			r.CheatSessions, r.AuditedCheat, r.DetectedCheat, r.DetectionRate())
	}

	switch *scenario {
	case "honest":
		run("honest", base)
	case "overreport":
		cfg := base
		cfg.CheatNode = "entry-0"
		cfg.CheatFactor = 1.5
		run("overreport", cfg)
	case "underreport":
		cfg := base
		cfg.ClientCheatFactor = 0.5
		run("underreport", cfg)
	case "all":
		run("honest", base)
		cfg1 := base
		cfg1.CheatNode = "entry-0"
		cfg1.CheatFactor = 1.5
		run("overreport", cfg1)
		cfg2 := base
		cfg2.ClientCheatFactor = 0.5
		run("underreport", cfg2)
	default:
		fmt.Fprintf(os.Stderr, "unknown scenario %q\n", *scenario)
		os.Exit(2)
	}
}

func printPrivacyMatrix() {
	fmt.Println("=== knowledge matrix (3-hop) ===")
	fmt.Println("party   C-IP   D-IP   SNI   bytes")
	fmt.Println("C       yes    yes    yes   yes")
	fmt.Println("E       yes    no     no    yes")
	fmt.Println("M       no     no     no    yes")
	fmt.Println("X       no     yes    no    yes")
	fmt.Println("D       no     -      -     yes")
}
