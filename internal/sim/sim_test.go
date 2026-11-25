package sim

import "testing"

func baseConfig() Config {
	return Config{
		Seed:              7,
		Clients:           60,
		NodesPerRole:      3,
		PacketsPerSession: 10,
		CellSize:          1024,
		DNSSize:           200,
		DNSMode:           "tunnel",
		LinkLatencyMs:     5,
		LinkBandwidthBps:  100 * 1024 * 1024,
		AuditProb:         1.0,
		Epsilon:           0.01,
		CheatFactor:       1,
		ClientCheatFactor: 1,
	}
}

func TestHonestNoFlag(t *testing.T) {
	r := New(baseConfig()).Run()
	if r.Flagged != 0 || r.Slashed != 0 {
		t.Fatalf("honest run flagged=%d slashed=%.2f, want 0/0", r.Flagged, r.Slashed)
	}
	if r.Delivered != r.Packets {
		t.Fatalf("delivered=%d packets=%d", r.Delivered, r.Packets)
	}
}

func TestOverreportDetected(t *testing.T) {
	cfg := baseConfig()
	cfg.CheatNode = "entry-0"
	cfg.CheatFactor = 1.5
	r := New(cfg).Run()
	if r.AuditedCheat == 0 {
		t.Fatal("cheat node never appeared in a circuit; increase clients")
	}
	if r.DetectedCheat != r.AuditedCheat {
		t.Fatalf("detected=%d audited=%d", r.DetectedCheat, r.AuditedCheat)
	}
	if r.Slashed <= 0 {
		t.Fatal("expected slashed stake > 0")
	}
}

func TestUnderreportFlagsClientNotNodes(t *testing.T) {
	cfg := baseConfig()
	cfg.ClientCheatFactor = 0.5
	r := New(cfg).Run()
	if r.ClientFlagged == 0 {
		t.Fatal("expected client to be flagged")
	}
	if r.Slashed != 0 {
		t.Fatalf("underreport should not slash nodes, slashed=%.2f", r.Slashed)
	}
}

func TestLinkReceiptsAndChallenge(t *testing.T) {
	r := New(baseConfig()).Run()
	if r.LinkReceipts == 0 {
		t.Fatal("expected link receipts")
	}
	if r.LinkFailed != 0 {
		t.Fatalf("honest link receipts failed: %d", r.LinkFailed)
	}
	if r.Challenges == 0 || r.ChallengeFailed != 0 {
		t.Fatalf("challenges=%d failed=%d", r.Challenges, r.ChallengeFailed)
	}
}

func TestOverreportLinkMismatch(t *testing.T) {
	cfg := baseConfig()
	cfg.CheatNode = "entry-0"
	cfg.CheatFactor = 1.5
	r := New(cfg).Run()
	if r.LinkFailed == 0 {
		t.Fatal("expected link receipt byte mismatch under overreport")
	}
}

func TestHops234(t *testing.T) {
	for _, h := range []int{2, 3, 4} {
		cfg := baseConfig()
		cfg.Hops = h
		cfg.Clients = 20
		cfg.PacketsPerSession = 5
		r := New(cfg).Run()
		if r.Hops != h {
			t.Fatalf("hops=%d want %d", r.Hops, h)
		}
		if r.Delivered != r.Packets {
			t.Fatalf("hops=%d delivered=%d packets=%d", h, r.Delivered, r.Packets)
		}
		if r.LinkReceipts == 0 {
			t.Fatalf("hops=%d no link receipts", h)
		}
	}
}

func TestPrivacyCover(t *testing.T) {
	base := baseConfig()
	base.Clients = 1
	base.PacketsPerSession = 10
	base.CoverSessions = 0
	r0 := New(base).Run()
	if r0.AnonymitySet != 1 {
		t.Fatalf("no cover: set=%f want 1", r0.AnonymitySet)
	}
	withCover := base
	withCover.CoverSessions = 100
	r1 := New(withCover).Run()
	if r1.AnonymitySet <= 1 {
		t.Fatalf("cover: set=%f want >1", r1.AnonymitySet)
	}
}

func TestRandomHopsAndDiversity(t *testing.T) {
	cfg := baseConfig()
	cfg.Hops = 0
	cfg.HopsMin = 3
	cfg.HopsMax = 5
	cfg.Clients = 30
	cfg.PacketsPerSession = 5
	r := New(cfg).Run()
	if r.AvgHops < 3 || r.AvgHops > 5 {
		t.Fatalf("avg hops=%f", r.AvgHops)
	}
	if r.DistinctCircuits < 2 {
		t.Fatalf("distinct circuits=%d", r.DistinctCircuits)
	}
	if r.Delivered != r.Packets {
		t.Fatalf("delivered=%d packets=%d", r.Delivered, r.Packets)
	}
}
