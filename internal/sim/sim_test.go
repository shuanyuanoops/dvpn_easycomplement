package sim

import "testing"

func baseConfig() Config {
	return Config{
		Seed:              7,
		Clients:           60,
		NodesPerRole:      3,
		PacketsPerSession: 10,
		PacketSize:        1200,
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
