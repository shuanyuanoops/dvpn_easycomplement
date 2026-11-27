package main

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

func TestBuildRelays(t *testing.T) {
	const n = 100
	relays := buildRelays(n, 10)
	if len(relays) != n {
		t.Fatalf("buildRelays(%d) returned %d relays", n, len(relays))
	}
	ids := map[string]bool{}
	addrs := map[string]bool{}
	roles := map[string]int{}
	ases := map[string]bool{}
	for _, r := range relays {
		if r.ID == "" || r.Addr == "" || r.AS == "" {
			t.Fatalf("incomplete relay: %+v", r)
		}
		if ids[r.ID] {
			t.Fatalf("duplicate relay id %q", r.ID)
		}
		ids[r.ID] = true
		if addrs[r.Addr] {
			t.Fatalf("duplicate relay addr %q", r.Addr)
		}
		addrs[r.Addr] = true
		roles[r.Role]++
		ases[r.AS] = true
	}
	if roles["entry"] != 34 || roles["middle"] != 33 || roles["exit"] != 33 {
		t.Fatalf("role split = %v, want 34/33/33", roles)
	}
	if len(ases) != 10 {
		t.Fatalf("buildRelays produced %d ASes, want 10", len(ases))
	}
}

func TestSimulateRoleMode(t *testing.T) {
	cfg := config{
		relays:      12,
		clients:     40,
		asCount:     4,
		seed:        9,
		candidates:  "role",
		maxAttempts: 16,
	}
	rep, err := simulate(cfg)
	if err != nil {
		t.Fatalf("simulate: %v", err)
	}
	if rep.assigned != cfg.clients {
		t.Fatalf("assigned = %d, want %d", rep.assigned, cfg.clients)
	}
	if rep.metrics.Circuits != cfg.clients {
		t.Fatalf("Circuits = %d, want %d", rep.metrics.Circuits, cfg.clients)
	}
	if rep.metrics.Attempts < cfg.clients {
		t.Fatalf("Attempts = %d, want at least %d", rep.metrics.Attempts, cfg.clients)
	}
	if rep.duplicateCircuits != 0 {
		t.Fatalf("within-circuit duplicate IDs = %d, want 0", rep.duplicateCircuits)
	}
	// Role-filtered pools have disjoint ID sets, so the board never has to
	// reject a duplicate-ID round.
	if rep.metrics.DuplicateIDRejects != 0 {
		t.Fatalf("DuplicateIDRejects = %d, want 0 in role mode", rep.metrics.DuplicateIDRejects)
	}
	if rep.neighborChecks != 3*cfg.clients {
		t.Fatalf("neighborChecks = %d, want %d", rep.neighborChecks, 3*cfg.clients)
	}
	if rep.distinctPaths < 1 || rep.distinctPaths > cfg.clients {
		t.Fatalf("distinctPaths = %d, want 1..%d", rep.distinctPaths, cfg.clients)
	}
	if rep.asDistinct == 0 {
		t.Fatal("no circuit reached pairwise-distinct AS values")
	}
	if len(rep.relayPicks) != cfg.relays {
		t.Fatalf("relayPicks has %d entries, want %d", len(rep.relayPicks), cfg.relays)
	}
	if len(rep.asPicks) != cfg.asCount {
		t.Fatalf("asPicks has %d entries, want %d", len(rep.asPicks), cfg.asCount)
	}

	relaySum := 0
	for _, rp := range rep.relayPicks {
		if rp.picks < 0 {
			t.Fatalf("negative picks for %s", rp.id)
		}
		relaySum += rp.picks
	}
	if relaySum != 3*cfg.clients {
		t.Fatalf("relay picks sum = %d, want %d", relaySum, 3*cfg.clients)
	}
	asSum := 0
	for _, ap := range rep.asPicks {
		asSum += ap.picks
	}
	if asSum != 3*cfg.clients {
		t.Fatalf("AS picks sum = %d, want %d", asSum, 3*cfg.clients)
	}

	var buf bytes.Buffer
	if err := rep.print(&buf); err != nil {
		t.Fatalf("print: %v", err)
	}
	out := buf.String()
	for _, want := range []string{
		"path diversity",
		"relay coverage",
		"AS distribution",
		"three-hop duplicate rate",
		"restricted views",
		"no middle/exit fields",
		"within-circuit dup IDs",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("report missing %q:\n%s", want, out)
		}
	}
	for _, rp := range rep.relayPicks {
		if !strings.Contains(out, fmt.Sprintf("%s=%d", rp.id, rp.picks)) {
			t.Fatalf("report missing per-relay count %s=%d", rp.id, rp.picks)
		}
	}
}

func TestSimulateFlatModeExercisesDuplicateRetries(t *testing.T) {
	cfg := config{
		relays:      6,
		clients:     80,
		asCount:     3,
		seed:        4,
		candidates:  "flat",
		maxAttempts: 16,
	}
	rep, err := simulate(cfg)
	if err != nil {
		t.Fatalf("simulate: %v", err)
	}
	if rep.duplicateCircuits != 0 {
		t.Fatalf("within-circuit duplicate IDs = %d, want 0", rep.duplicateCircuits)
	}
	if rep.metrics.DuplicateIDRejects == 0 {
		t.Fatal("flat candidate pools never produced a duplicate-ID retry")
	}
	if rep.metrics.Attempts <= cfg.clients {
		t.Fatalf("Attempts = %d, want more than %d after retries", rep.metrics.Attempts, cfg.clients)
	}
	if rep.neighborChecks != 3*cfg.clients {
		t.Fatalf("neighborChecks = %d, want %d", rep.neighborChecks, 3*cfg.clients)
	}
}

func TestSimulateRequestedScale(t *testing.T) {
	cfg := config{
		relays:      100,
		clients:     1000,
		asCount:     10,
		seed:        1,
		candidates:  "role",
		maxAttempts: 16,
	}
	rep, err := simulate(cfg)
	if err != nil {
		t.Fatalf("simulate: %v", err)
	}
	if rep.assigned != cfg.clients || rep.metrics.Circuits != cfg.clients {
		t.Fatalf("assigned=%d circuits=%d, want %d", rep.assigned, rep.metrics.Circuits, cfg.clients)
	}
	if rep.duplicateCircuits != 0 {
		t.Fatalf("duplicate circuits = %d, want 0", rep.duplicateCircuits)
	}
	if rep.neighborChecks != 3*cfg.clients {
		t.Fatalf("neighborChecks = %d, want %d", rep.neighborChecks, 3*cfg.clients)
	}
	if rep.distinctPaths < cfg.clients/2 {
		t.Fatalf("distinctPaths = %d, want at least %d", rep.distinctPaths, cfg.clients/2)
	}
	if len(rep.relayPicks) != cfg.relays || len(rep.asPicks) != cfg.asCount {
		t.Fatalf("relay/AS coverage = %d/%d, want %d/%d",
			len(rep.relayPicks), len(rep.asPicks), cfg.relays, cfg.asCount)
	}
}

func TestSimulateRejectsBadConfig(t *testing.T) {
	cases := map[string]config{
		"too few relays":   {relays: 2, clients: 1, asCount: 1, candidates: "role", maxAttempts: 1},
		"no clients":       {relays: 3, clients: 0, asCount: 1, candidates: "role", maxAttempts: 1},
		"no ASes":          {relays: 3, clients: 1, asCount: 0, candidates: "role", maxAttempts: 1},
		"bad candidates":   {relays: 3, clients: 1, asCount: 1, candidates: "bogus", maxAttempts: 1},
		"bad max attempts": {relays: 3, clients: 1, asCount: 1, candidates: "role", maxAttempts: 0},
	}
	for name, cfg := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := simulate(cfg); err == nil {
				t.Fatal("simulate unexpectedly succeeded")
			}
		})
	}
}
