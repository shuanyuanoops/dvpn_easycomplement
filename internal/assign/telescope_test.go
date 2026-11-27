package assign

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"dvpn-sim/internal/registry"
)

func testTicket() Ticket {
	return Ticket{
		Entry:       registry.Relay{ID: "entry-0", Role: "entry", Addr: "127.0.0.1:17101"},
		Middle:      registry.Relay{ID: "middle-0", Role: "middle", Addr: "127.0.0.1:17102"},
		Exit:        registry.Relay{ID: "exit-0", Role: "exit", Addr: "127.0.0.1:17103"},
		clientToken: "client-token",
		hopTokens:   [3]string{"h-entry", "h-middle", "h-exit"},
	}
}

func TestTelescopeDataPlane(t *testing.T) {
	tel := NewTelescope(testTicket())
	n, err := tel.Client.Build(tel.Entry)
	if err != nil {
		t.Fatal(err)
	}
	if n != 3 {
		t.Fatalf("keys=%d", n)
	}
	payload := []byte("hello through telescope")
	cell, err := tel.Client.Seal(payload)
	if err != nil {
		t.Fatal(err)
	}
	got, err := tel.Entry.Peel(cell)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("got %q", got)
	}
}

func TestTelescopeClientHidesExit(t *testing.T) {
	tel := NewTelescope(testTicket())
	if _, err := tel.Client.Build(tel.Entry); err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(tel.Client)
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	if strings.Contains(s, "middle-0") || strings.Contains(s, "exit-0") {
		t.Fatalf("client view leaks middle/exit: %s", s)
	}
	if !strings.Contains(s, "entry-0") {
		t.Fatalf("client view missing entry: %s", s)
	}
}
