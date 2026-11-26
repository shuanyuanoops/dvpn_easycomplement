package registry

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"dvpn-sim/internal/model"
)

func testPool() *Pool {
	return &Pool{Relays: []Relay{
		{ID: "entry-0", Role: "entry", Addr: "127.0.0.1:17101", Identity: "/tmp/dvpn_entry-0.id"},
		{ID: "entry-1", Role: "entry", Addr: "127.0.0.1:17102", Identity: "/tmp/dvpn_entry-1.id"},
		{ID: "middle-0", Role: "middle", Addr: "127.0.0.1:17103", Identity: "/tmp/dvpn_middle-0.id"},
		{ID: "middle-1", Role: "middle", Addr: "127.0.0.1:17104", Identity: "/tmp/dvpn_middle-1.id"},
		{ID: "exit-0", Role: "exit", Addr: "127.0.0.1:17105", Identity: "/tmp/dvpn_exit-0.id"},
		{ID: "exit-1", Role: "exit", Addr: "127.0.0.1:17106", Identity: "/tmp/dvpn_exit-1.id"},
	}}
}

func TestAssignRolesAndDistinctIDs(t *testing.T) {
	p := testPool()
	for i := 0; i < 100; i++ {
		entry, middle, exit, err := p.Assign()
		if err != nil {
			t.Fatalf("assign %d: %v", i, err)
		}
		if entry.Role != string(model.RoleEntry) {
			t.Fatalf("entry role = %q", entry.Role)
		}
		if middle.Role != string(model.RoleMiddle) {
			t.Fatalf("middle role = %q", middle.Role)
		}
		if exit.Role != string(model.RoleExit) {
			t.Fatalf("exit role = %q", exit.Role)
		}
		ids := map[string]bool{entry.ID: true, middle.ID: true, exit.ID: true}
		if len(ids) != 3 {
			t.Fatalf("duplicate ids: %s %s %s", entry.ID, middle.ID, exit.ID)
		}
		if entry.Addr == "" || middle.Addr == "" || exit.Addr == "" {
			t.Fatal("empty addr in assignment")
		}
	}
}

func TestAssignProducesVariety(t *testing.T) {
	p := testPool()
	combos := map[string]bool{}
	for i := 0; i < 200; i++ {
		entry, middle, exit, err := p.Assign()
		if err != nil {
			t.Fatalf("assign: %v", err)
		}
		combos[entry.ID+"|"+middle.ID+"|"+exit.ID] = true
	}
	// 2 entries x 2 middles x 2 exits = 8 combinations. Seeing fewer than 4
	// distinct combinations in 200 draws is effectively impossible.
	if len(combos) < 4 {
		t.Fatalf("only %d distinct combinations in 200 assignments: %v", len(combos), combos)
	}
}

func TestAssignMissingRole(t *testing.T) {
	p := &Pool{Relays: []Relay{
		{ID: "entry-0", Role: "entry", Addr: "127.0.0.1:17101", Identity: "/tmp/e.id"},
		{ID: "middle-0", Role: "middle", Addr: "127.0.0.1:17103", Identity: "/tmp/m.id"},
	}}
	if _, _, _, err := p.Assign(); err == nil {
		t.Fatal("expected error for pool without exit relay")
	}
}

func TestValidateRejectsBadPools(t *testing.T) {
	cases := map[string]*Pool{
		"empty":        {},
		"empty id":     {Relays: []Relay{{Role: "entry", Addr: "127.0.0.1:1", Identity: "/tmp/x"}}},
		"empty addr":   {Relays: []Relay{{ID: "a", Role: "entry", Identity: "/tmp/x"}}},
		"empty ident":  {Relays: []Relay{{ID: "a", Role: "entry", Addr: "127.0.0.1:1"}}},
		"bad role":     {Relays: []Relay{{ID: "a", Role: "gateway", Addr: "127.0.0.1:1", Identity: "/tmp/x"}}},
		"duplicate id": {Relays: []Relay{{ID: "a", Role: "entry", Addr: "127.0.0.1:1", Identity: "/tmp/x"}, {ID: "a", Role: "exit", Addr: "127.0.0.1:2", Identity: "/tmp/y"}}},
	}
	for name, p := range cases {
		if err := p.Validate(); err == nil {
			t.Errorf("%s: expected validation error", name)
		}
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "relays.json")
	want := testPool()
	if err := want.Save(path); err != nil {
		t.Fatalf("save: %v", err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(got.Relays) != len(want.Relays) {
		t.Fatalf("got %d relays, want %d", len(got.Relays), len(want.Relays))
	}
	for i := range want.Relays {
		if got.Relays[i] != want.Relays[i] {
			t.Fatalf("relay %d = %+v, want %+v", i, got.Relays[i], want.Relays[i])
		}
	}
}

func TestLoadBareArray(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "relays.json")
	b, err := json.Marshal(testPool().Relays)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}
	p, err := Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(p.Relays) != 6 {
		t.Fatalf("got %d relays", len(p.Relays))
	}
}

func TestLoadRejectsInvalid(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "relays.json")
	if err := os.WriteFile(path, []byte(`{"relays":[{"id":"x","role":"exit","addr":"127.0.0.1:1","identity":"/tmp/x"},{"id":"x","role":"exit","addr":"127.0.0.1:2","identity":"/tmp/y"}]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("expected duplicate-id error")
	}
}
