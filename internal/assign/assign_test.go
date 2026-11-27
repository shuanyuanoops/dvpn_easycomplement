package assign

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"

	"dvpn-sim/internal/model"
	"dvpn-sim/internal/registry"
)

func testRelay(id string, role model.Role, as string) registry.Relay {
	return registry.Relay{
		ID:   id,
		Role: string(role),
		Addr: "10.0.0.1:9000",
		AS:   as,
	}
}

func rolePool() []registry.Relay {
	return []registry.Relay{
		testRelay("entry-0", model.RoleEntry, "AS1"),
		testRelay("entry-1", model.RoleEntry, "AS2"),
		testRelay("middle-0", model.RoleMiddle, "AS3"),
		testRelay("middle-1", model.RoleMiddle, "AS4"),
		testRelay("exit-0", model.RoleExit, "AS5"),
		testRelay("exit-1", model.RoleExit, "AS6"),
	}
}

func flatPool() []registry.Relay {
	return []registry.Relay{
		testRelay("r0", model.RoleEntry, "AS1"),
		testRelay("r1", model.RoleMiddle, "AS2"),
		testRelay("r2", model.RoleExit, "AS3"),
		testRelay("r3", model.RoleEntry, "AS4"),
		testRelay("r4", model.RoleMiddle, "AS5"),
	}
}

func newTestBoard(t *testing.T, relays []registry.Relay, flat bool, seed uint64, maxAttempts int) *Board {
	t.Helper()
	dir, err := NewDirectory(relays)
	if err != nil {
		t.Fatalf("NewDirectory: %v", err)
	}
	entryCandidates := dir.ByRole(model.RoleEntry)
	middleCandidates := dir.ByRole(model.RoleMiddle)
	exitCandidates := dir.ByRole(model.RoleExit)
	if flat {
		all := dir.Relays()
		entryCandidates, middleCandidates, exitCandidates = all, all, all
	}
	entry, err := NewServer(model.RoleEntry, entryCandidates, seed)
	if err != nil {
		t.Fatalf("NewServer(entry): %v", err)
	}
	middle, err := NewServer(model.RoleMiddle, middleCandidates, seed+1)
	if err != nil {
		t.Fatalf("NewServer(middle): %v", err)
	}
	exit, err := NewServer(model.RoleExit, exitCandidates, seed+2)
	if err != nil {
		t.Fatalf("NewServer(exit): %v", err)
	}
	board, err := NewBoard(entry, middle, exit, maxAttempts)
	if err != nil {
		t.Fatalf("NewBoard: %v", err)
	}
	return board
}

func TestDirectoryValidatesAndIndexes(t *testing.T) {
	relays := rolePool()
	dir, err := NewDirectory(relays)
	if err != nil {
		t.Fatalf("NewDirectory: %v", err)
	}
	if dir.Len() != len(relays) {
		t.Fatalf("Len() = %d, want %d", dir.Len(), len(relays))
	}
	for _, role := range hopRoles {
		if got, want := len(dir.ByRole(role)), 2; got != want {
			t.Fatalf("ByRole(%s) = %d, want %d", role, got, want)
		}
	}
	if r, ok := dir.Lookup("middle-1"); !ok || r.Role != string(model.RoleMiddle) {
		t.Fatalf("Lookup(middle-1) = %+v, %v", r, ok)
	}
	if _, ok := dir.Lookup("missing"); ok {
		t.Fatal("Lookup(missing) unexpectedly succeeded")
	}

	// Callers get copies; mutating them must not corrupt the directory.
	all := dir.Relays()
	all[0].ID = "mutated"
	if dir.Relays()[0].ID == "mutated" {
		t.Fatal("Relays() exposed the directory's backing slice")
	}
	entries := dir.ByRole(model.RoleEntry)
	entries[0].ID = "mutated"
	if dir.ByRole(model.RoleEntry)[0].ID == "mutated" {
		t.Fatal("ByRole() exposed the directory's backing slice")
	}
}

func TestDirectoryRejectsBadPools(t *testing.T) {
	cases := map[string][]registry.Relay{
		"empty":         nil,
		"empty id":      {{Role: "entry", Addr: "10.0.0.1:1"}},
		"empty addr":    {{ID: "e", Role: "entry"}},
		"unknown role":  {{ID: "e", Role: "guard", Addr: "10.0.0.1:1"}},
		"duplicate id":  {{ID: "e", Role: "entry", Addr: "10.0.0.1:1"}, {ID: "e", Role: "middle", Addr: "10.0.0.1:2"}},
		"missing roles": {{ID: "e", Role: "entry", Addr: "10.0.0.1:1"}},
	}
	for name, relays := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := NewDirectory(relays); err == nil {
				t.Fatal("NewDirectory unexpectedly succeeded")
			}
		})
	}
}

func TestServerPicksOnlyFromItsPrivateCandidates(t *testing.T) {
	entries := []registry.Relay{
		testRelay("entry-0", model.RoleEntry, "AS1"),
		testRelay("entry-1", model.RoleEntry, "AS2"),
		testRelay("entry-2", model.RoleEntry, "AS3"),
	}
	middles := []registry.Relay{
		testRelay("middle-0", model.RoleMiddle, "AS4"),
		testRelay("middle-1", model.RoleMiddle, "AS5"),
	}
	server, err := NewServer(model.RoleEntry, entries, 7)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	if got := server.Role(); got != model.RoleEntry {
		t.Fatalf("Role() = %s", got)
	}
	allowed := map[string]bool{"entry-0": true, "entry-1": true, "entry-2": true}
	for i := 0; i < 300; i++ {
		r, err := server.Pick()
		if err != nil {
			t.Fatalf("Pick %d: %v", i, err)
		}
		if !allowed[r.ID] {
			t.Fatalf("Pick %d = %s, not in the server's candidate list", i, r.ID)
		}
	}

	// The server must hold a copy: mutating the caller's slice cannot widen or
	// redirect what this server can see.
	entries[0] = middles[0]
	for i := 0; i < 300; i++ {
		r, err := server.Pick()
		if err != nil {
			t.Fatalf("Pick after mutation %d: %v", i, err)
		}
		if r.ID == "middle-0" {
			t.Fatal("server observed a candidate injected into the caller's slice")
		}
	}

	if _, err := NewServer("guard", entries, 1); err == nil {
		t.Fatal("NewServer accepted an unknown role")
	}
	if _, err := NewServer(model.RoleEntry, nil, 1); err == nil {
		t.Fatal("NewServer accepted an empty candidate list")
	}
	if _, err := NewServer(model.RoleEntry, []registry.Relay{{Role: "entry"}}, 1); err == nil {
		t.Fatal("NewServer accepted a candidate with an empty id")
	}
}

func TestClientViewExposesOnlyEntryAndToken(t *testing.T) {
	typ := reflect.TypeOf(ClientView{})
	if got, want := typ.NumField(), 2; got != want {
		t.Fatalf("ClientView has %d fields, want %d", got, want)
	}
	fields := map[string]bool{}
	for i := 0; i < typ.NumField(); i++ {
		name := typ.Field(i).Name
		lower := strings.ToLower(name)
		if strings.Contains(lower, "middle") || strings.Contains(lower, "exit") {
			t.Fatalf("ClientView exposes forbidden field %q", name)
		}
		fields[name] = true
	}
	if !fields["Entry"] || !fields["Token"] {
		t.Fatalf("ClientView fields = %v, want Entry and Token", fields)
	}

	board := newTestBoard(t, rolePool(), false, 11, 16)
	ticket, err := board.Assign()
	if err != nil {
		t.Fatalf("Assign: %v", err)
	}
	view := ticket.ClientView()
	if view.Entry.ID != ticket.Entry.ID {
		t.Fatalf("client entry = %s, want %s", view.Entry.ID, ticket.Entry.ID)
	}
	if view.Token == "" {
		t.Fatal("client token is empty")
	}
	if entryToken, _ := ticket.HopToken(model.RoleEntry); view.Token == entryToken {
		t.Fatal("client token must not be the entry relay's hop token")
	}

	// The serialized client view must not grow middle/exit keys by accident,
	// and it must not carry the middle or exit relay IDs.
	raw, err := json.Marshal(view)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if strings.Contains(string(raw), ticket.Middle.ID) || strings.Contains(string(raw), ticket.Exit.ID) {
		t.Fatalf("client view leaks a non-entry relay: %s", raw)
	}
	var decoded map[string]json.RawMessage
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if len(decoded) != 2 {
		t.Fatalf("client JSON keys = %v, want entry and token", decoded)
	}
	for key := range decoded {
		lower := strings.ToLower(key)
		if strings.Contains(lower, "middle") || strings.Contains(lower, "exit") {
			t.Fatalf("client JSON exposes forbidden key %q", key)
		}
	}

	// A client holding its circuit token must not be able to query a relay's
	// neighbors with the entry ID.
	if _, _, err := board.Neighbors(view.Token, ticket.Entry.ID); !errors.Is(err, ErrAccessDenied) {
		t.Fatalf("client token used as relay token: err = %v, want ErrAccessDenied", err)
	}
}

func TestRelaySeesOnlyAdjacentHops(t *testing.T) {
	board := newTestBoard(t, rolePool(), false, 3, 16)
	ticket, err := board.Assign()
	if err != nil {
		t.Fatalf("Assign: %v", err)
	}
	if ticket.Entry.ID == ticket.Middle.ID || ticket.Entry.ID == ticket.Exit.ID || ticket.Middle.ID == ticket.Exit.ID {
		t.Fatalf("duplicate hops in ticket: %+v", ticket)
	}

	entryToken, ok := ticket.HopToken(model.RoleEntry)
	if !ok {
		t.Fatal("entry hop token missing")
	}
	middleToken, ok := ticket.HopToken(model.RoleMiddle)
	if !ok {
		t.Fatal("middle hop token missing")
	}
	exitToken, ok := ticket.HopToken(model.RoleExit)
	if !ok {
		t.Fatal("exit hop token missing")
	}

	prev, next, err := board.Neighbors(entryToken, ticket.Entry.ID)
	if err != nil {
		t.Fatalf("entry Neighbors: %v", err)
	}
	if prev != nil {
		t.Fatalf("entry has a previous hop: %+v", prev)
	}
	if next == nil || next.Position != model.RoleMiddle || next.Relay.ID != ticket.Middle.ID {
		t.Fatalf("entry next = %+v, want middle %s", next, ticket.Middle.ID)
	}
	if next.Relay.ID == ticket.Exit.ID {
		t.Fatal("entry learned the exit hop")
	}

	prev, next, err = board.Neighbors(middleToken, ticket.Middle.ID)
	if err != nil {
		t.Fatalf("middle Neighbors: %v", err)
	}
	if prev == nil || prev.Position != model.RoleEntry || prev.Relay.ID != ticket.Entry.ID {
		t.Fatalf("middle prev = %+v, want entry %s", prev, ticket.Entry.ID)
	}
	if next == nil || next.Position != model.RoleExit || next.Relay.ID != ticket.Exit.ID {
		t.Fatalf("middle next = %+v, want exit %s", next, ticket.Exit.ID)
	}

	prev, next, err = board.Neighbors(exitToken, ticket.Exit.ID)
	if err != nil {
		t.Fatalf("exit Neighbors: %v", err)
	}
	if next != nil {
		t.Fatalf("exit has a next hop: %+v", next)
	}
	if prev == nil || prev.Position != model.RoleMiddle || prev.Relay.ID != ticket.Middle.ID {
		t.Fatalf("exit prev = %+v, want middle %s", prev, ticket.Middle.ID)
	}
	if prev.Relay.ID == ticket.Entry.ID {
		t.Fatal("exit learned the entry hop")
	}

	other, err := board.Assign()
	if err != nil {
		t.Fatalf("second Assign: %v", err)
	}
	otherEntryToken, _ := other.HopToken(model.RoleEntry)

	denied := []struct {
		name  string
		token string
		id    string
	}{
		{"entry token with middle id", entryToken, ticket.Middle.ID},
		{"middle token with entry id", middleToken, ticket.Entry.ID},
		{"exit token with middle id", exitToken, ticket.Middle.ID},
		{"client token with entry id", ticket.ClientView().Token, ticket.Entry.ID},
		{"unknown token", "deadbeef", ticket.Entry.ID},
		{"unknown relay id", entryToken, "no-such-relay"},
		{"empty token", "", ticket.Entry.ID},
		{"empty id", entryToken, ""},
		{"other circuit's token", otherEntryToken, ticket.Entry.ID},
	}
	for _, tc := range denied {
		t.Run(tc.name, func(t *testing.T) {
			prev, next, err := board.Neighbors(tc.token, tc.id)
			if !errors.Is(err, ErrAccessDenied) {
				t.Fatalf("Neighbors(%q, %q) err = %v, want ErrAccessDenied", tc.token, tc.id, err)
			}
			if prev != nil || next != nil {
				t.Fatalf("denied query leaked neighbors: prev=%+v next=%+v", prev, next)
			}
		})
	}
}

func TestAssignKeepsHopsDistinct(t *testing.T) {
	t.Run("role candidates", func(t *testing.T) {
		board := newTestBoard(t, rolePool(), false, 5, 16)
		for i := 0; i < 400; i++ {
			ticket, err := board.Assign()
			if err != nil {
				t.Fatalf("Assign %d: %v", i, err)
			}
			ids := map[string]bool{ticket.Entry.ID: true, ticket.Middle.ID: true, ticket.Exit.ID: true}
			if len(ids) != 3 {
				t.Fatalf("Assign %d produced duplicate hops: %s %s %s",
					i, ticket.Entry.ID, ticket.Middle.ID, ticket.Exit.ID)
			}
			if !ticket.ASDistinct {
				t.Fatalf("Assign %d did not reach AS diversity with six distinct AS values", i)
			}
		}
		if got := board.Metrics().Circuits; got != 400 {
			t.Fatalf("Circuits = %d, want 400", got)
		}
	})

	t.Run("overlapping candidates", func(t *testing.T) {
		board := newTestBoard(t, flatPool(), true, 5, 16)
		tickets := make([]Ticket, 0, 400)
		for i := 0; i < 400; i++ {
			ticket, err := board.Assign()
			if err != nil {
				t.Fatalf("Assign %d: %v", i, err)
			}
			ids := map[string]bool{ticket.Entry.ID: true, ticket.Middle.ID: true, ticket.Exit.ID: true}
			if len(ids) != 3 {
				t.Fatalf("Assign %d produced duplicate hops: %s %s %s",
					i, ticket.Entry.ID, ticket.Middle.ID, ticket.Exit.ID)
			}
			tickets = append(tickets, ticket)
		}
		metrics := board.Metrics()
		if metrics.Circuits != 400 {
			t.Fatalf("Circuits = %d, want 400", metrics.Circuits)
		}
		if metrics.DuplicateIDRejects == 0 {
			t.Fatal("overlapping pools never triggered a duplicate-ID retry")
		}
		// Every accepted circuit still has a unique client token and three
		// distinct hop tokens.
		clientTokens := map[string]bool{}
		for _, ticket := range tickets {
			view := ticket.ClientView()
			if clientTokens[view.Token] {
				t.Fatalf("duplicate client token %q", view.Token)
			}
			clientTokens[view.Token] = true
			hopTokens := map[string]bool{}
			for _, role := range hopRoles {
				token, ok := ticket.HopToken(role)
				if !ok || token == "" {
					t.Fatalf("missing %s hop token", role)
				}
				if hopTokens[token] {
					t.Fatalf("duplicate hop token %q", token)
				}
				hopTokens[token] = true
			}
		}
	})
}

// scriptPicker serves a fixed sequence and then repeats its last pick. It lets
// the tests force a duplicate-ID or AS-collision round deterministically.
type scriptPicker struct {
	role  model.Role
	picks []registry.Relay
	i     int
}

func (p *scriptPicker) Role() model.Role { return p.role }

func (p *scriptPicker) Pick() (registry.Relay, error) {
	if len(p.picks) == 0 {
		return registry.Relay{}, errors.New("scriptPicker: no picks")
	}
	if p.i >= len(p.picks) {
		return p.picks[len(p.picks)-1], nil
	}
	r := p.picks[p.i]
	p.i++
	return r, nil
}

func newScriptBoard(t *testing.T, entry, middle, exit Picker, maxAttempts int) *Board {
	t.Helper()
	board, err := NewBoard(entry, middle, exit, maxAttempts)
	if err != nil {
		t.Fatalf("NewBoard: %v", err)
	}
	return board
}

func TestAssignRetriesDuplicateIDs(t *testing.T) {
	e := testRelay("e", model.RoleEntry, "AS1")
	m := testRelay("m", model.RoleMiddle, "AS2")
	x := testRelay("x", model.RoleExit, "AS3")

	entry := &scriptPicker{role: model.RoleEntry, picks: []registry.Relay{e}}
	middle := &scriptPicker{role: model.RoleMiddle, picks: []registry.Relay{e, m}}
	exit := &scriptPicker{role: model.RoleExit, picks: []registry.Relay{x}}
	board := newScriptBoard(t, entry, middle, exit, 16)

	ticket, err := board.Assign()
	if err != nil {
		t.Fatalf("Assign: %v", err)
	}
	if ticket.Attempts != 2 {
		t.Fatalf("Attempts = %d, want 2", ticket.Attempts)
	}
	if ticket.Middle.ID != "m" {
		t.Fatalf("middle = %s, want m", ticket.Middle.ID)
	}
	metrics := board.Metrics()
	if metrics.DuplicateIDRejects != 1 {
		t.Fatalf("DuplicateIDRejects = %d, want 1", metrics.DuplicateIDRejects)
	}
	if metrics.Attempts != 2 || metrics.Circuits != 1 {
		t.Fatalf("metrics = %+v, want 2 attempts and 1 circuit", metrics)
	}
}

func TestAssignRetriesASConflicts(t *testing.T) {
	e := testRelay("e", model.RoleEntry, "AS1")
	m1 := testRelay("m1", model.RoleMiddle, "AS1")
	m2 := testRelay("m2", model.RoleMiddle, "AS2")
	x1 := testRelay("x1", model.RoleExit, "AS1")
	x2 := testRelay("x2", model.RoleExit, "AS3")

	entry := &scriptPicker{role: model.RoleEntry, picks: []registry.Relay{e}}
	middle := &scriptPicker{role: model.RoleMiddle, picks: []registry.Relay{m1, m2}}
	exit := &scriptPicker{role: model.RoleExit, picks: []registry.Relay{x1, x2}}
	board := newScriptBoard(t, entry, middle, exit, 16)

	ticket, err := board.Assign()
	if err != nil {
		t.Fatalf("Assign: %v", err)
	}
	if ticket.Attempts != 2 || !ticket.ASDistinct {
		t.Fatalf("ticket = %+v, want 2 attempts and ASDistinct", ticket)
	}
	metrics := board.Metrics()
	if metrics.ASConflictRejects != 1 || metrics.Attempts != 2 {
		t.Fatalf("metrics = %+v, want 1 AS conflict in 2 attempts", metrics)
	}
	if metrics.ASFallbacks != 0 {
		t.Fatalf("ASFallbacks = %d, want 0", metrics.ASFallbacks)
	}
}

func TestAssignFallsBackWhenASDiversityIsImpossible(t *testing.T) {
	e := testRelay("e", model.RoleEntry, "AS1")
	m := testRelay("m", model.RoleMiddle, "AS1")
	x := testRelay("x", model.RoleExit, "AS1")

	board := newScriptBoard(t,
		&scriptPicker{role: model.RoleEntry, picks: []registry.Relay{e}},
		&scriptPicker{role: model.RoleMiddle, picks: []registry.Relay{m}},
		&scriptPicker{role: model.RoleExit, picks: []registry.Relay{x}},
		3,
	)
	ticket, err := board.Assign()
	if err != nil {
		t.Fatalf("Assign: %v", err)
	}
	if ticket.ASDistinct {
		t.Fatal("ticket claims AS diversity when every relay shares one AS")
	}
	if ticket.Attempts != 3 {
		t.Fatalf("Attempts = %d, want 3", ticket.Attempts)
	}
	metrics := board.Metrics()
	if metrics.ASConflictRejects != 3 || metrics.ASFallbacks != 1 || metrics.Circuits != 1 {
		t.Fatalf("metrics = %+v, want 3 conflicts, 1 fallback, 1 circuit", metrics)
	}
	// The fallback still must not duplicate IDs.
	if ticket.Entry.ID == ticket.Middle.ID || ticket.Entry.ID == ticket.Exit.ID || ticket.Middle.ID == ticket.Exit.ID {
		t.Fatalf("fallback ticket has duplicate hops: %+v", ticket)
	}
}

func TestAssignFailsWhenEveryRoundDuplicates(t *testing.T) {
	e := testRelay("e", model.RoleEntry, "AS1")
	x := testRelay("x", model.RoleExit, "AS2")

	board := newScriptBoard(t,
		&scriptPicker{role: model.RoleEntry, picks: []registry.Relay{e}},
		&scriptPicker{role: model.RoleMiddle, picks: []registry.Relay{e}},
		&scriptPicker{role: model.RoleExit, picks: []registry.Relay{x}},
		4,
	)
	if _, err := board.Assign(); err == nil {
		t.Fatal("Assign succeeded with only duplicate-ID rounds")
	}
	metrics := board.Metrics()
	if metrics.DuplicateIDRejects != 4 || metrics.Circuits != 0 {
		t.Fatalf("metrics = %+v, want 4 duplicate rejects and no circuit", metrics)
	}
}

func TestNewBoardValidatesPickers(t *testing.T) {
	e := testRelay("e", model.RoleEntry, "AS1")
	m := testRelay("m", model.RoleMiddle, "AS2")
	x := testRelay("x", model.RoleExit, "AS3")
	entry := &scriptPicker{role: model.RoleEntry, picks: []registry.Relay{e}}
	middle := &scriptPicker{role: model.RoleMiddle, picks: []registry.Relay{m}}
	exit := &scriptPicker{role: model.RoleExit, picks: []registry.Relay{x}}

	if _, err := NewBoard(nil, middle, exit, 1); err == nil {
		t.Fatal("NewBoard accepted a nil picker")
	}
	if _, err := NewBoard(middle, entry, exit, 1); err == nil {
		t.Fatal("NewBoard accepted pickers in the wrong role order")
	}
	if _, err := NewBoard(entry, middle, exit, -1); err == nil {
		t.Fatal("NewBoard accepted a negative attempt budget")
	}
	board, err := NewBoard(entry, middle, exit, 0)
	if err != nil {
		t.Fatalf("NewBoard with default attempts: %v", err)
	}
	if board.maxAttempts != DefaultMaxAttempts {
		t.Fatalf("maxAttempts = %d, want %d", board.maxAttempts, DefaultMaxAttempts)
	}
}

func TestAssignConcurrent(t *testing.T) {
	board := newTestBoard(t, rolePool(), false, 21, 16)
	const clients = 120

	var wg sync.WaitGroup
	tickets := make(chan Ticket, clients)
	errs := make(chan error, clients)
	for i := 0; i < clients; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ticket, err := board.Assign()
			if err != nil {
				errs <- err
				return
			}
			tickets <- ticket
		}()
	}
	wg.Wait()
	close(tickets)
	close(errs)

	for err := range errs {
		t.Fatalf("concurrent Assign: %v", err)
	}
	clientTokens := map[string]bool{}
	for ticket := range tickets {
		ids := map[string]bool{ticket.Entry.ID: true, ticket.Middle.ID: true, ticket.Exit.ID: true}
		if len(ids) != 3 {
			t.Fatalf("concurrent ticket has duplicate hops: %+v", ticket)
		}
		token := ticket.ClientView().Token
		if clientTokens[token] {
			t.Fatalf("duplicate client token %q", token)
		}
		clientTokens[token] = true
	}
	if got := board.Metrics().Circuits; got != clients {
		t.Fatalf("Circuits = %d, want %d", got, clients)
	}
}
