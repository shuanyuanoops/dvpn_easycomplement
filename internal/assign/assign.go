// Package assign simulates distributed random circuit assignment.
//
// A circuit has three hops (entry, middle, exit). Instead of one controller
// choosing all three, three independent assignment servers each pick exactly
// one hop. A bulletin board combines the three picks into a ticket, then
// enforces the invariants:
//
//   - the three relay IDs in one circuit are distinct (the board retries on a
//     collision);
//   - the three AS values are pairwise distinct when the pool can provide it
//     (the board retries, then accepts a checked fallback);
//   - the client learns only its entry relay and an opaque circuit token;
//   - a relay can resolve only its adjacent hops, using its own token + ID.
//
// The package is a routing-assignment prototype only. It reuses
// registry.Relay and deliberately does not touch transport, TUN, TLS or chain
// code.
package assign

import (
	crand "crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	mrand "math/rand/v2"
	"sync"

	"dvpn-sim/internal/model"
	"dvpn-sim/internal/registry"
)

// DefaultMaxAttempts is how many independent pick rounds the board tries
// before it accepts a non-AS-distinct fallback.
const DefaultMaxAttempts = 16

// ErrAccessDenied is returned for an unknown circuit token, an unknown relay
// ID, or a relay trying to use another hop's token. It is intentionally the
// same error in every case: a probe must not learn whether a token, a relay or
// a circuit exists.
var ErrAccessDenied = errors.New("assign: circuit token and relay id do not match a known hop")

var hopRoles = [3]model.Role{model.RoleEntry, model.RoleMiddle, model.RoleExit}

func roleIndex(role model.Role) (int, bool) {
	switch role {
	case model.RoleEntry:
		return 0, true
	case model.RoleMiddle:
		return 1, true
	case model.RoleExit:
		return 2, true
	default:
		return 0, false
	}
}

// Directory is the relay registry exposed to the assignment layer. It indexes
// the relays by role and by ID. Identity paths are not required because the
// simulation never opens a transport connection.
type Directory struct {
	all    []registry.Relay
	byRole map[model.Role][]registry.Relay
	byID   map[string]registry.Relay
}

// NewDirectory validates and indexes relays. IDs must be non-empty and unique,
// addresses must be non-empty, and every role must be entry, middle or exit.
func NewDirectory(relays []registry.Relay) (*Directory, error) {
	if len(relays) == 0 {
		return nil, errors.New("assign: relay directory is empty")
	}
	d := &Directory{
		all:    append([]registry.Relay(nil), relays...),
		byRole: make(map[model.Role][]registry.Relay, len(hopRoles)),
		byID:   make(map[string]registry.Relay, len(relays)),
	}
	for i, r := range d.all {
		if r.ID == "" {
			return nil, fmt.Errorf("assign: relay %d: empty id", i)
		}
		if r.Addr == "" {
			return nil, fmt.Errorf("assign: relay %s: empty addr", r.ID)
		}
		role := model.Role(r.Role)
		if _, ok := roleIndex(role); !ok {
			return nil, fmt.Errorf("assign: relay %s: unknown role %q", r.ID, r.Role)
		}
		if _, dup := d.byID[r.ID]; dup {
			return nil, fmt.Errorf("assign: duplicate relay id %q", r.ID)
		}
		d.byID[r.ID] = r
		d.byRole[role] = append(d.byRole[role], r)
	}
	for _, role := range hopRoles {
		if len(d.byRole[role]) == 0 {
			return nil, fmt.Errorf("assign: relay directory has no %s relay", role)
		}
	}
	return d, nil
}

// Len reports how many relays the directory holds.
func (d *Directory) Len() int { return len(d.all) }

// Relays returns a copy of the full relay list.
func (d *Directory) Relays() []registry.Relay {
	return append([]registry.Relay(nil), d.all...)
}

// ByRole returns a copy of the relays registered for role.
func (d *Directory) ByRole(role model.Role) []registry.Relay {
	return append([]registry.Relay(nil), d.byRole[role]...)
}

// Lookup returns the relay registered under id.
func (d *Directory) Lookup(id string) (registry.Relay, bool) {
	r, ok := d.byID[id]
	return r, ok
}

// Server is one independent assignment server. It owns one hop role and a
// private candidate list; it never receives the other servers' choices and
// offers no API that returns them.
//
// Candidates are supplied by the caller. A role-filtered deployment passes
// Directory.ByRole; a stress deployment may pass the whole pool to every
// server so the board has to reject collisions.
type Server struct {
	role       model.Role
	candidates []registry.Relay
	rng        *mrand.Rand
	mu         sync.Mutex
}

// NewServer builds an assignment server for role over a private copy of
// candidates. seed makes the random stream reproducible.
func NewServer(role model.Role, candidates []registry.Relay, seed uint64) (*Server, error) {
	if _, ok := roleIndex(role); !ok {
		return nil, fmt.Errorf("assign: unknown server role %q", role)
	}
	if len(candidates) == 0 {
		return nil, fmt.Errorf("assign: %s server has no candidates", role)
	}
	for i, r := range candidates {
		if r.ID == "" {
			return nil, fmt.Errorf("assign: %s candidate %d: empty id", role, i)
		}
	}
	return &Server{
		role:       role,
		candidates: append([]registry.Relay(nil), candidates...),
		rng:        mrand.New(mrand.NewPCG(seed, seed^0x9e3779b97f4a7c15)),
	}, nil
}

// Role reports which hop this server fills.
func (s *Server) Role() model.Role { return s.role }

// Pick returns one random relay from this server's private candidate list.
func (s *Server) Pick() (registry.Relay, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.candidates) == 0 {
		return registry.Relay{}, fmt.Errorf("assign: %s server has no candidates", s.role)
	}
	return s.candidates[s.rng.IntN(len(s.candidates))], nil
}

// Picker is what the board needs from one assignment server. *Server
// implements it; tests use scripted pickers to force collisions.
type Picker interface {
	Role() model.Role
	Pick() (registry.Relay, error)
}

// ClientView is the complete view a client gets: its entry relay and an opaque
// circuit token. The client presents the token to the entry during circuit
// setup (not modeled here); it is not a relay query credential and cannot
// unlock Neighbors. ClientView has no middle or exit field by construction;
// those hops exist only inside the board's Ticket.
type ClientView struct {
	Entry registry.Relay `json:"entry"`
	Token string         `json:"token"`
}

// Neighbor is one adjacent hop as seen by a relay. Position is the hop's
// position in the circuit (entry, middle or exit), not its advertised role.
type Neighbor struct {
	Position model.Role     `json:"position"`
	Relay    registry.Relay `json:"relay"`
}

// Ticket is the bulletin board's full circuit record. It is not a client or
// relay view: callers hand ClientView to clients and provision each relay with
// the token returned by HopToken.
type Ticket struct {
	Entry      registry.Relay
	Middle     registry.Relay
	Exit       registry.Relay
	Attempts   int  // pick rounds the board spent before accepting this ticket
	ASDistinct bool // entry/middle/exit AS values are non-empty and pairwise distinct

	clientToken string
	hopTokens   [3]string
}

// ClientView returns the restricted client view of the ticket.
func (t Ticket) ClientView() ClientView {
	return ClientView{Entry: t.Entry, Token: t.clientToken}
}

// HopToken returns the private token provisioned to the relay at role. Relays
// need it together with their own ID to query Neighbors.
func (t Ticket) HopToken(role model.Role) (string, bool) {
	i, ok := roleIndex(role)
	if !ok || t.hopTokens[i] == "" {
		return "", false
	}
	return t.hopTokens[i], true
}

// Metrics counts board work. It is filled by Assign.
type Metrics struct {
	Circuits           int // accepted circuits
	Attempts           int // pick rounds, including rejected ones
	DuplicateIDRejects int // rounds rejected because two hops had the same ID
	ASConflictRejects  int // rounds rejected because the three AS values were not pairwise distinct
	ASFallbacks        int // circuits accepted without pairwise-distinct AS after retries
}

type circuit struct {
	entry  registry.Relay
	middle registry.Relay
	exit   registry.Relay
}

type hopRef struct {
	c   *circuit
	pos model.Role
}

// Board is the bulletin board. It asks the three servers for independent
// picks, enforces the circuit invariants by retrying, and stores the resulting
// hop tokens. It never exposes a way to fetch the full path from a token.
type Board struct {
	picks       [3]Picker
	maxAttempts int

	mu      sync.Mutex
	hops    map[string]hopRef   // hop token -> circuit + position (relay query space)
	issued  map[string]struct{} // every token ever issued, hop and client
	metrics Metrics
}

// NewBoard builds a bulletin board from three independent pickers. maxAttempts
// == 0 means DefaultMaxAttempts; a negative value is rejected.
func NewBoard(entry, middle, exit Picker, maxAttempts int) (*Board, error) {
	if entry == nil || middle == nil || exit == nil {
		return nil, errors.New("assign: board needs three pickers")
	}
	picks := [3]Picker{entry, middle, exit}
	for i, want := range hopRoles {
		if got := picks[i].Role(); got != want {
			return nil, fmt.Errorf("assign: picker %d role = %q, want %q", i, got, want)
		}
	}
	if maxAttempts < 0 {
		return nil, errors.New("assign: max attempts must not be negative")
	}
	if maxAttempts == 0 {
		maxAttempts = DefaultMaxAttempts
	}
	return &Board{
		picks:       picks,
		maxAttempts: maxAttempts,
		hops:        make(map[string]hopRef),
		issued:      make(map[string]struct{}),
	}, nil
}

// Assign asks the three servers for one independent pick each. It retries on
// duplicate relay IDs and on AS collisions, accepting the first circuit whose
// IDs are distinct and whose AS values are pairwise distinct. If no
// AS-distinct circuit appears within maxAttempts, the first distinct-ID
// circuit is accepted as a fallback (ASDistinct=false). A fallback is never a
// duplicate-ID circuit: accepted tickets always have three distinct IDs.
func (b *Board) Assign() (Ticket, error) {
	var fallback *Ticket
	for attempt := 1; attempt <= b.maxAttempts; attempt++ {
		entry, err := b.picks[0].Pick()
		if err != nil {
			return Ticket{}, fmt.Errorf("assign: entry pick: %w", err)
		}
		middle, err := b.picks[1].Pick()
		if err != nil {
			return Ticket{}, fmt.Errorf("assign: middle pick: %w", err)
		}
		exit, err := b.picks[2].Pick()
		if err != nil {
			return Ticket{}, fmt.Errorf("assign: exit pick: %w", err)
		}
		if entry.ID == "" || middle.ID == "" || exit.ID == "" {
			return Ticket{}, errors.New("assign: picker returned a relay with an empty id")
		}

		ticket := Ticket{Entry: entry, Middle: middle, Exit: exit, Attempts: attempt}
		if entry.ID == middle.ID || entry.ID == exit.ID || middle.ID == exit.ID {
			b.record(func(m *Metrics) {
				m.Attempts++
				m.DuplicateIDRejects++
			})
			continue
		}
		if pairwiseASDistinct(entry, middle, exit) {
			ticket.ASDistinct = true
			b.record(func(m *Metrics) { m.Attempts++ })
			return b.register(ticket)
		}
		b.record(func(m *Metrics) {
			m.Attempts++
			m.ASConflictRejects++
		})
		if fallback == nil {
			cp := ticket
			fallback = &cp
		}
	}
	if fallback != nil {
		fallback.Attempts = b.maxAttempts
		b.record(func(m *Metrics) { m.ASFallbacks++ })
		return b.register(*fallback)
	}
	return Ticket{}, fmt.Errorf("assign: no circuit with three distinct relay IDs after %d attempts", b.maxAttempts)
}

func (b *Board) record(fn func(*Metrics)) {
	b.mu.Lock()
	fn(&b.metrics)
	b.mu.Unlock()
}

func (b *Board) register(t Ticket) (Ticket, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	c := &circuit{entry: t.Entry, middle: t.Middle, exit: t.Exit}
	var tokens [3]string
	rollback := func(n int) {
		for i := 0; i < n; i++ {
			delete(b.hops, tokens[i])
			delete(b.issued, tokens[i])
		}
	}
	for i, role := range hopRoles {
		tok, err := b.newTokenLocked()
		if err != nil {
			rollback(i)
			return Ticket{}, err
		}
		tokens[i] = tok
		b.issued[tok] = struct{}{}
		b.hops[tok] = hopRef{c: c, pos: role}
	}
	clientToken, err := b.newTokenLocked()
	if err != nil {
		rollback(len(tokens))
		return Ticket{}, err
	}
	b.issued[clientToken] = struct{}{}

	t.clientToken = clientToken
	t.hopTokens = tokens
	b.metrics.Circuits++
	return t, nil
}

// newTokenLocked returns a fresh 128-bit token. The caller must hold b.mu.
func (b *Board) newTokenLocked() (string, error) {
	for i := 0; i < 8; i++ {
		var raw [16]byte
		if _, err := crand.Read(raw[:]); err != nil {
			return "", fmt.Errorf("assign: token: %w", err)
		}
		tok := hex.EncodeToString(raw[:])
		if _, exists := b.issued[tok]; !exists {
			return tok, nil
		}
	}
	return "", errors.New("assign: could not allocate a unique circuit token")
}

// Neighbors returns the adjacent hops of the relay identified by relayID,
// authenticated by its own hop token. Entry has only a next hop, exit has only
// a previous hop, middle has both. The far hop is never returned.
//
// All failures return ErrAccessDenied, so a relay cannot probe other circuits,
// other hops, or whether a token exists.
func (b *Board) Neighbors(token, relayID string) (prev, next *Neighbor, err error) {
	if token == "" || relayID == "" {
		return nil, nil, ErrAccessDenied
	}
	b.mu.Lock()
	ref, ok := b.hops[token]
	b.mu.Unlock()
	if !ok {
		return nil, nil, ErrAccessDenied
	}

	c := ref.c
	var self registry.Relay
	switch ref.pos {
	case model.RoleEntry:
		self = c.entry
	case model.RoleMiddle:
		self = c.middle
	case model.RoleExit:
		self = c.exit
	default:
		return nil, nil, ErrAccessDenied
	}
	if self.ID != relayID {
		return nil, nil, ErrAccessDenied
	}

	switch ref.pos {
	case model.RoleEntry:
		next = &Neighbor{Position: model.RoleMiddle, Relay: c.middle}
	case model.RoleMiddle:
		prev = &Neighbor{Position: model.RoleEntry, Relay: c.entry}
		next = &Neighbor{Position: model.RoleExit, Relay: c.exit}
	case model.RoleExit:
		prev = &Neighbor{Position: model.RoleMiddle, Relay: c.middle}
	}
	return prev, next, nil
}

// Metrics returns a snapshot of the board's counters.
func (b *Board) Metrics() Metrics {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.metrics
}

func pairwiseASDistinct(relays ...registry.Relay) bool {
	for _, r := range relays {
		if r.AS == "" {
			return false
		}
	}
	for i := 0; i < len(relays); i++ {
		for j := i + 1; j < len(relays); j++ {
			if relays[i].AS == relays[j].AS {
				return false
			}
		}
	}
	return true
}
