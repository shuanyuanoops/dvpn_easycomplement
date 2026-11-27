// Command assignsim runs the distributed random circuit-assignment prototype.
//
// It builds a simulated relay registry, gives one role-filtered (or, with
// -candidates flat, a deliberately overlapping) candidate list to each of the
// three independent assignment servers, then assigns circuits for many clients
// and prints the aggregate statistics:
//
//   - path diversity;
//   - how often every relay was selected;
//   - AS distribution;
//   - three-hop duplicate rate, both final and rejected-before-ticket.
//
// The command only exercises internal/assign. It does not start relays,
// transports, TUN devices, TLS or chains.
package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"reflect"
	"sort"
	"strings"

	"dvpn-sim/internal/assign"
	"dvpn-sim/internal/model"
	"dvpn-sim/internal/registry"
)

var hopRoles = [3]model.Role{model.RoleEntry, model.RoleMiddle, model.RoleExit}

type config struct {
	relays      int
	clients     int
	asCount     int
	seed        uint64
	candidates  string // "role" (role-filtered pools) or "flat" (all relays eligible)
	maxAttempts int
}

func (c config) validate() error {
	if c.relays < 3 {
		return fmt.Errorf("assignsim: -relays must be at least 3, got %d", c.relays)
	}
	if c.clients < 1 {
		return fmt.Errorf("assignsim: -clients must be positive, got %d", c.clients)
	}
	if c.asCount < 1 {
		return fmt.Errorf("assignsim: -as must be positive, got %d", c.asCount)
	}
	if c.maxAttempts < 1 {
		return fmt.Errorf("assignsim: -max-attempts must be positive, got %d", c.maxAttempts)
	}
	switch c.candidates {
	case "role", "flat":
	default:
		return fmt.Errorf("assignsim: -candidates must be role or flat, got %q", c.candidates)
	}
	return nil
}

type relayPick struct {
	id    string
	picks int
}

type asPick struct {
	as     string
	relays int
	picks  int
}

type pathPick struct {
	path  string
	count int
}

type report struct {
	cfg config

	assigned        int
	metrics         assign.Metrics
	maxAttemptsUsed int

	distinctPaths int
	topPaths      []pathPick

	relayPicks []relayPick // every relay, sorted by ID
	topRelays  []relayPick // five most-selected relays
	coldRelays int
	minPicks   int
	maxPicks   int
	meanPicks  float64

	asPicks []asPick // every AS, sorted by AS name
	asSeen  int

	asDistinct        int
	duplicateCircuits int
	neighborChecks    int
	clientFields      []string
}

func main() {
	cfg := config{}
	flag.IntVar(&cfg.relays, "relays", 100, "number of simulated relays")
	flag.IntVar(&cfg.clients, "clients", 1000, "number of clients to assign")
	flag.IntVar(&cfg.asCount, "as", 10, "number of simulated ASes")
	flag.Uint64Var(&cfg.seed, "seed", 1, "random seed for the assignment servers")
	flag.StringVar(&cfg.candidates, "candidates", "role",
		"candidate pools: role (filtered by entry/middle/exit) or flat (all relays eligible for every hop)")
	flag.IntVar(&cfg.maxAttempts, "max-attempts", assign.DefaultMaxAttempts,
		"pick rounds before accepting an AS-diverse fallback")
	flag.Parse()

	rep, err := simulate(cfg)
	if err != nil {
		log.Fatalf("assignsim: %v", err)
	}
	if err := rep.print(os.Stdout); err != nil {
		log.Fatalf("assignsim: print: %v", err)
	}
}

// buildRelays creates a deterministic simulated registry. Roles and ASes are
// interleaved, so every role pool contains several ASes.
func buildRelays(n, asCount int) []registry.Relay {
	relays := make([]registry.Relay, 0, n)
	for i := 0; i < n; i++ {
		role := hopRoles[i%len(hopRoles)]
		relays = append(relays, registry.Relay{
			ID:   fmt.Sprintf("%s-%03d", role, i/len(hopRoles)),
			Role: string(role),
			Addr: fmt.Sprintf("10.10.%d.%d:51820", i/250, i%250+1),
			AS:   fmt.Sprintf("AS%d", 64496+i%asCount),
		})
	}
	return relays
}

func candidateSets(dir *assign.Directory, mode string) (entry, middle, exit []registry.Relay, err error) {
	switch mode {
	case "role":
		return dir.ByRole(model.RoleEntry),
			dir.ByRole(model.RoleMiddle),
			dir.ByRole(model.RoleExit),
			nil
	case "flat":
		all := dir.Relays()
		return all, all, all, nil
	default:
		return nil, nil, nil, fmt.Errorf("assignsim: unknown candidate mode %q", mode)
	}
}

func simulate(cfg config) (*report, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	relays := buildRelays(cfg.relays, cfg.asCount)
	dir, err := assign.NewDirectory(relays)
	if err != nil {
		return nil, err
	}
	entryCandidates, middleCandidates, exitCandidates, err := candidateSets(dir, cfg.candidates)
	if err != nil {
		return nil, err
	}
	entryServer, err := assign.NewServer(model.RoleEntry, entryCandidates, cfg.seed)
	if err != nil {
		return nil, err
	}
	middleServer, err := assign.NewServer(model.RoleMiddle, middleCandidates, cfg.seed+1)
	if err != nil {
		return nil, err
	}
	exitServer, err := assign.NewServer(model.RoleExit, exitCandidates, cfg.seed+2)
	if err != nil {
		return nil, err
	}
	board, err := assign.NewBoard(entryServer, middleServer, exitServer, cfg.maxAttempts)
	if err != nil {
		return nil, err
	}

	fields, err := clientViewFields()
	if err != nil {
		return nil, err
	}
	rep := &report{cfg: cfg, clientFields: fields}

	relayPicks := make(map[string]int, len(relays))
	asRelayCount := make(map[string]int)
	asPicks := make(map[string]int)
	for _, r := range relays {
		relayPicks[r.ID] = 0
		asRelayCount[r.AS]++
		asPicks[r.AS] = 0
	}
	pathCounts := make(map[string]int)

	for client := 0; client < cfg.clients; client++ {
		// The simulator plays the bulletin-board operator here: it receives
		// the full ticket so it can collect statistics and provision each
		// relay with its hop token. The client itself only gets the restricted
		// view built below.
		ticket, err := board.Assign()
		if err != nil {
			return nil, fmt.Errorf("assignsim: client %d: %w", client, err)
		}
		rep.assigned++
		if ticket.ASDistinct {
			rep.asDistinct++
		}
		if ticket.Attempts > rep.maxAttemptsUsed {
			rep.maxAttemptsUsed = ticket.Attempts
		}
		if ticket.Entry.ID == ticket.Middle.ID ||
			ticket.Entry.ID == ticket.Exit.ID ||
			ticket.Middle.ID == ticket.Exit.ID {
			rep.duplicateCircuits++
		}

		path := ticket.Entry.ID + ">" + ticket.Middle.ID + ">" + ticket.Exit.ID
		pathCounts[path]++
		for _, r := range []registry.Relay{ticket.Entry, ticket.Middle, ticket.Exit} {
			relayPicks[r.ID]++
			asPicks[r.AS]++
		}

		view := ticket.ClientView()
		if view.Entry.ID != ticket.Entry.ID || view.Token == "" {
			return nil, fmt.Errorf("assignsim: client %d got a malformed client view", client)
		}
		for _, role := range hopRoles {
			token, ok := ticket.HopToken(role)
			if !ok {
				return nil, fmt.Errorf("assignsim: client %d: missing %s hop token", client, role)
			}
			self, ok := relayForTicket(ticket, role)
			if !ok {
				return nil, fmt.Errorf("assignsim: client %d: unknown hop role %q", client, role)
			}
			prev, next, err := board.Neighbors(token, self.ID)
			if err != nil {
				return nil, fmt.Errorf("assignsim: client %d: %s neighbor lookup: %w", client, role, err)
			}
			if err := checkNeighbors(role, ticket, prev, next); err != nil {
				return nil, fmt.Errorf("assignsim: client %d: %w", client, err)
			}
			rep.neighborChecks++
		}
		// The client's circuit token is not a relay token: it must not unlock
		// neighbor information.
		if _, _, err := board.Neighbors(view.Token, ticket.Entry.ID); !errors.Is(err, assign.ErrAccessDenied) {
			return nil, fmt.Errorf("assignsim: client %d: client token gave neighbor access", client)
		}
	}

	rep.metrics = board.Metrics()
	if rep.metrics.Circuits != cfg.clients {
		return nil, fmt.Errorf("assignsim: board recorded %d circuits, want %d", rep.metrics.Circuits, cfg.clients)
	}

	rep.distinctPaths = len(pathCounts)
	paths := make([]pathPick, 0, len(pathCounts))
	for path, count := range pathCounts {
		paths = append(paths, pathPick{path: path, count: count})
	}
	sort.Slice(paths, func(i, j int) bool {
		if paths[i].count != paths[j].count {
			return paths[i].count > paths[j].count
		}
		return paths[i].path < paths[j].path
	})
	if len(paths) > 5 {
		paths = paths[:5]
	}
	rep.topPaths = paths

	totalPicks := 3 * rep.assigned
	if totalPicks == 0 {
		return nil, errors.New("assignsim: no hop selections recorded")
	}
	rep.relayPicks = make([]relayPick, 0, len(relays))
	for _, r := range relays {
		rep.relayPicks = append(rep.relayPicks, relayPick{
			id:    r.ID,
			picks: relayPicks[r.ID],
		})
	}
	sort.Slice(rep.relayPicks, func(i, j int) bool { return rep.relayPicks[i].id < rep.relayPicks[j].id })

	rep.minPicks = -1
	sumPicks := 0
	for _, rp := range rep.relayPicks {
		sumPicks += rp.picks
		if rep.minPicks == -1 || rp.picks < rep.minPicks {
			rep.minPicks = rp.picks
		}
		if rp.picks > rep.maxPicks {
			rep.maxPicks = rp.picks
		}
		if rp.picks == 0 {
			rep.coldRelays++
		}
	}
	if rep.minPicks == -1 {
		rep.minPicks = 0
	}
	if sumPicks != totalPicks {
		return nil, fmt.Errorf("assignsim: relay picks sum to %d, want %d", sumPicks, totalPicks)
	}
	rep.meanPicks = float64(sumPicks) / float64(len(rep.relayPicks))

	topRelays := append([]relayPick(nil), rep.relayPicks...)
	sort.Slice(topRelays, func(i, j int) bool {
		if topRelays[i].picks != topRelays[j].picks {
			return topRelays[i].picks > topRelays[j].picks
		}
		return topRelays[i].id < topRelays[j].id
	})
	if len(topRelays) > 5 {
		topRelays = topRelays[:5]
	}
	rep.topRelays = topRelays

	rep.asPicks = make([]asPick, 0, len(asRelayCount))
	sumAS := 0
	for as, relayCount := range asRelayCount {
		picks := asPicks[as]
		sumAS += picks
		if picks > 0 {
			rep.asSeen++
		}
		rep.asPicks = append(rep.asPicks, asPick{as: as, relays: relayCount, picks: picks})
	}
	sort.Slice(rep.asPicks, func(i, j int) bool { return rep.asPicks[i].as < rep.asPicks[j].as })
	if sumAS != totalPicks {
		return nil, fmt.Errorf("assignsim: AS picks sum to %d, want %d", sumAS, totalPicks)
	}

	return rep, nil
}

func clientViewFields() ([]string, error) {
	typ := reflect.TypeOf(assign.ClientView{})
	fields := make([]string, 0, typ.NumField())
	for i := 0; i < typ.NumField(); i++ {
		name := typ.Field(i).Name
		lower := strings.ToLower(name)
		if strings.Contains(lower, "middle") || strings.Contains(lower, "exit") {
			return nil, fmt.Errorf("assignsim: client view exposes forbidden field %q", name)
		}
		fields = append(fields, lower)
	}
	if len(fields) != 2 {
		return nil, fmt.Errorf("assignsim: client view has %d fields, want entry and token", len(fields))
	}
	return fields, nil
}

func relayForTicket(ticket assign.Ticket, role model.Role) (registry.Relay, bool) {
	switch role {
	case model.RoleEntry:
		return ticket.Entry, true
	case model.RoleMiddle:
		return ticket.Middle, true
	case model.RoleExit:
		return ticket.Exit, true
	default:
		return registry.Relay{}, false
	}
}

// checkNeighbors verifies that a relay only sees its immediate circuit
// neighbors and never the far hop.
func checkNeighbors(role model.Role, ticket assign.Ticket, prev, next *assign.Neighbor) error {
	switch role {
	case model.RoleEntry:
		if prev != nil {
			return fmt.Errorf("entry saw a previous hop: %+v", prev)
		}
		if next == nil || next.Position != model.RoleMiddle || next.Relay.ID != ticket.Middle.ID {
			return fmt.Errorf("entry next = %+v, want middle %s", next, ticket.Middle.ID)
		}
	case model.RoleMiddle:
		if prev == nil || prev.Position != model.RoleEntry || prev.Relay.ID != ticket.Entry.ID {
			return fmt.Errorf("middle prev = %+v, want entry %s", prev, ticket.Entry.ID)
		}
		if next == nil || next.Position != model.RoleExit || next.Relay.ID != ticket.Exit.ID {
			return fmt.Errorf("middle next = %+v, want exit %s", next, ticket.Exit.ID)
		}
	case model.RoleExit:
		if prev == nil || prev.Position != model.RoleMiddle || prev.Relay.ID != ticket.Middle.ID {
			return fmt.Errorf("exit prev = %+v, want middle %s", prev, ticket.Middle.ID)
		}
		if next != nil {
			return fmt.Errorf("exit saw a next hop: %+v", next)
		}
	default:
		return fmt.Errorf("unknown hop role %q", role)
	}
	return nil
}

func percent(n, d int) float64 {
	if d == 0 {
		return 0
	}
	return 100 * float64(n) / float64(d)
}

func (r *report) print(w io.Writer) error {
	bw := bufio.NewWriter(w)
	var err error
	printf := func(format string, args ...any) {
		if err != nil {
			return
		}
		_, err = fmt.Fprintf(bw, format, args...)
	}

	totalPicks := 3 * r.assigned
	avgAttempts := 0.0
	if r.metrics.Circuits > 0 {
		avgAttempts = float64(r.metrics.Attempts) / float64(r.metrics.Circuits)
	}

	printf("distributed random circuit assignment (simulation)\n")
	printf("  relays=%d clients=%d ASes=%d candidates=%s seed=%d max_attempts=%d\n\n",
		r.cfg.relays, r.cfg.clients, r.cfg.asCount, r.cfg.candidates, r.cfg.seed, r.cfg.maxAttempts)

	printf("assignment\n")
	printf("  %-26s %d\n", "circuits assigned", r.assigned)
	printf("  %-26s %d (avg %.2f per circuit, max %d)\n",
		"board attempts", r.metrics.Attempts, avgAttempts, r.maxAttemptsUsed)
	printf("  %-26s %d\n", "duplicate-ID retries", r.metrics.DuplicateIDRejects)
	printf("  %-26s %d\n", "AS-collision retries", r.metrics.ASConflictRejects)
	printf("  %-26s %d\n", "AS fallbacks", r.metrics.ASFallbacks)
	switch r.cfg.candidates {
	case "role":
		printf("  note: role pools are ID-disjoint; flat mode exercises duplicate-ID retries\n\n")
	case "flat":
		printf("  note: flat pools overlap by design; duplicate-ID retries are expected\n\n")
	default:
		printf("\n")
	}

	printf("path diversity\n")
	printf("  %-26s %d / %d (%.2f%%)\n", "distinct paths",
		r.distinctPaths, r.assigned, percent(r.distinctPaths, r.assigned))
	printf("  %-26s %d / %d (%.2f%%)\n", "repeated paths",
		r.assigned-r.distinctPaths, r.assigned, percent(r.assigned-r.distinctPaths, r.assigned))
	printf("  top paths\n")
	for i, p := range r.topPaths {
		printf("    %d. %s  x%d\n", i+1, p.path, p.count)
	}
	printf("\n")

	printf("relay coverage (%d hop selections)\n", totalPicks)
	printf("  %-26s %d / %d (%d cold)\n",
		"relays selected", len(r.relayPicks)-r.coldRelays, len(r.relayPicks), r.coldRelays)
	printf("  %-26s min=%d max=%d mean=%.2f\n",
		"picks per relay", r.minPicks, r.maxPicks, r.meanPicks)
	printf("  %-26s", "top relays")
	for i, rp := range r.topRelays {
		if i > 0 {
			printf(", ")
		}
		printf("%s=%d", rp.id, rp.picks)
	}
	printf("\n")
	printf("  per relay (id=picks):\n")
	for i, rp := range r.relayPicks {
		if i%5 == 0 {
			printf("    ")
		} else {
			printf("  ")
		}
		printf("%s=%d", rp.id, rp.picks)
		if i%5 == 4 || i == len(r.relayPicks)-1 {
			printf("\n")
		}
	}
	printf("\n")

	printf("AS distribution (%d hop selections)\n", totalPicks)
	printf("  %-26s %d / %d\n", "ASes seen", r.asSeen, len(r.asPicks))
	for _, ap := range r.asPicks {
		printf("  %-10s relays=%2d picks=%4d (%5.1f%%)\n",
			ap.as, ap.relays, ap.picks, percent(ap.picks, totalPicks))
	}
	printf("\n")

	printf("three-hop duplicate rate\n")
	printf("  %-26s %d / %d (%.2f%%)\n", "within-circuit dup IDs",
		r.duplicateCircuits, r.assigned, percent(r.duplicateCircuits, r.assigned))
	printf("  %-26s %d / %d (%.2f%%)\n", "AS-distinct circuits",
		r.asDistinct, r.assigned, percent(r.asDistinct, r.assigned))
	printf("  %-26s %d\n\n", "duplicate rounds rejected", r.metrics.DuplicateIDRejects)

	printf("restricted views\n")
	printf("  %-26s %s (no middle/exit fields)\n",
		"client view fields", strings.Join(r.clientFields, ", "))
	printf("  %-26s %d / %d adjacent-only\n",
		"relay neighbor checks", r.neighborChecks, r.neighborChecks)

	if err != nil {
		return err
	}
	return bw.Flush()
}
