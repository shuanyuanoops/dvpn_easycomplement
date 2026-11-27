// Package registry stores the relay pool that circuits are assigned from.
package registry

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
	"os"

	"dvpn-sim/internal/model"
)

// Relay is one assignable relay. Identity is the path to the relay's signed
// identity document (X25519 transport key + Ed25519 signature).
type Relay struct {
	ID       string `json:"id"`
	Role     string `json:"role"`
	Addr     string `json:"addr"`
	Identity string `json:"identity"`
	AS       string `json:"as,omitempty"`
}

// Pool is the set of relays available for assignment.
type Pool struct {
	Relays []Relay `json:"relays"`
}

// Load reads a relay pool from path. The file may be either
// {"relays":[...]} or a bare JSON array of relays.
func Load(path string) (*Pool, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var p Pool
	if err := json.Unmarshal(b, &p); err != nil {
		var list []Relay
		if err2 := json.Unmarshal(b, &list); err2 != nil {
			return nil, fmt.Errorf("parse %s: %w", path, err)
		}
		p = Pool{Relays: list}
	}
	if err := p.Validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &p, nil
}

// Save writes the pool as {"relays":[...]}.
func (p *Pool) Save(path string) error {
	if err := p.Validate(); err != nil {
		return err
	}
	b, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o644)
}

// Validate checks that every relay is usable and that IDs are unique.
func (p *Pool) Validate() error {
	if p == nil || len(p.Relays) == 0 {
		return errors.New("relay pool is empty")
	}
	seen := make(map[string]bool, len(p.Relays))
	for i, r := range p.Relays {
		if r.ID == "" {
			return fmt.Errorf("relay %d: empty id", i)
		}
		if r.Addr == "" {
			return fmt.Errorf("relay %s: empty addr", r.ID)
		}
		if r.Identity == "" {
			return fmt.Errorf("relay %s: empty identity path", r.ID)
		}
		switch model.Role(r.Role) {
		case model.RoleEntry, model.RoleMiddle, model.RoleExit:
		default:
			return fmt.Errorf("relay %s: unknown role %q", r.ID, r.Role)
		}
		if seen[r.ID] {
			return fmt.Errorf("duplicate relay id %q", r.ID)
		}
		seen[r.ID] = true
	}
	for _, role := range []model.Role{model.RoleEntry, model.RoleMiddle, model.RoleExit} {
		if len(p.byRole(role)) == 0 {
			return fmt.Errorf("pool has no %s relay", role)
		}
	}
	return nil
}

type combo struct {
	entry, middle, exit Relay
}

func asDistinct(c combo) bool {
	if c.entry.AS == "" || c.middle.AS == "" || c.exit.AS == "" {
		return false
	}
	return c.entry.AS != c.middle.AS && c.entry.AS != c.exit.AS && c.middle.AS != c.exit.AS
}

// Assign picks one entry, one middle and one exit at random. It prefers
// combinations whose AS values are all present and pairwise distinct; if the
// pool cannot provide that, it falls back to any random combination with
// distinct IDs.
func (p *Pool) Assign() (entry, middle, exit Relay, err error) {
	if err := p.Validate(); err != nil {
		return Relay{}, Relay{}, Relay{}, err
	}
	entries := p.byRole(model.RoleEntry)
	middles := p.byRole(model.RoleMiddle)
	exits := p.byRole(model.RoleExit)
	if len(entries) == 0 || len(middles) == 0 || len(exits) == 0 {
		return Relay{}, Relay{}, Relay{}, errors.New("pool missing a role")
	}

	var all, distinct []combo
	for _, e := range entries {
		for _, m := range middles {
			for _, x := range exits {
				if e.ID == m.ID || e.ID == x.ID || m.ID == x.ID {
					continue
				}
				c := combo{e, m, x}
				all = append(all, c)
				if asDistinct(c) {
					distinct = append(distinct, c)
				}
			}
		}
	}
	pool := all
	if len(distinct) > 0 {
		pool = distinct
	}
	if len(pool) == 0 {
		return Relay{}, Relay{}, Relay{}, errors.New("no valid entry/middle/exit combination")
	}
	c := pool[rand.IntN(len(pool))]
	return c.entry, c.middle, c.exit, nil
}

func (p *Pool) byRole(role model.Role) []Relay {
	out := make([]Relay, 0, len(p.Relays))
	for _, r := range p.Relays {
		if model.Role(r.Role) == role {
			out = append(out, r)
		}
	}
	return out
}
