package audit

import (
	"fmt"

	"dvpn-sim/internal/receipt"
)

type Check struct {
	From string
	To   string
	A    int64
	B    int64
	Diff float64
	OK   bool
}

type Report struct {
	Receipts []*receipt.Receipt
	Checks   []Check
	Failed   bool
}

// Run verifies all receipt signatures and checks the byte-count chain
// client -> entry -> middle -> exit -> sink.
func Run(rs []*receipt.Receipt, epsilon float64) (Report, error) {
	for _, r := range rs {
		if !r.Verify() {
			return Report{}, fmt.Errorf("bad signature: %s/%s", r.Role, r.Name)
		}
	}
	byRole := map[string]*receipt.Receipt{}
	for _, r := range rs {
		byRole[r.Role] = r
	}

	rep := Report{Receipts: rs}
	pairs := []struct{ from, to string }{
		{"client", "entry"},
		{"entry", "middle"},
		{"middle", "exit"},
		{"exit", "sink"},
	}
	for _, p := range pairs {
		a, b := byRole[p.from], byRole[p.to]
		if a == nil || b == nil {
			continue
		}
		diff := relDiff(float64(a.BytesOut), float64(b.BytesIn))
		ok := diff <= epsilon
		rep.Checks = append(rep.Checks, Check{
			From: p.from, To: p.to,
			A: a.BytesOut, B: b.BytesIn,
			Diff: diff, OK: ok,
		})
		if !ok {
			rep.Failed = true
		}
	}
	return rep, nil
}

func relDiff(a, b float64) float64 {
	if a == 0 && b == 0 {
		return 0
	}
	d := a - b
	if d < 0 {
		d = -d
	}
	m := a
	if b > m {
		m = b
	}
	return d / m
}
