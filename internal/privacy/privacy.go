package privacy

import "math"

// Obs is one flow observation at an entry or exit.
type Obs struct {
	Session string
	Start   int64 // ns
	End     int64 // ns
	Bytes   int64
	Real    bool
}

type Report struct {
	RealSessions int
	AvgSetSize   float64
	Linkability  float64 // average 1/set size
	Top1         float64 // fraction whose nearest observation is the true one
}

// Analyze estimates how well a colluding entry+exit can match real flows
// against a set of real + cover observations.
func Analyze(real, cover []Obs, timeWindow, byteWindow int64) Report {
	all := make([]Obs, 0, len(real)+len(cover))
	all = append(all, real...)
	all = append(all, cover...)

	rep := Report{RealSessions: len(real)}
	if len(real) == 0 {
		return rep
	}
	var sumSet, sumLink, top1 float64
	for _, r := range real {
		set := 0
		best := int64(math.MaxInt64)
		bestSession := ""
		for _, x := range all {
			if abs64(x.Start-r.Start) <= timeWindow && abs64(x.Bytes-r.Bytes) <= byteWindow {
				set++
			}
			d := abs64(x.Start-r.Start) + abs64(x.Bytes-r.Bytes)
			if d < best {
				best = d
				bestSession = x.Session
			}
		}
		if set == 0 {
			set = 1
		}
		sumSet += float64(set)
		sumLink += 1 / float64(set)
		if bestSession == r.Session {
			top1++
		}
	}
	n := float64(len(real))
	rep.AvgSetSize = sumSet / n
	rep.Linkability = sumLink / n
	rep.Top1 = top1 / n
	return rep
}

func abs64(x int64) int64 {
	if x < 0 {
		return -x
	}
	return x
}
