package privacy

import "testing"

func TestNoCover(t *testing.T) {
	real := []Obs{{Session: "s1", Start: 100, Bytes: 1000, Real: true}}
	rep := Analyze(real, nil, 10, 100)
	if rep.AvgSetSize != 1 || rep.Linkability != 1 || rep.Top1 != 1 {
		t.Fatalf("got %+v", rep)
	}
}

func TestCoverLowersLinkability(t *testing.T) {
	real := []Obs{{Session: "s1", Start: 100, Bytes: 1000, Real: true}}
	var cover []Obs
	for i := 0; i < 10; i++ {
		cover = append(cover, Obs{Session: "c", Start: 100, Bytes: 1000})
	}
	rep := Analyze(real, cover, 10, 100)
	if rep.AvgSetSize != 11 {
		t.Fatalf("set=%f want 11", rep.AvgSetSize)
	}
	if rep.Linkability > 0.1 {
		t.Fatalf("linkability=%f want <= 0.1", rep.Linkability)
	}
}

func TestOutsideWindow(t *testing.T) {
	real := []Obs{{Session: "s1", Start: 100, Bytes: 1000, Real: true}}
	cover := []Obs{{Session: "c", Start: 1000, Bytes: 5000}}
	rep := Analyze(real, cover, 10, 100)
	if rep.AvgSetSize != 1 {
		t.Fatalf("set=%f want 1", rep.AvgSetSize)
	}
}
