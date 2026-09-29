package hashcat

import (
	"strings"
	"testing"
)

func TestHumanCand(t *testing.T) {
	cases := map[int64]string{
		0:             "0",
		500:           "500",
		2_900:         "2.9K",
		1_000_000:     "1.0M",
		2_900_000_000: "2.9B",
		3_400_000_000_000:       "3.4T",
		6_600_000_000_000_000:   "6.6P",
	}
	for n, want := range cases {
		if got := humanCand(n); got != want {
			t.Errorf("humanCand(%d) = %q, want %q", n, got, want)
		}
	}
}

// TestApplyStatusAggCandidates verifies the candidate-progress fields (tried /
// total keyspace) are populated — the info that was missing for mask cracks.
func TestApplyStatusAggCandidates(t *testing.T) {
	var s Summary
	st := hcStatus{
		Status:   3,
		Progress: []int64{1_500_000_000, 2_900_000_000}, // this pass: 1.5B done
	}
	// Mask keyspace total = 2.9B, no prior passes done.
	applyStatusAgg(&s, st, 0, 2_900_000_000)
	if s.CandTried != 1_500_000_000 {
		t.Errorf("CandTried = %d, want 1500000000", s.CandTried)
	}
	if s.CandTotal != 2_900_000_000 {
		t.Errorf("CandTotal = %d, want 2900000000", s.CandTotal)
	}
	if !strings.Contains(s.CandHuman, "/") || !strings.HasPrefix(s.CandHuman, "1.5B") {
		t.Errorf("CandHuman = %q, want like '1.5B / 2.9B'", s.CandHuman)
	}
	if s.ProgressPct != 51 {
		t.Errorf("ProgressPct = %d, want 51 (1.5B of 2.9B)", s.ProgressPct)
	}
}
