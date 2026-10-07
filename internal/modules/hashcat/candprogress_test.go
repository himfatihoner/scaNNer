package hashcat

import (
	"strings"
	"testing"
)

func TestHumanCand(t *testing.T) {
	cases := map[int64]string{
		0:                     "0",
		500:                   "500",
		2_900:                 "2.9K",
		1_000_000:             "1.0M",
		2_900_000_000:         "2.9B",
		3_400_000_000_000:     "3.4T",
		6_600_000_000_000_000: "6.6P",
	}
	for n, want := range cases {
		if got := humanCand(n); got != want {
			t.Errorf("humanCand(%d) = %q, want %q", n, got, want)
		}
	}
}

// Single pass, single mode, NO salt amplification (hashcat end == our base).
func TestApplyStatusAggCandidates(t *testing.T) {
	var s Summary
	st := hcStatus{
		Status:   3,
		Progress: []int64{1_500_000_000, 2_900_000_000}, // this pass: 1.5B of 2.9B
	}
	// passWeight == totalWeight == hashcat end (2.9B); no prior passes; single mode.
	applyStatusAgg(&s, st, 0, 2_900_000_000, 2_900_000_000, 0, 1)
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

// THE BUG: salted hashes make hashcat's progress counter = base × salts, so its
// `cur` (1.5B) exceeds our salt-free base keyspace (1B). The old code added the
// raw counter to a salt-free denominator and clamped → the bar pinned at 100%.
// The fix uses hashcat's own fraction (cur/end), so a run that is 50% through its
// keyspace reports 50%, not 100%.
func TestApplyStatusAggSalted(t *testing.T) {
	var s Summary
	const base = int64(1_000_000_000) // words×rules, salt-free
	st := hcStatus{
		Status:   3,
		Progress: []int64{1_500_000_000, 3_000_000_000}, // 50% of a 3-salt (3B) keyspace
	}
	applyStatusAgg(&s, st, 0, base, base, 0, 1)
	if s.ProgressPct != 50 {
		t.Fatalf("ProgressPct = %d, want 50 — salted progress must NOT pin at 100%%", s.ProgressPct)
	}
	if s.CandTried != 500_000_000 {
		t.Errorf("CandTried = %d, want 500000000 (salt-free base candidates)", s.CandTried)
	}
	if s.CandTotal != base {
		t.Errorf("CandTotal = %d, want %d (salt-free)", s.CandTotal, base)
	}
}

// Multi-rule: pass 2 of 2. Pass 1 (weight 1B) already done; pass 2 (weight 2B) is
// half way. Overall = (1B + 0.5×2B) / 3B = 66%.
func TestApplyStatusAggMultiPass(t *testing.T) {
	var s Summary
	st := hcStatus{Status: 3, Progress: []int64{1_000_000_000, 2_000_000_000}} // 50% of pass 2
	applyStatusAgg(&s, st, 1_000_000_000 /*done*/, 2_000_000_000 /*passW*/, 3_000_000_000 /*total*/, 0, 1)
	if s.ProgressPct != 66 {
		t.Fatalf("ProgressPct = %d, want 66 (pass1 done + pass2 half of 3B total)", s.ProgressPct)
	}
}

// Auto-detect: candidate mode 2 of 3 (modeBase=1/3, span=1/3), this mode half
// done → overall = 1/3 + 1/3×0.5 = 50%. The bar must not reset to 0 per mode.
func TestApplyStatusAggAutoDetectModes(t *testing.T) {
	var s Summary
	st := hcStatus{Status: 3, Progress: []int64{500_000_000, 1_000_000_000}} // 50% within the mode
	applyStatusAgg(&s, st, 0, 1_000_000_000, 1_000_000_000, 1.0/3.0, 1.0/3.0)
	if s.ProgressPct != 50 {
		t.Fatalf("ProgressPct = %d, want 50 (mode 2/3 half done)", s.ProgressPct)
	}
}
