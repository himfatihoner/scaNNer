package hashcat

import "strings"

// buildSlideMasks generates the per-position hashcat masks for the known-substring
// sliding attack: the known literal (cfg.KnownSub) placed at every offset, with the
// remaining positions filled by cfg.SubToken, for each total length in
// [SubLenMin,SubLenMax]. E.g. KnownSub="test", SubToken="?l", length 8 →
//
//	test?l?l?l?l · ?ltest?l?l?l · ?l?ltest?l?l · ?l?l?ltest?l · ?l?l?l?ltest
//
// The literal is escaped ('?' → '??') so a known fragment containing '?' can't be
// read as a hashcat charset reference. L (the known part's CHARACTER count) is the
// pre-escape rune length, since an escaped '?' is still one password position.
// Each returned mask becomes its own pass (see buildPasses) so the existing
// keyspace-weighted progress/ETA aggregation spans every position.
func buildSlideMasks(cfg Config) []string {
	lit := escapeCustom(cfg.KnownSub)
	if lit == "" || cfg.SubToken == "" {
		return nil
	}
	L := len([]rune(cfg.KnownSub))
	lo, hi := cfg.SubLenMin, cfg.SubLenMax
	if hi < lo {
		lo, hi = hi, lo
	}
	if lo < L {
		lo = L // can't be shorter than the known part
	}
	var out []string
	for n := lo; n <= hi; n++ {
		unknown := n - L
		if unknown < 0 {
			continue
		}
		for p := 0; p <= unknown; p++ {
			var b strings.Builder
			for i := 0; i < p; i++ {
				b.WriteString(cfg.SubToken)
			}
			b.WriteString(lit)
			for i := 0; i < unknown-p; i++ {
				b.WriteString(cfg.SubToken)
			}
			out = append(out, b.String())
		}
	}
	return out
}

// SlideMaskCount returns how many masks (= hashcat passes/process spawns) a given
// known-substring config would generate — used to cap absurdly wide length ranges.
func SlideMaskCount(knownLen, lenMin, lenMax int) int {
	lo, hi := lenMin, lenMax
	if hi < lo {
		lo, hi = hi, lo
	}
	if lo < knownLen {
		lo = knownLen
	}
	n := 0
	for L := lo; L <= hi; L++ {
		n += (L - knownLen) + 1
	}
	return n
}
