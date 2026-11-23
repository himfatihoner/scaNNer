package hashcat

import (
	"strings"
	"testing"
)

func TestBuildSlideMasks(t *testing.T) {
	// Fixed length 8, known "test" (L=4), unknown ?l → 5 sliding masks.
	got := buildSlideMasks(Config{KnownSub: "test", SubToken: "?l", SubLenMin: 8, SubLenMax: 8})
	want := []string{"test?l?l?l?l", "?ltest?l?l?l", "?l?ltest?l?l", "?l?l?ltest?l", "?l?l?l?ltest"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("len8: got %v want %v", got, want)
	}
	// N == L → a single literal-only mask (checks the password IS the substring).
	if g := buildSlideMasks(Config{KnownSub: "test", SubToken: "?l", SubLenMin: 4, SubLenMax: 4}); len(g) != 1 || g[0] != "test" {
		t.Errorf("N==L: %v", g)
	}
	// Range 6..7, L=4 → (6-4+1)+(7-4+1) = 3+4 = 7 masks.
	if g := buildSlideMasks(Config{KnownSub: "test", SubToken: "?d", SubLenMin: 6, SubLenMax: 7}); len(g) != 7 {
		t.Errorf("range: %d masks (want 7)", len(g))
	}
	// A '?' in the known fragment must be escaped to '??' (else hashcat reads it
	// as a charset reference). "a?b" L=3, N=4 → 2 masks, literal "a??b".
	g4 := buildSlideMasks(Config{KnownSub: "a?b", SubToken: "?l", SubLenMin: 4, SubLenMax: 4})
	if len(g4) != 2 || !strings.Contains(g4[0], "a??b") {
		t.Errorf("escape: %v", g4)
	}
	// SlideMaskCount mirrors the generation count.
	if SlideMaskCount(4, 8, 8) != 5 || SlideMaskCount(4, 6, 7) != 7 {
		t.Errorf("SlideMaskCount mismatch: %d %d", SlideMaskCount(4, 8, 8), SlideMaskCount(4, 6, 7))
	}
}

func TestBuildPassesAndArgsSubstring(t *testing.T) {
	cfg := Config{Attack: 3, KnownSub: "test", SubToken: "?l", SubLenMin: 8, SubLenMax: 8}
	passes := buildPasses(cfg)
	if len(passes) != 5 {
		t.Fatalf("want 5 passes, got %d", len(passes))
	}
	if passes[0].mask != "test?l?l?l?l" {
		t.Errorf("pass0 mask = %q", passes[0].mask)
	}
	// buildArgs must put the per-pass mask in the -a 3 positional.
	args := strings.Join(buildArgs(cfg, 0, "", passes[1].mask, "/tmp/h", "/tmp/o"), " ")
	if !strings.Contains(args, "?ltest?l?l?l -a 3") {
		t.Errorf("argv missing per-position mask: %s", args)
	}
	// Per-position keyspace = 26^4 (?l over the 4 unknown positions).
	if ks := passKeyspace(cfg, "", passes[0].mask, 0); ks != 26*26*26*26 {
		t.Errorf("keyspace = %d (want %d)", ks, 26*26*26*26)
	}
}

func TestSubstringCustomCharset(t *testing.T) {
	// Unknown positions = ?1 defined as ?l?d (size 36). Known "ab" L=2, N=4 → 2 unknown.
	cfg := Config{Attack: 3, KnownSub: "ab", SubToken: "?1", MaskCharsets: []string{"?l?d"}, SubLenMin: 4, SubLenMax: 4}
	passes := buildPasses(cfg)
	if len(passes) != 3 || passes[0].mask != "ab?1?1" {
		t.Fatalf("passes = %+v", passes)
	}
	args := strings.Join(buildArgs(cfg, 1000, "", passes[0].mask, "/tmp/h", "/tmp/o"), " ")
	if !strings.Contains(args, "-1 ?l?d") || !strings.Contains(args, "ab?1?1 -a 3") {
		t.Errorf("argv = %s", args)
	}
	if ks := passKeyspace(cfg, "", passes[0].mask, 0); ks != 36*36 {
		t.Errorf("keyspace = %d (want %d)", ks, 36*36)
	}
}

// ResolveCharsetToken (handler-facing) maps a UI charset selection to a token + defs.
func TestResolveCharsetToken(t *testing.T) {
	// Single class → built-in token, no def.
	if tok, defs, err := ResolveCharsetToken(MaskPos{Lower: true}); err != nil || tok != "?l" || len(defs) != 0 {
		t.Errorf("lower: tok=%q defs=%v err=%v", tok, defs, err)
	}
	// Multi-class → ?1 + a def.
	if tok, defs, err := ResolveCharsetToken(MaskPos{Lower: true, Digit: true}); err != nil || tok != "?1" || len(defs) != 1 || defs[0] != "?l?d" {
		t.Errorf("lower+digit: tok=%q defs=%v err=%v", tok, defs, err)
	}
	// Empty selection → error.
	if _, _, err := ResolveCharsetToken(MaskPos{}); err == nil {
		t.Error("empty selection should error")
	}
}
