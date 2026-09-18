package hashcat

import (
	"errors"
	"strings"
)

// This file builds a hashcat mask from a structured, UI-driven selection instead
// of a raw ?d?l?u… string typed by the operator. The web form submits per-position
// character-class choices (or a single class set + a length range); AssembleMask
// turns that into a real hashcat mask plus the ≤4 custom charsets (-1..-4) it needs.
//
// hashcat token vocabulary produced here:
//   ?l lowercase(26)  ?u uppercase(26)  ?d digits(10)  ?s symbols(33)  ?a all(95=l+u+d+s)
//   ?1..?4 custom charset slots, whose definitions are emitted as -1..-4 <def>.
// A "def" is a UNION of built-in tokens (?l?u?d?s…) and/or literal characters, e.g.
// "?l?d" (lower+digits) or "?d!@" (digits plus the literals ! and @).

const maskMaxLen = 16 // per-position count / range bound cap (keeps the UI + keyspace sane)

// Built-in charset cardinalities (single source of truth, shared with keyspace math).
var maskBaseSizes = map[byte]int64{'d': 10, 'l': 26, 'u': 26, 's': 33, 'a': 95, 'b': 256, 'h': 16, 'H': 16}

var (
	// ErrNoMask: a position (or the whole mask) selected no character class at all.
	ErrNoMask = errors.New("no_mask")
	// ErrTooManyCharsets: more than 4 DISTINCT multi-class/custom sets are needed,
	// but hashcat only has -1..-4.
	ErrTooManyCharsets = errors.New("too_many_charsets")
	// ErrBadMaskLen: length / range outside 1..maskMaxLen, or min > max.
	ErrBadMaskLen = errors.New("bad_mask_len")
)

// MaskPos is one position's (or, in range mode, the single shared) class selection.
type MaskPos struct {
	Lower  bool
	Upper  bool
	Digit  bool
	Symbol bool
	Custom string // extra literal characters to include at this position
}

// MaskInput is the structured selection submitted by the form.
type MaskInput struct {
	Mode      string    // "fixed" | "range"
	Positions []MaskPos // fixed mode: one entry per position
	Min, Max  int       // range mode: length bounds
	Range     MaskPos   // range mode: the single class set applied to every position
}

// MaskPlan is the assembled, hashcat-ready result.
type MaskPlan struct {
	Mask     string   // e.g. "?d?d?1?1" or "?a" or "?1?1?1?1"
	Charsets []string // custom charset defs; index 0 → -1, index 1 → -2, …
	IncMin   int      // --increment-min (0 = no increment)
	IncMax   int      // --increment-max (0 = off)
}

// AssembleMask converts the structured selection into a hashcat mask + custom
// charsets. See the file header for the token vocabulary and the per-position rules.
func AssembleMask(in MaskInput) (MaskPlan, error) {
	var defs []string // distinct custom charset definitions, first-seen order → -1..-4

	if in.Mode == "range" {
		if in.Min < 1 || in.Max < 1 || in.Min > maskMaxLen || in.Max > maskMaxLen || in.Min > in.Max {
			return MaskPlan{}, ErrBadMaskLen
		}
		tok, err := resolvePos(in.Range, &defs)
		if err != nil {
			return MaskPlan{}, err
		}
		return MaskPlan{
			Mask:     strings.Repeat(tok, in.Max),
			Charsets: defs,
			IncMin:   in.Min,
			IncMax:   in.Max,
		}, nil
	}

	// fixed mode
	n := len(in.Positions)
	if n < 1 || n > maskMaxLen {
		return MaskPlan{}, ErrBadMaskLen
	}
	var b strings.Builder
	for _, p := range in.Positions {
		tok, err := resolvePos(p, &defs)
		if err != nil {
			return MaskPlan{}, err
		}
		b.WriteString(tok)
	}
	return MaskPlan{Mask: b.String(), Charsets: defs}, nil
}

// resolvePos turns one position's selection into a mask token, allocating (and
// deduping) a custom charset slot in *defs when the selection can't be expressed
// with a single built-in token. Enforces the 4-slot cap.
func resolvePos(p MaskPos, defs *[]string) (string, error) {
	custom := escapeCustom(p.Custom)
	classes := 0
	if p.Lower {
		classes++
	}
	if p.Upper {
		classes++
	}
	if p.Digit {
		classes++
	}
	if p.Symbol {
		classes++
	}

	if classes == 0 && custom == "" {
		return "", ErrNoMask
	}

	// Single built-in cases (no slot consumed).
	if custom == "" {
		if classes == 4 {
			return "?a", nil // l+u+d+s == ?a (95)
		}
		if classes == 1 {
			switch {
			case p.Lower:
				return "?l", nil
			case p.Upper:
				return "?u", nil
			case p.Digit:
				return "?d", nil
			case p.Symbol:
				return "?s", nil
			}
		}
	}

	// Needs a custom charset: build its definition (canonical class order + literals).
	def := classTokens(p) + custom
	// Reuse an existing identical slot.
	for i, d := range *defs {
		if d == def {
			return slotToken(i), nil
		}
	}
	if len(*defs) >= 4 {
		return "", ErrTooManyCharsets
	}
	*defs = append(*defs, def)
	return slotToken(len(*defs) - 1), nil
}

// classTokens returns the selected built-in tokens in canonical l,u,d,s order.
func classTokens(p MaskPos) string {
	var b strings.Builder
	if p.Lower {
		b.WriteString("?l")
	}
	if p.Upper {
		b.WriteString("?u")
	}
	if p.Digit {
		b.WriteString("?d")
	}
	if p.Symbol {
		b.WriteString("?s")
	}
	return b.String()
}

func slotToken(i int) string { return "?" + string(rune('1'+i)) }

// escapeCustom escapes '?' as '??' (a bare '?' in a hashcat charset def is a
// charset reference) and drops non-printable bytes the operator can't have meant.
func escapeCustom(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x20 || c == 0x7f {
			continue
		}
		if c == '?' {
			b.WriteString("??")
			continue
		}
		b.WriteByte(c)
	}
	return b.String()
}

// charsetDefSize returns the cardinality of a custom charset definition: the sum
// of its built-in token sizes plus one per literal character ('??' → literal '?').
func charsetDefSize(def string) int64 {
	var total int64
	for i := 0; i < len(def); {
		if def[i] == '?' && i+1 < len(def) {
			if s, ok := maskBaseSizes[def[i+1]]; ok {
				total += s
			} else {
				total++ // '??' → a single literal '?', or an unknown ref → count as 1
			}
			i += 2
		} else {
			total++
			i++
		}
	}
	if total < 1 {
		total = 1
	}
	return total
}
