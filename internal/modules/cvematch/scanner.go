package cvematch

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
)

var _ = strconv.Atoi

// Input is one (product, version, source-context) triple the matcher
// will evaluate against the CVE database.
type Input struct {
	Product string `json:"product"`
	Version string `json:"version,omitempty"`
	URL     string `json:"url,omitempty"`    // source target URL (techdetect)
	Source  string `json:"source,omitempty"` // "techdetect", "manual", "portservice"
	// RawRequest/RawResponse carry the HTTP exchange that detected the product
	// (tech-detection). Embedded into every Match built from this input so a CVE
	// matched off a detected technology can show, in its PoC, the exact request
	// and response that evidenced the technology. Empty for manual/portservice
	// input (no HTTP capture). Kept in the JSON via the raw_request/raw_response
	// keys that the vuln-index extractor already reads for PoC enrichment.
	RawRequest  string `json:"raw_request,omitempty"`
	RawResponse string `json:"raw_response,omitempty"`
}

// Match is one CVE record applied to one input.
//
// Audit fix: the previous embedded Input + same-named Source field caused
// Go's outer-field shadowing to hide Input.Source from template lookups —
// {{.Source}} in cvematch_results.html resolved to the match origin
// (builtin/nvd/cache) instead of the input origin (techdetect/manual).
// Renamed to MatchSource (JSON tag stays "match_source" so wire schema
// is unchanged) and templates explicitly reach Input.Source when they
// want the input origin.
type Match struct {
	Input
	CVE         string `json:"cve"`
	Severity    string `json:"severity"`
	CVSS        string `json:"cvss"`
	Description string `json:"description"`
	Remediation string `json:"remediation,omitempty"`
	FixedIn     string `json:"fixed_in,omitempty"`
	Reference   string `json:"reference"`
	MatchSource string `json:"match_source,omitempty"` // builtin | nvd | cache
	// UnverifiedVersion=true means the input arrived without version info,
	// so we couldn't bound-check the affected range — the match is a
	// product-hit only and should be visually flagged in the UI.
	UnverifiedVersion bool `json:"unverified_version,omitempty"`
	// PotentialSeverity carries the CVE's native severity (CRITICAL/HIGH/…)
	// when UnverifiedVersion=true. For unverified product-hits the reported
	// Severity is forced to INFO so version-less matches can't inflate the
	// CRITICAL/HIGH alarm counts (the false-positive engine); the original
	// severity is preserved here for triage ("POTENTIAL CVE — verify
	// version"). Empty for versioned matches.
	PotentialSeverity string `json:"potential_severity,omitempty"`
}

type ScanResult struct {
	Inputs  []Input `json:"inputs"`
	Matches []Match `json:"matches"`
	// SkippedNoVersion lists inputs that were dropped from matching
	// because they had no Version (only used when we *didn't* keep them
	// as unverified hits — kept for future UI surfacing).
	SkippedNoVersion []Input `json:"skipped_no_version,omitempty"`
}

type Config struct {
	Inputs []Input
}

type ProgressFunc func(done int, msg string)

// PartialFunc receives snapshots of the in-progress ScanResult so the
// handler can flush them to the DB (and the htmx-polled UI) without
// waiting for the entire input list to finish matching.
type PartialFunc func(*ScanResult)

// CacheLookup is the callback shape the scanner uses to query the SQLite-
// backed NVD cache. The handler injects an implementation that wraps
// db.CVELookup. Returning nil/empty means "no cache entries" and the
// matcher falls back to the in-tree CVEDatabase only.
type CacheLookup func(productKey string) []CacheCVE

// CacheCVE mirrors db.CVERecord but lives in this package so callers
// don't need to import the database package.
type CacheCVE struct {
	CVEID       string
	ProductKey  string
	ProductName string
	VersionLo   string
	VersionHi   string
	LoInc       bool
	HiInc       bool
	FixedIn     string
	Severity    string
	CVSS        float64
	Description string
	Remediation string
	Reference   string
}

// ScanContext iterates the inputs and produces match records. If
// cacheLookup is non-nil, NVD cache rows are merged with the built-in
// curated DB (cache hits override built-in entries with the same CVE ID
// so the freshest data wins).
//
// Audit fix: previous signature dropped context.Context entirely so the
// Stop button (ScanManager.Cancel) was a no-op once a Scan was running
// against a large input list. ScanContext is the canonical entry point.
// A PartialFunc was added so live UI updates can flush per-input — the
// previous handler waited until completion before writing any results.
func ScanContext(ctx context.Context, cfg Config, progress ProgressFunc, partial PartialFunc, cacheLookup CacheLookup) *ScanResult {
	result := &ScanResult{Inputs: cfg.Inputs}
	var mu sync.Mutex
	// Memoize DB cache lookups by product key. Many inputs share the same
	// product (e.g. "ASP.NET" fingerprinted on hundreds of hosts), and every
	// input triggers 2+ lookups (matchInputCombined + productHasCVEs). Without
	// this, a chained CVE phase re-queries SQLite tens of thousands of times —
	// turning a genuinely local, sub-second match into minutes of redundant I/O.
	// The input loop is sequential, so a plain map is safe.
	if cacheLookup != nil {
		raw := cacheLookup
		memo := make(map[string][]CacheCVE)
		cacheLookup = func(productKey string) []CacheCVE {
			if v, ok := memo[productKey]; ok {
				return v
			}
			v := raw(productKey)
			memo[productKey] = v
			return v
		}
	}
	for i, in := range cfg.Inputs {
		// Respect cancellation between inputs. Each matchInputCombined
		// is a bounded SQLite query, so per-input granularity is enough.
		if ctx != nil {
			select {
			case <-ctx.Done():
				return result
			default:
			}
		}
		ms := matchInputCombined(in, cacheLookup)
		// Record version-less products that DO have CVEs in the DB so the
		// UI can surface "detected, version unknown — not CVE-checked"
		// without emitting a (guessed) vulnerability match. Products with
		// no CVEs at all (fonts, icon libs) are not recorded — no signal.
		skip := strings.TrimSpace(in.Version) == "" &&
			strings.TrimSpace(in.Product) != "" &&
			productHasCVEs(in, cacheLookup)
		mu.Lock()
		result.Matches = append(result.Matches, ms...)
		if skip {
			result.SkippedNoVersion = append(result.SkippedNoVersion, in)
		}
		// Snapshot a partial result while the lock is held so the
		// caller's PartialFunc gets a coherent slice — the live UI
		// throttle in the handler decides whether to flush.
		var snap *ScanResult
		if partial != nil {
			snap = &ScanResult{
				Inputs:           result.Inputs,
				Matches:          append([]Match(nil), result.Matches...),
				SkippedNoVersion: append([]Input(nil), result.SkippedNoVersion...),
			}
		}
		mu.Unlock()
		if partial != nil && snap != nil {
			partial(snap)
		}
		if progress != nil {
			progress(i+1, fmt.Sprintf("[%d/%d] %s %s — %d CVE(s)", i+1, len(cfg.Inputs), in.Product, in.Version, len(ms)))
		}
	}
	return result
}

// Scan is the legacy entry point retained for callers (advancedweb,
// techdetect chained mode) that don't yet thread a context. New code
// should use ScanContext.
func Scan(cfg Config, progress ProgressFunc, cacheLookup CacheLookup) *ScanResult {
	return ScanContext(context.Background(), cfg, progress, nil, cacheLookup)
}

// matchInputCombined queries the SQLite cve_records table for CVE
// matches. The built-in 35 curated CVEs are SEEDED into the same table
// at startup (source='builtin') so this is the single source of truth.
// If lookup is nil (no cache wired) we fall back to the in-memory
// CVEDatabase slice for offline mode.
func matchInputCombined(in Input, lookup CacheLookup) []Match {
	// User directive: if the product version could not be determined, do
	// NOT perform vulnerability matching at all. Without a version we
	// cannot bound-check a CVE's affected range, so any "match" is a
	// guess. Previously version-less hits were kept (downgraded to INFO)
	// which still cluttered results; now they are dropped entirely.
	// ScanContext records the input in SkippedNoVersion (when the product
	// actually has CVEs) so the UI can show "detected, version unknown —
	// not CVE-checked" without emitting any vulnerability match.
	if strings.TrimSpace(in.Version) == "" {
		return nil
	}
	var builtin []Match
	if lookup == nil {
		// No cache → in-memory fallback (used by tests / standalone usage).
		builtin = matchInput(in)
	}
	// SQLite cache lookup — covers built-in + NVD rows.
	var cached []Match
	if lookup != nil {
		// Walk product aliases — for each canonical product, look up by
		// the CPE-style key. Try both "vendor:product" and just "product".
		// For products NOT in the curated alias table, fall back to a
		// normalized bare name so matching isn't limited to the ~25 curated
		// products; the exact-component key match + version-range check keep
		// false positives low.
		canonical := canonicalProduct(in.Product)
		if canonical == "" {
			canonical = fallbackProduct(in.Product)
		}
		if canonical != "" {
			seenKeys := map[string]bool{}
			// Direct lookup by canonical product (treated as the second
			// half of vendor:product, which is what most CPEs use).
			for _, key := range candidateCacheKeys(canonical, in.Product) {
				if seenKeys[key] {
					continue
				}
				seenKeys[key] = true
				for _, cce := range lookup(key) {
					// Version is guaranteed non-empty here (version-less
					// inputs return early above). A row that doesn't cover
					// the input version is a genuine non-match.
					if !cveCacheRowMatches(cce, in.Version) {
						continue
					}
					// Derive FixedIn for NVD rows that didn't carry an
					// explicit field: if HiInc=false (exclusive upper),
					// then version_hi IS the fixed version.
					fixedIn := cce.FixedIn
					if fixedIn == "" && cce.VersionHi != "" && !cce.HiInc {
						fixedIn = cce.VersionHi
					}
					cached = append(cached, Match{
						Input:       in,
						CVE:         cce.CVEID,
						Severity:    cce.Severity,
						CVSS:        fmt.Sprintf("%.1f", cce.CVSS),
						Description: cce.Description,
						Remediation: cce.Remediation,
						FixedIn:     fixedIn,
						Reference:   cce.Reference,
						MatchSource: "cache",
					})
				}
			}
		}
	}
	// Dedup by CVE ID — cache wins.
	byCVE := map[string]Match{}
	for _, m := range builtin {
		byCVE[m.CVE] = m
	}
	for _, m := range cached {
		byCVE[m.CVE] = m
	}
	out := make([]Match, 0, len(byCVE))
	for _, m := range byCVE {
		out = append(out, m)
	}
	return out
}

// productHasCVEs reports whether the input's product has ANY CVE entry in
// the cache (or builtin DB when no cache is wired), regardless of version.
// Used to decide whether a version-less detection is worth recording as
// "skipped — version unknown" (a product with zero CVEs is pure noise).
// The cache lookups are memoized by the handler, so repeat products are
// cheap.
func productHasCVEs(in Input, lookup CacheLookup) bool {
	canonical := canonicalProduct(in.Product)
	if canonical == "" {
		canonical = fallbackProduct(in.Product)
	}
	if canonical == "" {
		return false
	}
	if lookup != nil {
		seen := map[string]bool{}
		for _, key := range candidateCacheKeys(canonical, in.Product) {
			if seen[key] {
				continue
			}
			seen[key] = true
			if len(lookup(key)) > 0 {
				return true
			}
		}
		return false
	}
	for _, rec := range CVEDatabase {
		if rec.Product == canonical {
			return true
		}
	}
	return false
}

// candidateCacheKeys turns a canonical product name into one or more
// product_key candidates we'll try against the NVD cache. The cache
// stores keys as "vendor:product" (cpe-derived); our canonical names
// are "human readable" so we try several variants.
func candidateCacheKeys(canonical, raw string) []string {
	// Lowercase + replace spaces with underscores or just take the last word.
	c := strings.ToLower(canonical)
	out := []string{}
	// Pattern: "apache http server" → match cache keys ending in :http_server
	// (vendor=apache, product=http_server).
	words := strings.Fields(c)
	if len(words) >= 2 {
		out = append(out, words[0]+":"+strings.Join(words[1:], "_"))
	}
	if len(words) == 1 {
		// Single word product (nginx, openssh, php). vendor is often the same.
		out = append(out, words[0]+":"+words[0])
	}
	// Always try just the product part as wildcard fallback.
	rawLow := strings.ToLower(strings.TrimSpace(raw))
	rawLow = strings.ReplaceAll(rawLow, " ", "_")
	out = append(out, rawLow)
	return out
}

// fallbackProduct is the best-effort canonical for a product NOT in the curated
// productAliases table: lowercased + trimmed. It lets CVE matching reach beyond
// the ~25 curated products to any detected product whose exact name is an NVD
// product component (jquery, bootstrap, …) — safety comes from the exact
// component-key match (CVELookup) plus the mandatory version-range check.
// Names shorter than 4 chars are rejected as too generic to match safely.
func fallbackProduct(raw string) string {
	low := strings.ToLower(strings.TrimSpace(raw))
	if len(low) < 4 {
		return ""
	}
	return low
}

// cveCacheRowMatches checks whether a given input version falls in this
// cache row's affected range.
func cveCacheRowMatches(c CacheCVE, version string) bool {
	if version == "" {
		return false
	}
	v := parseVersion(version)
	if c.VersionLo != "" {
		cmp := cmpVer(v, parseVersion(c.VersionLo))
		if c.LoInc {
			if cmp < 0 {
				return false
			}
		} else {
			if cmp <= 0 {
				return false
			}
		}
	}
	if c.VersionHi != "" {
		cmp := cmpVer(v, parseVersion(c.VersionHi))
		if c.HiInc {
			if cmp > 0 {
				return false
			}
		} else {
			if cmp >= 0 {
				return false
			}
		}
	}
	return true
}

// matchInput finds every CVE whose product matches the input product (via
// alias map) and whose version range covers the input version.
func matchInput(in Input) []Match {
	// User directive: no version → no vulnerability matching (see
	// matchInputCombined). Version-less inputs never produce matches.
	if strings.TrimSpace(in.Version) == "" {
		return nil
	}
	prodNormalized := canonicalProduct(in.Product)
	if prodNormalized == "" {
		return nil
	}
	var out []Match
	for _, rec := range CVEDatabase {
		if rec.Product != prodNormalized {
			continue
		}
		// Version known here; an out-of-range record is a genuine non-match.
		if !versionInRange(in.Version, rec.AffectedLo, rec.AffectedHi) {
			continue
		}
		out = append(out, Match{
			Input:       in,
			CVE:         rec.CVE,
			Severity:    rec.Severity,
			CVSS:        rec.CVSS,
			Description: rec.Description,
			Remediation: rec.Remediation,
			FixedIn:     rec.FixedIn,
			Reference:   rec.Reference,
			MatchSource: "builtin",
		})
	}
	return out
}

// canonicalProduct normalizes a free-form product banner ("Apache
// Tomcat/9.0.30", "OpenSSH 8.2p1", "nginx") to one of the canonical
// keys in productAliases.
//
// Audit fix: previous implementation iterated productAliases in random
// map order and used strings.Contains, which (a) made the result
// non-deterministic across process restarts and (b) misrouted aliases —
// e.g. "apache" as an alias under "apache http server" would match an
// "apache tomcat" banner if visited first; "ssh" as an alias under
// "openssh" would match inside "ssh-agent" / any non-OpenSSH SSH server.
//
// The new logic does two ordered passes against a stable, length-sorted
// alias table:
//  1. Canonical pass — check every canonical name first, longest-first.
//     This guarantees the multi-token canonicals ("apache tomcat",
//     "spring cloud function") win over single-word aliases that might
//     overlap ("apache" under "apache http server").
//  2. Alias pass — only if no canonical matched, fall back to aliases,
//     sorted longest-first so "spring boot" wins over "spring".
//
// All matches are token-based (word boundaries on whitespace +
// punctuation) so "ssh" no longer matches inside "openssh".
func canonicalProduct(raw string) string {
	low := strings.ToLower(strings.TrimSpace(raw))
	if low == "" {
		return ""
	}
	tokens := tokenize(low)
	ordered := orderedAliases()
	// Pass 1: canonical names. Multi-token canonicals (the more
	// specific entries) get evaluated first thanks to descending-
	// length sort.
	for _, e := range ordered {
		if tokenContains(tokens, e.canonical) {
			return e.canonical
		}
	}
	// Pass 2: aliases. Only reached when no canonical hit — so
	// "apache" alias can't pre-empt "apache tomcat" canonical.
	for _, e := range ordered {
		for _, a := range e.aliases {
			if tokenContains(tokens, a) {
				return e.canonical
			}
		}
	}
	return ""
}

// aliasEntry is one row of the ordered alias table.
type aliasEntry struct {
	canonical string
	aliases   []string
}

// orderedAliasesCache memoizes the sorted alias table — productAliases
// is package-global and immutable after init, so a single sort suffices
// across the process lifetime. Computed lazily on first call to keep the
// package init cheap.
var (
	orderedAliasesOnce  sync.Once
	orderedAliasesCache []aliasEntry
)

func orderedAliases() []aliasEntry {
	orderedAliasesOnce.Do(func() {
		entries := make([]aliasEntry, 0, len(productAliases))
		for canonical, aliases := range productAliases {
			// Per-entry: sort the aliases by descending length so the
			// most specific token (e.g. "spring boot" before "spring")
			// is checked first.
			as := append([]string(nil), aliases...)
			sort.SliceStable(as, func(i, j int) bool {
				return len(as[i]) > len(as[j])
			})
			entries = append(entries, aliasEntry{canonical: canonical, aliases: as})
		}
		// Walk canonicals longest-first so "apache tomcat" beats
		// "apache http server" which beats just "apache" — without this
		// the alias "apache" under "apache http server" wins for a
		// "apache tomcat 9" banner.
		sort.SliceStable(entries, func(i, j int) bool {
			return len(entries[i].canonical) > len(entries[j].canonical)
		})
		orderedAliasesCache = entries
	})
	return orderedAliasesCache
}

// tokenize splits text on whitespace and ASCII punctuation so we can
// do word-boundary matching for alias detection. "apache-tomcat/9.0.30"
// becomes ["apache", "tomcat", "9.0.30"]. Numeric tokens are kept
// because they don't hurt the contains check and may be useful for
// future fuzzy logic.
func tokenize(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool {
		switch {
		case r >= 'a' && r <= 'z':
			return false
		case r >= '0' && r <= '9':
			return false
		case r == '.':
			return false
		default:
			return true
		}
	})
}

// tokenContains returns true if `needle` appears either as a complete
// token sequence (for multi-word aliases like "apache http server" or
// "spring boot") or, for single-word needles, as a standalone token.
// This is the key fix for "ssh" matching inside "openssh": "ssh" is
// only accepted if it's a whole token, never a substring.
func tokenContains(tokens []string, needle string) bool {
	needle = strings.ToLower(strings.TrimSpace(needle))
	if needle == "" {
		return false
	}
	// Re-tokenize the needle with the same splitter we use on the input
	// so a needle like "microsoft-iis" decomposes into ["microsoft","iis"]
	// and matches inputs containing those two tokens in order.
	nTokens := tokenize(needle)
	if len(nTokens) == 0 || len(nTokens) > len(tokens) {
		return false
	}
	if len(nTokens) == 1 {
		// Single token: require a standalone match (no substring hits).
		for _, t := range tokens {
			if t == nTokens[0] {
				return true
			}
		}
		return false
	}
	// Multi-token: do an ordered sub-slice match against tokens.
outer:
	for i := 0; i+len(nTokens) <= len(tokens); i++ {
		for j, nt := range nTokens {
			if tokens[i+j] != nt {
				continue outer
			}
		}
		return true
	}
	return false
}

// versionInRange returns true iff version ∈ [lo, hi] (inclusive).
// Empty bound means open. Versions are compared by dotted-numeric parts;
// non-numeric suffixes are stripped.
//
// Audit note: an EMPTY version returns false from this function — the
// caller (matchInput / matchInputCombined) handles the empty case as
// "unverified product hit" instead of silently dropping.
func versionInRange(version, lo, hi string) bool {
	if version == "" {
		return false
	}
	v := parseVersion(version)
	if lo != "" {
		if cmpVer(v, parseVersion(lo)) < 0 {
			return false
		}
	}
	if hi != "" {
		if cmpVer(v, parseVersion(hi)) > 0 {
			return false
		}
	}
	return true
}

func parseVersion(s string) []int {
	s = strings.TrimSpace(s)
	// Strip common suffixes ("p1", "-rc1", etc.) for comparison.
	for i, r := range s {
		if (r >= '0' && r <= '9') || r == '.' {
			continue
		}
		s = s[:i]
		break
	}
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ".")
	out := make([]int, len(parts))
	for i, p := range parts {
		n, _ := strconv.Atoi(p)
		out[i] = n
	}
	return out
}

func cmpVer(a, b []int) int {
	n := len(a)
	if len(b) > n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		var x, y int
		if i < len(a) {
			x = a[i]
		}
		if i < len(b) {
			y = b[i]
		}
		if x < y {
			return -1
		}
		if x > y {
			return 1
		}
	}
	return 0
}
