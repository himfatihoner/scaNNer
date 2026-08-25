package cvematch

import "time"

// Seeder is the small subset of *database.DB needed to persist built-in
// records — kept here so this package doesn't pull in the database
// import directly. Handlers wire the real DB via a closure.
type Seeder func(cveID, source, productKey, productName, versionLo, versionHi string,
	loInc, hiInc bool, fixedIn, severity string, cvss float64,
	description, remediation, reference string,
	publishedAt, modifiedAt time.Time) error

// SeedBuiltin pushes every entry of the in-tree CVEDatabase into the
// SQLite cve_records table with source='builtin'. Called at server
// startup. Re-running it is idempotent: each row's upsert key is
// (cve_id, source, product_key, version_lo, version_hi).
//
// The matcher now reads built-ins from SQLite (not from the Go slice),
// so users get ONE unified source of truth: the cve_records table.
// CVEDatabase stays in the repo as the authoritative seed list — if you
// want to add a curated CVE, edit db.go and the startup seed will
// re-push it.
func SeedBuiltin(upsert Seeder) (int, error) {
	now := time.Now().UTC()
	added := 0
	for _, rec := range CVEDatabase {
		key := canonicalCacheKey(rec.Product)
		if key == "" {
			continue
		}
		lo, hi := rec.AffectedLo, rec.AffectedHi
		// Built-in entries use inclusive bounds. An empty bound means
		// "open ended" — same convention as the NVD downloader.
		loInc := lo != ""
		hiInc := hi != ""
		cvss := 0.0
		// parse CVSS like "9.8" into float — best effort.
		var x float64
		_, _ = parseFloat(rec.CVSS, &x)
		cvss = x
		err := upsert(
			rec.CVE,
			"builtin",
			key,
			rec.Product,
			lo, hi,
			loInc, hiInc,
			rec.FixedIn,
			rec.Severity, cvss,
			rec.Description, rec.Remediation, rec.Reference,
			now, now,
		)
		if err == nil {
			added++
		}
	}
	return added, nil
}

// canonicalCacheKey turns a built-in Product label like "apache http
// server" into the same vendor:product key shape the NVD CPE parser
// produces. Best-effort — the matcher's candidateCacheKeys() function
// tries multiple variants on lookup, so an imperfect key here still
// matches.
func canonicalCacheKey(product string) string {
	// productAliases keys are the canonical names (e.g. "apache http
	// server"). Convert to "apache:http_server" format.
	p := product
	// Crude: split on the first space; first word becomes vendor, rest
	// joined with _ becomes product slug.
	// e.g. "apache http server" → "apache:http_server"
	//      "openssl"            → "openssl:openssl"
	//      "vmware workspace one access" → "vmware:workspace_one_access"
	words := splitFields(p)
	if len(words) == 0 {
		return ""
	}
	for i := range words {
		words[i] = toLower(words[i])
	}
	if len(words) == 1 {
		return words[0] + ":" + words[0]
	}
	return words[0] + ":" + joinUnderscore(words[1:])
}

func splitFields(s string) []string {
	var out []string
	cur := ""
	for _, r := range s {
		if r == ' ' || r == '\t' {
			if cur != "" {
				out = append(out, cur)
				cur = ""
			}
			continue
		}
		cur += string(r)
	}
	if cur != "" {
		out = append(out, cur)
	}
	return out
}

func toLower(s string) string {
	b := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 32
		}
		b[i] = c
	}
	return string(b)
}

func joinUnderscore(parts []string) string {
	out := ""
	for i, p := range parts {
		if i > 0 {
			out += "_"
		}
		out += p
	}
	return out
}

// parseFloat is a minimal float parser that avoids importing strconv just
// for the float case. Returns (n, true) on success.
func parseFloat(s string, dst *float64) (float64, error) {
	if s == "" {
		*dst = 0
		return 0, nil
	}
	// Tiny float parser: integer.fraction
	neg := false
	i := 0
	if i < len(s) && s[i] == '-' {
		neg = true
		i++
	}
	intp := 0.0
	for ; i < len(s) && s[i] >= '0' && s[i] <= '9'; i++ {
		intp = intp*10 + float64(s[i]-'0')
	}
	frac := 0.0
	scale := 1.0
	if i < len(s) && s[i] == '.' {
		i++
		for ; i < len(s) && s[i] >= '0' && s[i] <= '9'; i++ {
			scale *= 10
			frac += float64(s[i]-'0') / scale
		}
	}
	v := intp + frac
	if neg {
		v = -v
	}
	*dst = v
	return v, nil
}
