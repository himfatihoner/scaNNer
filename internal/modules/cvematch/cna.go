package cvematch

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"scanner/internal/modules/shared"
)

// CNA enrichment: NVD-published CVEs that are still "Received"/"Awaiting
// Analysis" carry NO CPE configurations, so the NVD parser yields zero rows and
// the (newest, most relevant) CVE is unmatchable. The CVE.org / MITRE record for
// the same CVE already carries the CNA-supplied structured `affected`
// product+version data at publication time. FetchCNARows pulls it and builds
// the same CVERow shape the matcher already understands, so brand-new CVEs match
// without waiting days/weeks for NVD analysis.

const (
	cnaAPIFormat  = "https://cveawg.mitre.org/api/cve/%s"
	cnaFetchLimit = 4 * 1024 * 1024 // response cap
)

// cveOrgRecord is the slice of the CVE 5.x JSON we consume.
type cveOrgRecord struct {
	Containers struct {
		CNA struct {
			Affected []struct {
				Vendor        string `json:"vendor"`
				Product       string `json:"product"`
				DefaultStatus string `json:"defaultStatus"`
				Versions      []struct {
					Version         string `json:"version"`
					Status          string `json:"status"`
					LessThan        string `json:"lessThan"`
					LessThanOrEqual string `json:"lessThanOrEqual"`
				} `json:"versions"`
			} `json:"affected"`
			Metrics []struct {
				CVSSV40 cnaCVSS `json:"cvssV4_0"`
				CVSSV31 cnaCVSS `json:"cvssV3_1"`
				CVSSV30 cnaCVSS `json:"cvssV3_0"`
			} `json:"metrics"`
		} `json:"cna"`
	} `json:"containers"`
}

type cnaCVSS struct {
	BaseScore    float64 `json:"baseScore"`
	BaseSeverity string  `json:"baseSeverity"`
}

// bestCNASeverity picks the highest-versioned CVSS the CNA supplied.
func (r *cveOrgRecord) bestCNASeverity() (sev string, score float64) {
	for _, m := range r.Containers.CNA.Metrics {
		for _, c := range []cnaCVSS{m.CVSSV40, m.CVSSV31, m.CVSSV30} {
			if c.BaseSeverity != "" || c.BaseScore > 0 {
				s := strings.ToUpper(c.BaseSeverity)
				if s == "" {
					s = severityFromScore(c.BaseScore)
				}
				return s, c.BaseScore
			}
		}
	}
	return "", 0
}

// severityFromScore maps a CVSS base score to the NVD severity band.
func severityFromScore(score float64) string {
	switch {
	case score >= 9.0:
		return "CRITICAL"
	case score >= 7.0:
		return "HIGH"
	case score >= 4.0:
		return "MEDIUM"
	case score > 0:
		return "LOW"
	default:
		return "UNKNOWN"
	}
}

func cnaHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 20 * time.Second,
		Transport: &http.Transport{
			MaxIdleConns:        8,
			MaxIdleConnsPerHost: 8,
			IdleConnTimeout:     60 * time.Second,
			// Pin to the killswitch outbound iface like the NVD downloader.
			DialContext: shared.BoundDialer(nil, 15*time.Second).DialContext,
		},
	}
}

var cnaKeyClean = regexp.MustCompile(`[^a-z0-9]+`)

// cnaProductKey renders "vendor:product" in the same lowercased, underscore-
// separated shape parseCPE produces for NVD rows, so CVELookup's exact + suffix
// matching treats a CNA row identically to an NVD one.
func cnaProductKey(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = cnaKeyClean.ReplaceAllString(s, "_")
	return strings.Trim(s, "_")
}

// FetchCNARows fetches the CVE.org record for an unanalyzed CVE and converts its
// CNA `affected` entries into version-bounded CVERows. Returns an empty slice
// (no error) when the record has no usable affected/version data — the caller
// then simply skips that CVE rather than inventing an unbounded match.
func FetchCNARows(ctx context.Context, u UnanalyzedCVE) ([]CVERow, error) {
	url := fmt.Sprintf(cnaAPIFormat, u.CVEID)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("User-Agent", "scaNNer-CVE-Matcher/1.0 (+pentest tool)")
	resp, err := cnaHTTPClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch %s: %w", u.CVEID, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, nil // no MITRE record — nothing to enrich
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("CVE.org %s returned HTTP %d", u.CVEID, resp.StatusCode)
	}
	var rec cveOrgRecord
	if err := json.NewDecoder(io.LimitReader(resp.Body, cnaFetchLimit)).Decode(&rec); err != nil {
		return nil, fmt.Errorf("decode %s: %w", u.CVEID, err)
	}

	// Prefer NVD's severity (passed in); fall back to the CNA-supplied CVSS,
	// which "Received"/unanalyzed CVEs usually carry even before NVD scores them.
	sev, cvss := u.Severity, u.CVSS
	if sev == "" || sev == "UNKNOWN" {
		if cs, sc := rec.bestCNASeverity(); cs != "" {
			sev = cs
			if cvss == 0 {
				cvss = sc
			}
		}
	}
	if sev == "" {
		sev = "UNKNOWN"
	}
	var out []CVERow
	seen := map[string]bool{}
	for _, a := range rec.Containers.CNA.Affected {
		product := strings.TrimSpace(a.Product)
		if product == "" || strings.EqualFold(product, "n/a") {
			continue
		}
		vendor := strings.TrimSpace(a.Vendor)
		if vendor == "" || strings.EqualFold(vendor, "n/a") {
			vendor = product
		}
		pk := cnaProductKey(vendor) + ":" + cnaProductKey(product)
		defAffected := strings.EqualFold(a.DefaultStatus, "affected")

		for _, ve := range a.Versions {
			lo, hi, loInc, hiInc, ok := cnaVersionRange(ve.Version, ve.Status, ve.LessThan, ve.LessThanOrEqual, defAffected)
			if !ok {
				continue
			}
			// Dedup identical (product, lo, hi) rows.
			sig := pk + "|" + lo + "|" + hi
			if seen[sig] {
				continue
			}
			seen[sig] = true
			out = append(out, CVERow{
				CVEID:       u.CVEID,
				ProductKey:  pk,
				ProductName: product,
				VersionLo:   lo,
				VersionHi:   hi,
				LoInc:       loInc,
				HiInc:       hiInc,
				Severity:    sev,
				CVSS:        cvss,
				Description: u.Description,
				Reference:   u.Reference,
				PublishedAt: u.PublishedAt,
				ModifiedAt:  u.ModifiedAt,
			})
		}
	}
	return out, nil
}

// cnaVersionRange maps one CVE 5.x `versions[]` entry to a (lo, hi) affected
// bound. It is deliberately tolerant of the single most common CNA data error:
// encoding "fixed in X" as {version:"0", status:"unaffected", lessThan:"X"}
// (literally "[0,X) is unaffected", which is nonsensical for a vulnerability and
// virtually always means "affected below X"). Rules:
//   - a boundary (lessThan / lessThanOrEqual) with a zero/star/empty base is
//     read as "affected up to the fix" regardless of the status label;
//   - status=affected with a specific base + boundary → that explicit range;
//   - status=affected exact version (no boundary) → that single version;
//   - status=unaffected specific version with defaultStatus=affected → the fix
//     boundary, so affected is everything below it.
//
// Returns ok=false when the entry carries no usable version signal (so the
// caller won't emit an unbounded, false-positive-prone row).
func cnaVersionRange(version, status, lessThan, lessThanOrEqual string, defAffected bool) (lo, hi string, loInc, hiInc, ok bool) {
	version = strings.TrimSpace(version)
	lessThan = strings.TrimSpace(lessThan)
	lessThanOrEqual = strings.TrimSpace(lessThanOrEqual)
	affected := strings.EqualFold(status, "affected")
	unaffected := strings.EqualFold(status, "unaffected")
	baseZero := version == "" || version == "0" || version == "*" || version == "-"

	// Boundary form: [base, boundary).
	if lessThan != "" || lessThanOrEqual != "" {
		bhi, binc := lessThan, false
		if lessThan == "" {
			bhi, binc = lessThanOrEqual, true
		}
		switch {
		case affected:
			lo = ""
			if !baseZero {
				lo = version
			}
			return lo, bhi, true, binc, true
		case unaffected && baseZero:
			// Malformed "fixed in X" → affected below the boundary.
			return "", bhi, false, binc, true
		default:
			// e.g. unaffected [specificVersion, boundary) — can't represent the
			// affected complement cleanly; skip.
			return "", "", false, false, false
		}
	}

	// Exact-version form (no boundary).
	if !baseZero {
		if affected {
			return version, version, true, true, true // single affected version
		}
		if unaffected && defAffected {
			return "", version, false, false, true // fix version → affected below it
		}
	}
	return "", "", false, false, false
}
