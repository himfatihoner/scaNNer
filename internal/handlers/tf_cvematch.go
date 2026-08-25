package handlers

import (
	"encoding/json"
	"strings"
	"time"
)

// parseCVEMatchTarget extracts per-target findings from a cvematch scan
// result. Shape: {"inputs":[],"matches":[{product,version,url,cve,severity,
// cvss,description,fixed_in,reference,remediation}],"skipped_no_version":[]}.
// The Match struct embeds Input, so product/version/url are promoted to the
// top level of each matches[] entry. Each match is host-keyed by its url: a
// match with a url that resolves to `target` is emitted; a match with an
// empty url is accepted because the scan config already targeted this host.
// Every match becomes a CatVuln raw.
//
// scanID is part of the contract but ignored here (the engine wires the link).
func parseCVEMatchTarget(resJSON, target string, scanDate time.Time, scanID string, emit func(targetRaw, time.Time)) {
	var res struct {
		Matches []struct {
			Product     string `json:"product"`
			Version     string `json:"version"`
			URL         string `json:"url"`
			CVE         string `json:"cve"`
			Severity    string `json:"severity"`
			Description string `json:"description"`
			FixedIn     string `json:"fixed_in"`
			CVSS        string `json:"cvss"`
			Remediation string `json:"remediation"`
			Reference   string `json:"reference"`
		} `json:"matches"`
	}
	if err := json.Unmarshal([]byte(resJSON), &res); err != nil {
		return
	}

	const maxFindings = 500
	emitted := 0

	for _, m := range res.Matches {
		if emitted >= maxFindings {
			return
		}

		// Host-key: empty url means the scan config already targeted this
		// host — accept. A non-empty url must resolve to this target.
		if u := strings.TrimSpace(m.URL); u != "" && !urlMatchesAsset(u, target) {
			continue
		}

		cve := strings.TrimSpace(m.CVE)
		product := strings.TrimSpace(m.Product)
		version := strings.TrimSpace(m.Version)

		// Title: "<cve> (<product> <version>)". Skip if there's nothing
		// meaningful to title.
		label := strings.TrimSpace(product + " " + version)
		var title string
		switch {
		case cve != "" && label != "":
			title = cve + " (" + label + ")"
		case cve != "":
			title = cve
		case label != "":
			title = label
		}
		if title == "" {
			continue
		}

		detail := strings.TrimSpace(m.Description)
		if fixed := strings.TrimSpace(m.FixedIn); fixed != "" {
			if detail != "" {
				detail += "; fixed in " + fixed
			} else {
				detail = "fixed in " + fixed
			}
		}

		sev := strings.ToUpper(strings.TrimSpace(m.Severity))

		// Typed enrichment: promote the match's structured fields out of the
		// flattened Title/Detail so the findings drawer can render CVE links,
		// references, the version-match proof, and remediation text.
		var cves []string
		if cve != "" {
			cves = []string{cve}
		}
		// Reference is a single free-form field but may carry several
		// whitespace/comma-separated URLs — split so each renders as a link.
		var refs []string
		for _, r := range strings.FieldsFunc(m.Reference, func(c rune) bool {
			return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == ','
		}) {
			if r = strings.TrimSpace(r); r != "" {
				refs = append(refs, r)
			}
		}
		// Evidence is the concrete proof the CVE applies: the detected
		// product/version that fell inside the CVE's affected range, plus the
		// CVSS score when known.
		var evParts []string
		if label != "" {
			evParts = append(evParts, "Detected "+label)
		}
		if cvss := strings.TrimSpace(m.CVSS); cvss != "" && cvss != "0.0" {
			evParts = append(evParts, "CVSS "+cvss)
		}
		evidence := strings.Join(evParts, "; ")

		emit(targetRaw{
			SevRank:     severityRank(sev),
			Severity:    sev,
			Category:    CatVuln,
			Module:      "cvematch",
			Title:       title,
			Detail:      detail,
			Locus:       strings.TrimSpace(m.URL),
			CVEs:        cves,
			References:  refs,
			Evidence:    evidence,
			Remediation: strings.TrimSpace(m.Remediation),
		}, scanDate)
		emitted++
	}
}
