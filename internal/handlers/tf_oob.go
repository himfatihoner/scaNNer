package handlers

import (
	"encoding/json"
	"strings"
	"time"
)

// tf_oob.go — per-target finding parser for the "oob" (OOB Collaborator) module.
//
// Result shape (from internal/modules/oob/server.go — the DB envelope written by
// internal/handlers/oob.go is a flat {"interactions":[...]} wrapper around the
// oob.Interaction slice):
//
//	{"interactions":[{
//	    "kind":"http",                 // "http" | "dns"
//	    "token":"...",
//	    "at":"2026-07-16T12:00:00Z",   // RFC3339
//	    "remote_addr":"1.2.3.4:5555",
//	    "host":"oob.scanner.local",
//	    "method":"GET",
//	    "path":"/token-1",
//	    "user_agent":"curl/8.0",
//	    "body_snippet":"...",
//	    "subdomain":"abc.oob.scanner.local"
//	}]}
//
// Host key: NONE. The collaborator is a single listener minted for one scan, so
// every recorded interaction belongs to the scan-config's targeted host — we
// emit them all rather than filtering on a per-item host field.
//
// Category mapping:
//   - interactions[] -> CatOOB, SevRank -1 (recon fact, no severity)
//       Title  = "<kind> callback from <remote_addr>"
//       Detail = method + path + user_agent
//       Locus  = subdomain (preferred) or host
//
// Timestamp: prefer the per-item RFC3339 `at` when non-zero; else scanDate.

// Safety cap so a flooded collaborator can't spawn unbounded rows (the in-memory
// ring in server.go already caps at ~500, but the DB blob is trusted input).
const maxOobInteractions = 1000

func parseOobTarget(resJSON, target string, scanDate time.Time, scanID string, emit func(targetRaw, time.Time)) {
	_ = scanID // engine owns the scan link; parser ignores scanID by contract.
	_ = target // collaborator has no per-item host key; the scan already targeted this host.

	var res struct {
		Interactions []struct {
			Kind        string    `json:"kind"`
			Token       string    `json:"token"`
			At          time.Time `json:"at"`
			RemoteAddr  string    `json:"remote_addr"`
			Host        string    `json:"host"`
			Method      string    `json:"method"`
			Path        string    `json:"path"`
			UserAgent   string    `json:"user_agent"`
			BodySnippet string    `json:"body_snippet"`
			Subdomain   string    `json:"subdomain"`
		} `json:"interactions"`
	}
	if err := json.Unmarshal([]byte(resJSON), &res); err != nil {
		return
	}

	for i, in := range res.Interactions {
		if i >= maxOobInteractions {
			break
		}

		kind := strings.TrimSpace(in.Kind)
		remote := strings.TrimSpace(in.RemoteAddr)

		// Title needs at least a kind or a source to be meaningful.
		if kind == "" && remote == "" {
			continue
		}
		label := kind
		if label == "" {
			label = "callback"
		} else {
			label = kind + " callback"
		}
		title := label
		if remote != "" {
			title = label + " from " + remote
		}

		// Detail = method + path + user_agent.
		var parts []string
		method := strings.TrimSpace(in.Method)
		path := strings.TrimSpace(in.Path)
		if method != "" || path != "" {
			parts = appendUnique(parts, strings.TrimSpace(method+" "+path))
		}
		if ua := strings.TrimSpace(in.UserAgent); ua != "" {
			parts = appendUnique(parts, "UA: "+ua)
		}
		detail := strings.Join(parts, " — ")

		// Locus = subdomain preferred, else host.
		locus := strings.TrimSpace(in.Subdomain)
		if locus == "" {
			locus = strings.TrimSpace(in.Host)
		}

		when := scanDate
		if !in.At.IsZero() {
			when = in.At
		}

		emit(targetRaw{
			Module:   "oob",
			Category: CatOOB,
			Title:    title,
			Detail:   detail,
			Locus:    locus,
			Severity: "",
			SevRank:  -1,
		}, when)
	}
}
