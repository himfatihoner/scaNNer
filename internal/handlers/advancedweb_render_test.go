package handlers

// Render smoke test for the advancedweb suite overview + the new per-module
// sub-pages (?stage=<id>). It calls the real handler against the real template
// set and a real done scan, so a template execution error (nil deref, wrong
// type to index, a dict key a reused *_results_inner needs) surfaces as a 500
// instead of reaching production. No auth/HTTP middleware is involved — the
// handler func is invoked directly, which is exactly what a unit test should do.
//
// Needs data/scanner.db to hold the done advancedweb scan below; skips cleanly
// if the DB or scan isn't present (e.g. CI without the dev DB).

import (
	"net/http/httptest"
	"os"
	"testing"

	"scanner/internal/database"
	"scanner/internal/modules"
	"scanner/internal/modules/advancedweb"
)

func TestAdvancedWebStageRender(t *testing.T) {
	const dbPath = "../../data/scanner.db"
	const scanID = "314bc4f8-d421-4821-94f8-b0d616de44fe"
	if _, err := os.Stat(dbPath); err != nil {
		t.Skipf("dev DB not present (%v) — skipping render smoke test", err)
	}
	db, err := database.New(dbPath)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer db.Close()
	if _, err := db.GetScan(scanID); err != nil {
		t.Skipf("test scan %s not in DB (%v) — skipping", scanID, err)
	}

	reg := modules.NewRegistry()
	reg.Register(&advancedweb.Module{})
	h, err := New(reg, db, "../../web/templates")
	if err != nil {
		t.Fatalf("new handler: %v", err)
	}

	stages := []string{"", "whoisinfo", "dnsenum", "httpxfind", "sslscan", "wafdetect",
		"techdetect", "cvematch", "wpscan", "nuclei", "dirspider", "httpmethods", "secheaders"}
	for _, st := range stages {
		for _, partial := range []string{"", "&partial=1"} {
			url := "/modules/advancedweb/results/" + scanID
			if st != "" {
				url += "?stage=" + st + partial
			} else if partial != "" {
				url += "?partial=1"
			}
			rec := httptest.NewRecorder()
			req := httptest.NewRequest("GET", url, nil)
			h.AdvancedWebResults(rec, req)
			if rec.Code != 200 {
				body := rec.Body.String()
				if len(body) > 800 {
					body = body[:800]
				}
				t.Errorf("stage=%q partial=%q: HTTP %d\n%s", st, partial, rec.Code, body)
			}
		}
	}
}
