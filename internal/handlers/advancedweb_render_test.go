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
	"strings"
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

// TestAdvancedWebStageRunningNoConsoleLeak exercises the EXACT failing condition
// the done-scan smoke test above cannot: a RUNNING suite. The bug was that a
// per-stage sub-page (e.g. CVE Matcher) pulled in the suite-wide scan_progress
// panel, whose poller painted the whole scan's live log (a running Nuclei
// stage's output) into a console ON the CVE Matcher page. The poller's guard is
// only live while the scan is running/pending — so a done scan never reproduces
// it. Here we create a fresh running suite scan and assert the stage sub-page
// carries NO suite console/panel but KEEPS its auto-refresh poller, while the
// suite OVERVIEW still shows the console.
func TestAdvancedWebStageRunningNoConsoleLeak(t *testing.T) {
	dir := t.TempDir()
	db, err := database.New(dir + "/t.db")
	if err != nil {
		t.Fatalf("db: %v", err)
	}
	defer db.Close()
	ws, err := db.CreateWorkspace("t", "")
	if err != nil {
		t.Fatalf("workspace: %v", err)
	}
	scan, err := db.CreateScan(ws.ID, "advancedweb", "{}", 10)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if !db.MarkRunning(scan.ID) {
		t.Fatal("MarkRunning returned false")
	}
	db.UpdateScanResult(scan.ID, `{"stages":{"cvematch":{"stage":"cvematch","status":"done","message":"5 CVE matches"}}}`)

	reg := modules.NewRegistry()
	reg.Register(&advancedweb.Module{})
	h, err := New(reg, db, "../../web/templates")
	if err != nil {
		t.Fatalf("new handler: %v", err)
	}

	render := func(url string) string {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", url, nil)
		h.AdvancedWebResults(rec, req)
		if rec.Code != 200 {
			t.Fatalf("%s: HTTP %d", url, rec.Code)
		}
		return rec.Body.String()
	}

	// CVE Matcher sub-page of a RUNNING suite: no suite-wide console/panel.
	stage := render("/modules/advancedweb/results/" + scan.ID + "?stage=cvematch")
	if strings.Contains(stage, `id="scanLog"`) {
		t.Error("REGRESSION: suite console (#scanLog) rendered on the CVE Matcher stage page")
	}
	if strings.Contains(stage, "Scan in progress") {
		t.Error("REGRESSION: suite progress panel rendered on the CVE Matcher stage page")
	}
	// ...but it MUST still carry the poller so the stage auto-refreshes.
	if !strings.Contains(stage, "refreshContent") {
		t.Error("stage sub-page lost its auto-refresh poller")
	}
	// Sanity: the OVERVIEW of the same running suite SHOULD still show the console.
	overview := render("/modules/advancedweb/results/" + scan.ID)
	if !strings.Contains(overview, `id="scanLog"`) {
		t.Error("overview unexpectedly lost its suite console")
	}
}
