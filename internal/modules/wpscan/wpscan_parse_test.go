package wpscan

import (
	"encoding/json"
	"strings"
	"testing"
)

// parse unmarshals a wpscan JSON blob (exercising the struct json tags) and
// runs the pure mapping. rawOutput defaults to the JSON itself.
func parse(t *testing.T, jsonBlob string) *TargetResult {
	t.Helper()
	var raw RawOutput
	if err := json.Unmarshal([]byte(jsonBlob), &raw); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	tr := &TargetResult{URL: "https://site/"}
	populateResult(tr, &raw, jsonBlob)
	return tr
}

func hasFindingTitle(tr *TargetResult, substr string) bool {
	for _, f := range tr.Findings {
		if strings.Contains(f.Title, substr) {
			return true
		}
	}
	return false
}

// Fix 3: config_backups / db_exports / themes / users are parsed and surfaced.
func TestPopulate_EnumeratedCategories(t *testing.T) {
	blob := `{
	  "effective_url": "https://site/",
	  "version": {"number":"6.0","status":"insecure","vulnerabilities":[{"title":"Core XSS","references":{"cve":["2022-1"]}}]},
	  "main_theme": {"slug":"twentytwenty","version":{"number":"1.0"}},
	  "plugins": {"cf7":{"slug":"cf7","vulnerabilities":[{"title":"CF7 RCE","references":{}}]}},
	  "themes": {"twentytwenty":{"slug":"twentytwenty"},"oldtheme":{"slug":"oldtheme","vulnerabilities":[{"title":"OldTheme SQLi","references":{}}]}},
	  "config_backups": {"https://site/wp-config.php.bak":{"found_by":"Direct Access"}},
	  "db_exports": {"https://site/db.sql":{"found_by":"Direct Access"}},
	  "users": {"admin":{"id":1},"editor":{"id":2}}
	}`
	tr := parse(t, blob)

	if tr.Status != "scanned" || !tr.IsWordPress {
		t.Fatalf("want scanned+wordpress, got status=%q isWP=%v", tr.Status, tr.IsWordPress)
	}
	want := []string{
		"WordPress 6.0 (Insecure)", // version insecure
		"Core XSS",                 // version vuln
		"CF7 RCE",                  // plugin vuln
		"OldTheme SQLi",            // non-main theme vuln (the whole point of Fix 3)
		"Exposed wp-config backup", // config_backups
		"Exposed database export",  // db_exports
		"Enumerated user: admin",   // users
		"Enumerated user: editor",
	}
	for _, w := range want {
		if !hasFindingTitle(tr, w) {
			t.Fatalf("missing finding %q; got %d findings: %+v", w, len(tr.Findings), titles(tr))
		}
	}
	// the active theme (twentytwenty, no vulns) must NOT be double-processed into
	// a spurious theme finding.
	if hasFindingTitle(tr, "twentytwenty") {
		t.Fatal("active theme should not appear as its own finding")
	}
	// config backup finding carries the URL.
	for _, f := range tr.Findings {
		if f.Title == "Exposed wp-config backup" && !strings.Contains(f.Description, "wp-config.php.bak") {
			t.Fatalf("config backup finding missing URL, desc=%q", f.Description)
		}
	}
}

// Fix 2: a SUCCESSFUL scan whose vuln free-text contains an abort marker
// ("could not connect") must NOT be discarded — it has a WordPress signal.
func TestPopulate_NoFalseDiscardWithWPSignal(t *testing.T) {
	blob := `{"effective_url":"https://site/","version":{"number":"6.0","status":"latest"},` +
		`"plugins":{"p":{"slug":"p","vulnerabilities":[{"title":"Plugin bug",` +
		`"description":"An unauthenticated attacker where the server could not connect triggers RCE","references":{}}]}}}`
	tr := parse(t, blob)
	if tr.Status != "scanned" || !tr.IsWordPress {
		t.Fatalf("WP scan with abort-marker in a vuln description was wrongly discarded: status=%q err=%q", tr.Status, tr.Error)
	}
	if !hasFindingTitle(tr, "Plugin bug") {
		t.Fatal("plugin vuln finding was dropped")
	}
}

// Regression: a genuine not-WordPress abort (via scan_aborted) is still caught.
func TestPopulate_GenuineNotWordPress(t *testing.T) {
	tr := parse(t, `{"scan_aborted":"The remote website is up, but does not seem to be running WordPress."}`)
	if tr.Status != "not_wordpress" {
		t.Fatalf("want not_wordpress, got %q (err=%q)", tr.Status, tr.Error)
	}
}

// Regression: an abort that leaked as leading text with NO parsed WP signal is
// still caught by the gated free-text fallback.
func TestPopulate_LeadingTextAbortNoSignal(t *testing.T) {
	raw := &RawOutput{} // no WP signal
	tr := &TargetResult{URL: "https://site/"}
	populateResult(tr, raw, "Trace: could not connect to https://site/\n{}")
	if tr.Status != "unreachable" {
		t.Fatalf("want unreachable (gated fallback should fire with no WP signal), got %q", tr.Status)
	}
}

func titles(tr *TargetResult) []string {
	out := make([]string, 0, len(tr.Findings))
	for _, f := range tr.Findings {
		out = append(out, f.Title)
	}
	return out
}
