package handlers

import (
	"encoding/json"
	"reflect"
	"sort"
	"testing"
)

// TestExtractVulnsGenericKeepsInfo proves the extractor now RETAINS info-severity
// findings (SevRank 0) alongside rank≥1 ones, so the info index can see them.
func TestExtractVulnsGenericKeepsInfo(t *testing.T) {
	res := `{"results":[{"url":"https://a.example.com","findings":[
		{"severity":"high","title":"SQLi","template_id":"sqli"},
		{"severity":"info","title":"WordPress Detected","template_id":"wordpress-detect"}
	]}]}`
	got := extractVulnsGeneric(json.RawMessage(res), vulnInherit{})
	var sawHigh, sawInfo bool
	for _, v := range got {
		if v.Title == "SQLi" && v.SevRank == 3 {
			sawHigh = true
		}
		if v.Title == "WordPress Detected" && v.SevRank == 0 && isInfoSev(v.Severity) {
			sawInfo = true
		}
	}
	if !sawHigh {
		t.Error("expected the high finding to be extracted")
	}
	if !sawInfo {
		t.Error("expected the info finding to be kept (SevRank 0, severity INFO)")
	}
}

// TestInfoAggregator covers dedup-by-title, host aggregation, non-info exclusion,
// and the most-widespread-first ordering.
func TestInfoAggregator(t *testing.T) {
	ag := newInfoAggregator()
	ag.add(GlobalVuln{Title: "WordPress Detected", Severity: "INFO", SevRank: 0, Host: "https://a.example.com", Module: "nuclei", Tool: "nuclei", CheckID: "wordpress-detect"})
	ag.add(GlobalVuln{Title: "WordPress Detected", Severity: "info", SevRank: 0, Host: "https://b.example.com:443/x"})
	ag.add(GlobalVuln{Title: "Server Header", Severity: "INFO", SevRank: 0, Host: "https://a.example.com"})
	ag.add(GlobalVuln{Title: "SQLi", Severity: "HIGH", SevRank: 3, Host: "https://a.example.com"})     // excluded (rank≥1)
	ag.add(GlobalVuln{Title: "Recon", Severity: "UNKNOWN", SevRank: 0, Host: "https://a.example.com"}) // excluded (not info)

	out := ag.result()
	if len(out) != 2 {
		t.Fatalf("want 2 deduped info findings, got %d: %+v", len(out), out)
	}
	wp := out[0] // most widespread first → 2 hosts
	if wp.Title != "WordPress Detected" {
		t.Fatalf("want 'WordPress Detected' first, got %q", wp.Title)
	}
	if wp.Count != 2 {
		t.Errorf("Count = %d, want 2", wp.Count)
	}
	want := []string{normalizeAsset("https://a.example.com"), normalizeAsset("https://b.example.com:443/x")}
	sort.Strings(want)
	if !reflect.DeepEqual(wp.Hosts, want) {
		t.Errorf("Hosts = %v, want %v", wp.Hosts, want)
	}
	if wp.ID != infoID("WordPress Detected") {
		t.Errorf("ID = %q, want %q", wp.ID, infoID("WordPress Detected"))
	}
	for _, v := range out {
		if v.Title == "SQLi" || v.Title == "Recon" {
			t.Errorf("non-info finding %q leaked into the info index", v.Title)
		}
	}
}
