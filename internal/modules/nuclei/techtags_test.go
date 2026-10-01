package nuclei

import (
	"reflect"
	"testing"
)

func TestTechTags(t *testing.T) {
	got := TechTags([]string{"Microsoft IIS", "WordPress", "Nginx"})
	want := []string{"iis", "nginx", "wordpress"} // sorted
	if !reflect.DeepEqual(got, want) {
		t.Errorf("TechTags = %v, want %v", got, want)
	}
	// Name variants + dedupe + unknowns dropped.
	got = TechTags([]string{"Apache HTTP Server", "Apache", "Node.js", "jQuery", "Totally Unknown Thing"})
	want = []string{"apache", "nodejs"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("TechTags variants = %v, want %v", got, want)
	}
	if TechTags([]string{"jQuery", "Bootstrap"}) != nil {
		t.Errorf("unknown-only techs should map to nil")
	}
}

func TestEffectiveTagSet(t *testing.T) {
	cfg := ScanConfig{
		Tags: []string{"cve"}, // user-selected tag always applies
		TagsByTarget: map[string][]string{
			"https://a.example.com": {"iis"},
			"b.example.com":         {"wordpress"},
		},
	}
	// Tech host (by URL): user tag + stack tag + generic baseline, sorted.
	got := effectiveTagSet(cfg, "https://a.example.com")
	want := []string{"cve", "default-login", "exposure", "iis", "misconfig", "panel"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("tech-by-url = %v, want %v", got, want)
	}
	// Tech host matched by bare host from a full URL.
	got = effectiveTagSet(cfg, "https://b.example.com:8443/path")
	want = []string{"cve", "default-login", "exposure", "misconfig", "panel", "wordpress"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("tech-by-host = %v, want %v", got, want)
	}
	// No-tech host: only the user tag (no baseline added).
	got = effectiveTagSet(cfg, "https://c.example.com")
	want = []string{"cve"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("no-tech = %v, want %v", got, want)
	}
	// No user tags, no tech → nil (full scan, no -tags).
	if effectiveTagSet(ScanConfig{}, "https://x.example.com") != nil {
		t.Errorf("empty cfg should yield nil tag-set")
	}
}
