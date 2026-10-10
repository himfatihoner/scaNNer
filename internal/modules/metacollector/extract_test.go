package metacollector

import "testing"

func TestClassify(t *testing.T) {
	cases := []struct {
		grp, suffix, want string
	}{
		{"", "author", "user"},
		{"", "lastmodifiedby", "user"},
		{"", "producer", "software"},
		{"", "creatortool", "software"}, // exact-suffix: not confused with 'creator'
		{"PDF", "creator", "software"},  // bare creator in a pdf group → software
		{"XMP-pdf", "creator", "software"},
		{"XMP-dc", "creator", "user"}, // bare creator elsewhere → user
		{"", "company", "company"},
		{"", "template", "path"},
		{"", "operatingsystem", "os"},
		{"", "createdate", "date"},
		{"", "printername", "printer"},
		{"", "gpslatitude", "gps"},
		{"", "pagecount", ""},
	}
	for _, c := range cases {
		if got := classify(c.grp, c.suffix); got != c.want {
			t.Errorf("classify(%q,%q) = %q, want %q", c.grp, c.suffix, got, c.want)
		}
	}
}

func hasFinding(fs []rawFinding, cat, value string) bool {
	for _, f := range fs {
		if f.cat == cat && f.value == value {
			return true
		}
	}
	return false
}

func TestCategorizeSoftwareHint(t *testing.T) {
	// An Author value that is clearly software is reclassified user→software.
	out := categorize("XMP-dc", "XMP-dc:Author", "Microsoft Word 2019")
	if !hasFinding(out, "software", "Microsoft Word 2019") {
		t.Errorf("software-hint override failed: %+v", out)
	}
	if hasFinding(out, "user", "Microsoft Word 2019") {
		t.Errorf("value should not remain a user finding: %+v", out)
	}
}

func TestCategorizePathGate(t *testing.T) {
	// A template value that is not path-like is dropped (not stored as path).
	out := categorize("", "XML:Template", "Normal.dotm")
	if hasFinding(out, "path", "Normal.dotm") {
		t.Errorf("non-path template should be gated out: %+v", out)
	}
	// A path-like template is kept.
	out2 := categorize("", "XML:Template", `C:\Templates\corp.dotx`)
	if !hasFinding(out2, "path", `C:\Templates\corp.dotx`) {
		t.Errorf("path-like template should be kept: %+v", out2)
	}
}

func TestCategorizeRegexHarvest(t *testing.T) {
	out := categorize("", "XMP:Subject", `contact me at Bob@Example.COM or \\FILE01\share`)
	// Email is harvested over any tag value and lowercased.
	if !hasFinding(out, "email", "bob@example.com") {
		t.Errorf("email not harvested/lowercased: %+v", out)
	}
	// A mid-string UNC/path is caught by the PATH regex (the server regex is
	// start-anchored, so it does NOT fire here).
	if !hasFinding(out, "path", `\\FILE01\share`) {
		t.Errorf("mid-string UNC path not harvested: %+v", out)
	}
	if hasFinding(out, "server", "FILE01") {
		t.Errorf("server regex is anchored; it must NOT match a mid-string UNC: %+v", out)
	}

	// An anchored UNC value DOES yield a server finding.
	out2 := categorize("", "XMP:Comment", `\\DC01\netlogon`)
	if !hasFinding(out2, "server", "DC01") {
		t.Errorf("anchored UNC should yield a server: %+v", out2)
	}
}

func TestClean(t *testing.T) {
	cases := []struct{ in, want string }{
		{"  Foo®  ", "Foo"},
		{"Ahmet Yılmaz", "Ahmet Yılmaz"},
		{"a\x00b", ""},       // control char
		{"a\uFFFDb", ""},     // replacement char
		{"§§§§", ""},         // mostly non-ok symbols, len>=4
	}
	for _, c := range cases {
		if got := clean(c.in); got != c.want {
			t.Errorf("clean(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestNormDate(t *testing.T) {
	if v, ok := normDate("2019:05:01 12:30:00"); !ok || v != "2019-05-01T12:30:00" {
		t.Errorf("normDate basic = %q,%v", v, ok)
	}
	if v, ok := normDate("2019:05:01 12:30:00+03:00"); !ok || v != "2019-05-01T12:30:00+03:00" {
		t.Errorf("normDate tz = %q,%v", v, ok)
	}
	if v, ok := normDate("0000:00:00 00:00:00"); ok || v != "" {
		t.Errorf("zeroed date should drop, got %q,%v", v, ok)
	}
	if v, ok := normDate("not a date"); !ok || v != "not a date" {
		t.Errorf("non-date falls back to clean, got %q,%v", v, ok)
	}
}

func TestServerFromAnchored(t *testing.T) {
	if s := serverFrom(`\\SRV01\share\x`); s != "SRV01" {
		t.Errorf("serverFrom anchored = %q, want SRV01", s)
	}
	if s := serverFrom(`prefix \\SRV\s`); s != "" {
		t.Errorf("serverFrom should require start-anchor, got %q", s)
	}
}

func TestLooksPath(t *testing.T) {
	for _, p := range []string{`C:\x`, `/etc/x`, `a:b`, `x%5cy`} {
		if !looksPath(p) {
			t.Errorf("looksPath(%q) = false, want true", p)
		}
	}
	if looksPath("plainword") {
		t.Errorf("looksPath(plainword) = true, want false")
	}
}

func TestEmitBodyUNC(t *testing.T) {
	out := emitBody(`email a@b.com and path \\DC01\sysvol\policies`)
	if !hasFinding(out, "email", "a@b.com") {
		t.Errorf("body email missing: %+v", out)
	}
	if !hasFinding(out, "server", "DC01") {
		t.Errorf("body UNC server missing: %+v", out)
	}
}

func TestStringifyValue(t *testing.T) {
	if stringifyValue(nil) != "" {
		t.Error("nil should stringify empty")
	}
	if stringifyValue(float64(2019)) != "2019" {
		t.Errorf("integer float = %q", stringifyValue(float64(2019)))
	}
	if got := stringifyValue([]interface{}{"a@b.com", "c@d.com"}); got != "a@b.com, c@d.com" {
		t.Errorf("slice join = %q", got)
	}
}
