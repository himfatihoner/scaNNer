package metacollector

import (
	"reflect"
	"testing"
)

func testAgg() *Aggregator {
	docs := []Document{
		{URL: "https://x/a.pdf", Filetype: "pdf"},
		{URL: "https://x/b.pdf", Filetype: "pdf"},
		{URL: "https://x/c.docx", Filetype: "docx"},
	}
	findings := []Finding{
		{"user", "alice", "XMP:Author", "https://x/a.pdf"},
		{"software", "Word", "PDF:Producer", "https://x/a.pdf"},
		{"path", `\\srv\x`, "XMP:Template", "https://x/a.pdf"},
		{"user", "alice", "XMP:Author", "https://x/b.pdf"},
		{"software", "Acrobat", "PDF:Producer", "https://x/b.pdf"},
		{"user", "bob", "XMP:Author", "https://x/c.docx"},
		{"email", "b@x.com", "Body", "https://x/c.docx"},
		{"date", "2019-05-01T10:00:00", "PDF:CreateDate", "https://x/a.pdf"},
	}
	return NewAggregator(findings, docs)
}

func TestAggCats(t *testing.T) {
	a := testAgg()
	c := a.Cats()
	want := map[string]int{"user": 2, "software": 2, "path": 1, "email": 1, "date": 1}
	for k, v := range want {
		if c[k] != v {
			t.Errorf("Cats[%q] = %d, want %d", k, c[k], v)
		}
	}
}

func TestAggSummaryDistinctDocs(t *testing.T) {
	a := testAgg()
	s := a.Summary("user")
	if len(s) != 2 || s[0].Value != "alice" || s[0].Docs != 2 || s[1].Value != "bob" || s[1].Docs != 1 {
		t.Errorf("Summary(user) = %+v", s)
	}
}

func TestAggByUserCorrelation(t *testing.T) {
	a := testAgg()
	bu := a.ByUser()
	if got := bu["alice"]["software"]; !reflect.DeepEqual(got, []string{"Acrobat", "Word"}) {
		t.Errorf("alice software = %v, want [Acrobat Word]", got)
	}
	if got := bu["alice"]["path"]; !reflect.DeepEqual(got, []string{`\\srv\x`}) {
		t.Errorf("alice path = %v", got)
	}
	if _, ok := bu["bob"]["software"]; ok {
		t.Errorf("bob should have no software correlation")
	}
}

func TestAggByDocument(t *testing.T) {
	a := testAgg()
	bd := a.ByDocument()
	doc := bd["https://x/a.pdf"]
	if doc["filetype"] != "pdf" {
		t.Errorf("filetype = %v", doc["filetype"])
	}
	if got, _ := doc["user"].([]string); !reflect.DeepEqual(got, []string{"alice"}) {
		t.Errorf("a.pdf user = %v", got)
	}
}

func TestAggByValue(t *testing.T) {
	a := testAgg()
	bv := a.ByValue()
	if got := bv["user"]["alice"]; !reflect.DeepEqual(got, []string{"https://x/a.pdf", "https://x/b.pdf"}) {
		t.Errorf("by_value user/alice = %v", got)
	}
}

func TestAggYears(t *testing.T) {
	a := testAgg()
	if y := a.Years(); y["2019"] != 1 {
		t.Errorf("Years = %v", y)
	}
}

func TestAggCorrelationSoftwareOnly(t *testing.T) {
	a := testAgg()
	corr := a.Correlation([]string{"software"}, 15)
	for _, row := range corr {
		if row[0].(string) == "alice" {
			rel := row[1].(map[string][]string)
			if !reflect.DeepEqual(rel["software"], []string{"Acrobat", "Word"}) {
				t.Errorf("alice corr software = %v", rel["software"])
			}
			return
		}
	}
	t.Error("alice not found in correlation")
}
