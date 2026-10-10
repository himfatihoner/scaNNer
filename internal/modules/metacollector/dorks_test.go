package metacollector

import "testing"

func TestCombinedQuery(t *testing.T) {
	got := combinedQuery("example.com", []string{"pdf", "docx", "xlsx"})
	want := "site:example.com (filetype:pdf OR filetype:docx OR filetype:xlsx)"
	if got != want {
		t.Fatalf("combinedQuery = %q, want %q", got, want)
	}
}

func TestPerFiletypeQueries(t *testing.T) {
	got := perFiletypeQueries("example.com", []string{"pdf", "doc"})
	if len(got) != 2 {
		t.Fatalf("want 2 queries, got %d", len(got))
	}
	if got[0].Filetype != "pdf" || got[0].Query != "site:example.com filetype:pdf" {
		t.Errorf("q0 = %+v", got[0])
	}
	if got[1].Filetype != "doc" || got[1].Query != "site:example.com filetype:doc" {
		t.Errorf("q1 = %+v", got[1])
	}
}

func TestDefaultFiletypes(t *testing.T) {
	if len(DefaultFiletypes) != 22 {
		t.Fatalf("want 22 default filetypes, got %d", len(DefaultFiletypes))
	}
	if DefaultFiletypes[0] != "pdf" || DefaultFiletypes[21] != "svg" {
		t.Errorf("unexpected order: first=%s last=%s", DefaultFiletypes[0], DefaultFiletypes[21])
	}
}
