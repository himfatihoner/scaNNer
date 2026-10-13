package handlers

import "testing"

func personListHas(ps []Person, p Person) bool {
	for _, x := range ps {
		if x == p {
			return true
		}
	}
	return false
}

func personListHasValue(ps []Person, v string) bool {
	for _, x := range ps {
		if x.Value == v {
			return true
		}
	}
	return false
}

func TestScanMetaPeople(t *testing.T) {
	result := `{"findings":[
	  {"category":"email","value":"ali@x.com","tag":"Body","doc_url":"https://docs.example.com/a.pdf"},
	  {"category":"user","value":"Ali Veli","tag":"XMP-dc:Author","doc_url":"https://docs.example.com/a.pdf"},
	  {"category":"email","value":"ali@x.com","tag":"XMP:Creator","doc_url":"https://docs.example.com/b.pdf"},
	  {"category":"user","value":"Mehmet","tag":"PDF:Author","doc_url":"https://files.example.org:8443/c.docx"},
	  {"category":"company","value":"ACME","tag":"XMP:Company","doc_url":"https://docs.example.com/a.pdf"},
	  {"category":"software","value":"Microsoft Word","tag":"PDF:Producer","doc_url":"https://docs.example.com/a.pdf"},
	  {"category":"email","value":"orphan@x.com","tag":"x","doc_url":""}
	]}`

	got := scanMetaPeople("metacollector", result)

	// Keys are normalizeAsset(doc_url): scheme + port stripped, lowercased.
	if len(got) != 2 {
		t.Fatalf("want 2 FQDN keys, got %d: %+v", len(got), got)
	}
	d := got["docs.example.com"]
	if !personListHas(d, Person{Value: "ali@x.com", Kind: "email"}) {
		t.Errorf("missing email on docs.example.com: %+v", d)
	}
	if !personListHas(d, Person{Value: "Ali Veli", Kind: "name"}) {
		t.Errorf("missing name on docs.example.com: %+v", d)
	}
	// company + software dropped; the email is deduped across a.pdf/b.pdf → one entry.
	if personListHasValue(d, "ACME") || personListHasValue(d, "Microsoft Word") {
		t.Errorf("company/software must be dropped: %+v", d)
	}
	if len(d) != 2 {
		t.Errorf("docs.example.com want exactly 2 (email + name), got %d: %+v", len(d), d)
	}
	// Port stripped → files.example.org, one "name".
	f := got["files.example.org"]
	if len(f) != 1 || f[0] != (Person{Value: "Mehmet", Kind: "name"}) {
		t.Errorf("files.example.org = %+v", f)
	}
	// Empty doc_url must not create a key.
	if _, ok := got[""]; ok {
		t.Error("empty doc_url must not create a key")
	}
	// Non-metacollector module → nil.
	if scanMetaPeople("nuclei", result) != nil {
		t.Error("non-metacollector module should return nil")
	}
}
