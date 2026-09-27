package shared

import "testing"

func TestPickUserAgent(t *testing.T) {
	pool := []string{"UA-A", "UA-B", "UA-C"}

	// Fixed mode → the explicit UserAgent.
	o := &HTTPOptions{UserAgent: "UA-FIXED", UserAgents: pool, RotateUA: false}
	if got := o.PickUserAgent(); got != "UA-FIXED" {
		t.Fatalf("fixed: got %q want UA-FIXED", got)
	}

	// Fixed mode, no explicit UA → first pool entry.
	o = &HTTPOptions{UserAgents: pool, RotateUA: false}
	if got := o.PickUserAgent(); got != "UA-A" {
		t.Fatalf("fixed/first: got %q want UA-A", got)
	}

	// Rotate mode → always a pool member.
	o = &HTTPOptions{UserAgents: pool, RotateUA: true}
	in := map[string]bool{"UA-A": true, "UA-B": true, "UA-C": true}
	for i := 0; i < 50; i++ {
		if got := o.PickUserAgent(); !in[got] {
			t.Fatalf("rotate: got %q not in pool", got)
		}
	}

	// nil-safe.
	if (*HTTPOptions)(nil).PickUserAgent() != "" {
		t.Fatal("nil opts should return empty UA")
	}
}

func TestInjectNmapUserAgent(t *testing.T) {
	// A UA with a comma inside — must be double-quoted so it doesn't split the
	// comma-separated --script-args list.
	ua := "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0"
	SetGlobalUserAgent(ua)
	defer SetGlobalUserAgent("")

	want := `http.useragent="` + ua + `"`

	// No scripts → untouched.
	plain := []string{"-sV", "-p", "80"}
	if got := injectNmapUserAgent(append([]string(nil), plain...)); len(got) != len(plain) {
		t.Fatalf("no-script scan should be untouched, got %v", got)
	}

	// -sC present, no existing --script-args → appended.
	got := injectNmapUserAgent([]string{"-sC", "-p", "80"})
	if !lastTwo(got, "--script-args", want) {
		t.Fatalf("append: got %v want trailing --script-args %q", got, want)
	}

	// Existing --script-args → merged (comma-joined), our kv last.
	got = injectNmapUserAgent([]string{"--script", "http-title", "--script-args", "userdb=/x,passdb=/y"})
	found := false
	for _, a := range got {
		if a == "userdb=/x,passdb=/y,"+want {
			found = true
		}
	}
	if !found {
		t.Fatalf("merge: expected existing script-args to gain %q, got %v", want, got)
	}

	// No UA set → untouched even with scripts.
	SetGlobalUserAgent("")
	if got := injectNmapUserAgent([]string{"-sC"}); len(got) != 1 {
		t.Fatalf("no UA: should be untouched, got %v", got)
	}
}

func lastTwo(s []string, a, b string) bool {
	return len(s) >= 2 && s[len(s)-2] == a && s[len(s)-1] == b
}
