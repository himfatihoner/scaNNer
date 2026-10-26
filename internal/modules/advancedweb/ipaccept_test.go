package advancedweb

import (
	"strings"
	"testing"

	"scanner/internal/modules/shared"
)

// All stages OFF → Scan does no network; exercises classification + partition +
// stage-skip bookkeeping only.

func TestIPOnlyAccepted_NoNetwork(t *testing.T) {
	out, err := Scan(Config{
		Targets:       []string{"192.0.2.10"}, // TEST-NET-1 (RFC 5737)
		EnableWhois:   true,                    // enabled but must SKIP (no domain), no network
		EnableDNSEnum: true,
	}, &shared.HTTPOptions{}, 1, nil, nil, nil)
	if err != nil {
		t.Fatalf("IP-only target must be accepted, got error: %v", err)
	}
	if out == nil || out.Kind != string(shared.KindIP) {
		t.Fatalf("want Kind=ip, got %+v", out)
	}
	for _, s := range []Stage{StageWhois, StageDNSEnum} {
		sr := out.Stages[s]
		if sr == nil || sr.Status != StatusSkipped || !strings.Contains(sr.Message, "domain") {
			t.Fatalf("stage %v: want skipped+domain-msg, got %+v", s, sr)
		}
	}
}

func TestMixedAccepted(t *testing.T) {
	out, err := Scan(Config{
		Targets: []string{"192.0.2.10", "example.com", "https://192.0.2.11/app", "2001:db8::1"},
	}, &shared.HTTPOptions{}, 1, nil, nil, nil)
	if err != nil || out == nil {
		t.Fatalf("mixed IPv4+domain+URL+IPv6 must be accepted, got err=%v", err)
	}
}

func TestGenuinelyInvalidOrUnsafeRejected(t *testing.T) {
	for _, bad := range []string{"not a target", "  ", "also/bad"} {
		if _, err := Scan(Config{Targets: []string{bad}}, &shared.HTTPOptions{}, 1, nil, nil, nil); err == nil {
			t.Fatalf("invalid target %q must be rejected", bad)
		}
	}
}

func TestClassifyGuards(t *testing.T) {
	// IPs accepted (v4 + v6).
	for _, ip := range []string{"192.0.2.10", "10.0.0.1", "::1", "2001:db8::1"} {
		c, err := shared.ClassifyInput(ip)
		if err != nil || c.Kind != shared.KindIP {
			t.Fatalf("ClassifyInput(%q) want ip, got kind=%v err=%v", ip, c.Kind, err)
		}
	}
	// Leading-dash + shell metachars rejected (flag-injection / argv safety).
	for _, bad := range []string{"-oN.evil.com", "--datadir=.x.com", "a;id.com", "a|b.com", "a$b.com", "a`b.com", "a&b.com"} {
		if _, err := shared.ClassifyInput(bad); err == nil {
			t.Fatalf("ClassifyInput(%q) must be rejected (unsafe)", bad)
		}
	}
	// Legit domain still accepted.
	if c, err := shared.ClassifyInput("sub.example-site.com"); err != nil || c.Kind != shared.KindDomain {
		t.Fatalf("legit domain must classify as domain, got kind=%v err=%v", c.Kind, err)
	}
}

func TestEnsureURLBracketsIPv6(t *testing.T) {
	cases := map[string]string{
		"192.0.2.10":  "https://192.0.2.10",
		"example.com": "https://example.com",
	}
	for in, want := range cases {
		c, _ := shared.ClassifyInput(in)
		if got := c.EnsureURL(); got != want {
			t.Fatalf("EnsureURL(%q) = %q, want %q", in, got, want)
		}
	}
	// IPv6 must be bracketed into a parseable URL.
	c, _ := shared.ClassifyInput("2001:db8::1")
	if got := c.EnsureURL(); got != "https://[2001:db8::1]" {
		t.Fatalf("EnsureURL(ipv6) = %q, want https://[2001:db8::1]", got)
	}
}
