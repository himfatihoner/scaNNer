package handlers

import "testing"

func TestNormalizeSSLTarget(t *testing.T) {
	cases := map[string]string{
		"https://apphost.example.com":            "apphost.example.com",
		"https://apphost.example.com/giris":      "apphost.example.com",
		"https://apphost.example.com:8443/x":     "apphost.example.com",
		"http://example.com/a/b?q=1":            "example.com",
		"apphost.example.com/giris":              "apphost.example.com", // scheme-less path
		"apphost.example.com":                    "apphost.example.com", // bare host untouched
		"10.0.0.0/24":                           "10.0.0.0/24",        // CIDR untouched
		"192.168.1.1-50":                        "192.168.1.1-50",     // range untouched
		"2001:db8::/32":                         "2001:db8::/32",      // IPv6 CIDR untouched
		"  https://spaced.example.com/  ":       "spaced.example.com",
	}
	for in, want := range cases {
		if got := normalizeSSLTarget(in); got != want {
			t.Errorf("normalizeSSLTarget(%q) = %q, want %q", in, got, want)
		}
	}
}
