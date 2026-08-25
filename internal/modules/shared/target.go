package shared

import (
	"errors"
	"net"
	"net/url"
	"strings"
)

// InputKind classifies a single user-supplied scan target so callers can
// branch on what's actually been given (vs. blindly assuming a URL).
type InputKind string

const (
	KindIP     InputKind = "ip"
	KindDomain InputKind = "domain"
	KindURL    InputKind = "url"
)

// ClassifiedInput is the parsed view of a target string. For URLs the
// scheme/host/path are split out; for domains and IPs the Host field
// carries the literal value and Scheme/Path are empty.
type ClassifiedInput struct {
	Raw    string
	Kind   InputKind
	Scheme string // "http" / "https" — only filled for KindURL
	Host   string // hostname (without port) for URL/domain; the IP literal for IP
	Port   string // empty unless URL contained an explicit port
	Path   string // empty unless URL had a path
}

// ClassifyInput returns what the input looks like — URL, plain IP, or
// bare domain. Whitespace is trimmed; an explicit `http(s)://` prefix
// forces URL classification. For raw IPs, both v4 and v6 are recognised.
// Domains require at least one dot and no characters that would make
// them invalid (whitespace, schemes, slashes).
func ClassifyInput(s string) (ClassifiedInput, error) {
	out := ClassifiedInput{Raw: strings.TrimSpace(s)}
	if out.Raw == "" {
		return out, errors.New("empty target")
	}

	// Explicit URL form.
	low := strings.ToLower(out.Raw)
	if strings.HasPrefix(low, "http://") || strings.HasPrefix(low, "https://") {
		u, err := url.Parse(out.Raw)
		if err != nil {
			return out, err
		}
		if u.Host == "" {
			return out, errors.New("URL missing host")
		}
		out.Kind = KindURL
		out.Scheme = u.Scheme
		out.Host = u.Hostname()
		out.Port = u.Port()
		out.Path = u.Path
		return out, nil
	}

	// Bare IP — must not contain slashes or hyphen-ranges (those are
	// CIDR / range syntax, not a single target the suite would scan).
	if strings.ContainsAny(out.Raw, "/ \t") {
		return out, errors.New("target contains whitespace, slash, or range syntax — not supported")
	}
	if ip := net.ParseIP(out.Raw); ip != nil {
		out.Kind = KindIP
		out.Host = out.Raw
		return out, nil
	}

	// Bare domain — must contain a dot, nothing weird.
	if !strings.Contains(out.Raw, ".") {
		return out, errors.New("target is neither URL, IP, nor domain")
	}
	for _, r := range out.Raw {
		if r == '\n' || r == '\r' {
			return out, errors.New("target contains newline")
		}
	}
	out.Kind = KindDomain
	out.Host = out.Raw
	return out, nil
}

// EnsureURL returns a usable absolute URL for stages that need one.
// For URL inputs it returns the original. For domains it prefixes
// "https://". IPs are returned as-is with https:// (caller may downgrade).
func (c ClassifiedInput) EnsureURL() string {
	if c.Kind == KindURL {
		return c.Raw
	}
	return "https://" + c.Host
}

// SafeTarget validates a user-supplied target value before it reaches a
// subprocess (nmap, smbclient, whois, enum4linux, etc.). Returns
// (target, true) when the value is safe, (target, false) when it would
// expand into command-line flags or contain control characters.
//
// Audit K04/K09: hostdiscovery and smbenum both passed cfg.Targets[i]
// straight into shared.Command(ctx, "nmap", ..., target). An attacker who
// can submit a scan with target value "--script=http-shellshock-exploit"
// or "--script=/path/to/malicious.nse" turns nmap into a remote-script
// exec. Same shape applies to any module that exec's a target.
// Reject:
//   - empty / whitespace-only
//   - leading "-" (flag injection)
//   - any whitespace (lets attacker append "extra args")
//   - shell metachars: ; | & $ ` < > \ " '
//   - newline / control bytes
func SafeTarget(s string) (string, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", false
	}
	if strings.HasPrefix(s, "-") {
		return s, false
	}
	for _, r := range s {
		// Anything below space or DEL is unacceptable.
		if r < 0x20 || r == 0x7f {
			return s, false
		}
		switch r {
		case ' ', '\t', ';', '|', '&', '$', '`', '<', '>', '"', '\'', '\\':
			return s, false
		}
	}
	return s, true
}
