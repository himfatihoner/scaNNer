package shared

import (
	"context"
	"net"
	"net/http/httptest"
	"testing"
	"time"
)

func TestNormalizeReachTarget(t *testing.T) {
	cases := []struct {
		in       string
		scheme   string
		host     string
		hostport string
	}{
		{"https://panelhost.example.com/panel/", "https", "panelhost.example.com", "panelhost.example.com:443"},
		{"http://x.com", "http", "x.com", "x.com:80"},
		{"https://x.com:8443/a", "https", "x.com", "x.com:8443"},
		{"bare.host", "https", "bare.host", "bare.host:443"},
		{"bare.host:80", "http", "bare.host", "bare.host:80"},
		{"bare.host:9443", "https", "bare.host", "bare.host:9443"},
		{"", "", "", ""},
	}
	for _, c := range cases {
		s, h, hp := normalizeReachTarget(c.in)
		if s != c.scheme || h != c.host || hp != c.hostport {
			t.Errorf("normalizeReachTarget(%q) = (%q,%q,%q), want (%q,%q,%q)", c.in, s, h, hp, c.scheme, c.host, c.hostport)
		}
	}
}

func TestFilterReachableEmpty(t *testing.T) {
	live, dead := FilterReachable(context.Background(), nil, nil, time.Second, 4)
	if len(live) != 0 || len(dead) != 0 {
		t.Fatalf("empty input should yield empty sets, got live=%v dead=%v", live, dead)
	}
}

// A listener that accepts the TCP connection then drops it immediately — the TLS
// handshake can never complete. This is the legacyhost scenario (TCP opens,
// TLS resets) made deterministic.
func dropListener(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	return ln
}

func TestProbeTLSResetUnreachable(t *testing.T) {
	ln := dropListener(t)
	defer ln.Close()
	ok, reason := Probe(context.Background(), nil, "https://"+ln.Addr().String(), 3*time.Second)
	if ok {
		t.Fatalf("a host that drops the TLS handshake must be unreachable")
	}
	t.Logf("dropped-handshake host correctly unreachable: %s", reason)
}

func TestProbeTCPRefusedUnreachable(t *testing.T) {
	// 127.0.0.1:1 — nothing listening → connection refused.
	ok, reason := Probe(context.Background(), nil, "https://127.0.0.1:1", 2*time.Second)
	if ok {
		t.Fatalf("TCP-refused host must be unreachable (%s)", reason)
	}
}

func TestProbeHTTPPlainReachable(t *testing.T) {
	// http:// only needs an open TCP socket — the drop listener still accepts.
	ln := dropListener(t)
	defer ln.Close()
	ok, reason := Probe(context.Background(), nil, "http://"+ln.Addr().String(), 2*time.Second)
	if !ok {
		t.Fatalf("open TCP http target should be reachable: %s", reason)
	}
}

// The whole point of Workstream A: an INVALID certificate must NOT make a target
// unreachable — the handshake completes under InsecureSkipVerify. httptest's TLS
// server uses a self-signed cert no client would trust.
func TestProbeBadCertReachable(t *testing.T) {
	srv := httptest.NewTLSServer(nil)
	defer srv.Close()
	ok, reason := Probe(context.Background(), nil, srv.URL, 3*time.Second)
	if !ok {
		t.Fatalf("self-signed-cert host must be reachable (handshake completes): %s", reason)
	}
}

func TestFilterReachableSplits(t *testing.T) {
	dead := dropListener(t)
	defer dead.Close()
	live := httptest.NewTLSServer(nil)
	defer live.Close()

	urls := []string{live.URL, "https://" + dead.Addr().String(), live.URL} // dup live
	got, deadMap := FilterReachable(context.Background(), nil, urls, 3*time.Second, 8)
	if len(got) != 1 || got[0] != live.URL {
		t.Fatalf("live set should be [%s] (deduped), got %v", live.URL, got)
	}
	if _, ok := deadMap["https://"+dead.Addr().String()]; !ok {
		t.Fatalf("dead host missing from dead map: %v", deadMap)
	}
}
