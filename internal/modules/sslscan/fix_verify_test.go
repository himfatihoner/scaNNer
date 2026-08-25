package sslscan

import (
	"crypto/tls"
	"testing"
)

// Regression tests for the "No Modern TLS" false positive (which has recurred
// across two engine rewrites) and the tool-failure recovery paths.

// User's real apphost.example.com console — sslscan died at the Heartbleed probe
// ("TLSv1.3 dying"), truncating its XML, yet the protocol block (printed early)
// clearly shows TLS 1.2/1.3 enabled. We must salvage that.
const apphostConsole = `Version: 2.1.5

Connected to 203.0.113.10

Testing SSL server apphost.example.com on port 443 using SNI name apphost.example.com

  SSL/TLS Protocols:
SSLv2     disabled
SSLv3     disabled
TLSv1.0   disabled
TLSv1.1   disabled
TLSv1.2   enabled
TLSv1.3   enabled

  TLS Fallback SCSV:
Server does not support TLS Fallback SCSV

  Heartbleed:
TLSv1.3 dying `

func TestConsoleSalvage(t *testing.T) {
	ss := parseSslscanConsoleTest(apphostConsole)
	if ss == nil {
		t.Fatal("console salvage returned nil for apphost output")
	}
	enabled := map[string]bool{}
	for _, p := range ss.Protocols {
		enabled[sslscanProtoName(p.Type, p.Version)] = p.Enabled == "1"
	}
	if !enabled["TLS 1.2"] || !enabled["TLS 1.3"] {
		t.Fatalf("salvage missed modern TLS: %+v", enabled)
	}
	if enabled["TLS 1.0"] || enabled["SSL 3.0"] {
		t.Fatalf("salvage wrongly enabled legacy: %+v", enabled)
	}
}

func TestNoModernTLSGuards(t *testing.T) {
	// Empty protocols (both tools failed to enumerate) → must NOT emit the
	// finding: that's asserting a negative from missing evidence.
	if hasFinding(analyzeFindings(&HostResult{Host: "x", Port: 443}), "No Modern TLS") {
		t.Fatal("emitted 'No Modern TLS' from an empty protocol list (false positive)")
	}
	// Only TLS 1.0 supported → SHOULD still emit it (true positive preserved).
	legacy := &HostResult{Protocols: []ProtoResult{{Version: tls.VersionTLS10, Name: "TLS 1.0", Supported: true}}}
	if !hasFinding(analyzeFindings(legacy), "No Modern TLS") {
		t.Fatal("did NOT emit 'No Modern TLS' for a TLS1.0-only server (regression)")
	}
	// TLS 1.2 present → no finding.
	modern := &HostResult{Protocols: []ProtoResult{{Version: tls.VersionTLS12, Name: "TLS 1.2", Supported: true}}}
	if hasFinding(analyzeFindings(modern), "No Modern TLS") {
		t.Fatal("emitted 'No Modern TLS' despite TLS 1.2 supported")
	}
}

func TestBackstopInjectsModern(t *testing.T) {
	// Both tools nil (failed) but the Go version sweep proved TLS 1.3 → backstop
	// must record it supported and suppress the false finding.
	r := &HostResult{Host: "x", Port: 443}
	mergeToolResults(r, nil, nil, map[uint16]bool{tls.VersionTLS13: true})
	if hasFinding(r.Findings, "No Modern TLS") {
		t.Fatal("backstop failed: 'No Modern TLS' emitted with negVer=TLS1.3")
	}
	ok := false
	for _, p := range r.Protocols {
		if p.Version == tls.VersionTLS13 && p.Supported {
			ok = true
		}
	}
	if !ok {
		t.Fatal("backstop did not add a supported TLS 1.3 protocol row")
	}
}

// ftpsvc.example.com false positive: nmap's ssl-enum printed a phantom
// single-cipher "TLSv1.0" section (inconsistent load-balancer), while sslscan
// said disabled and no Go handshake completed. nmap must NOT assert a legacy
// protocol on its own — a version nobody can actually handshake is not an
// exposure.
func TestNmapCannotAssertLegacyAlone(t *testing.T) {
	ss := &sslscanTest{Protocols: []sslscanProto{
		{Type: "tls", Version: "1.0", Enabled: "0"},
		{Type: "tls", Version: "1.1", Enabled: "0"},
		{Type: "tls", Version: "1.2", Enabled: "1"},
	}}
	nm := &nmapSSL{Protocols: map[string]bool{"TLS 1.0": true, "TLS 1.2": true}}
	goVers := map[uint16]bool{tls.VersionTLS12: true} // Go confirmed only 1.2
	r := &HostResult{Host: "ftpsvc.example.com", Port: 443}
	mergeToolResults(r, ss, nm, goVers)

	sup := map[string]bool{}
	for _, p := range r.Protocols {
		sup[p.Name] = p.Supported
	}
	if sup["TLS 1.0"] {
		t.Fatalf("nmap alone wrongly asserted legacy TLS 1.0 (sslscan disabled + no Go handshake): %+v", sup)
	}
	if !sup["TLS 1.2"] {
		t.Fatalf("modern TLS 1.2 lost: %+v", sup)
	}
	if hasFinding(r.Findings, "TLS 1.0") {
		t.Fatal("phantom TLS 1.0 finding emitted")
	}
}

// A COMPLETED Go handshake is authoritative for legacy: it proves the server
// accepts that version, so it's supported even when sslscan didn't examine it
// (hosta.example.com / hostb.example.com — real, openssl-confirmed TLS 1.0/1.1).
func TestGoHandshakeConfirmsLegacy(t *testing.T) {
	nm := &nmapSSL{Protocols: map[string]bool{"TLS 1.0": true}}
	goVers := map[uint16]bool{tls.VersionTLS10: true, tls.VersionTLS12: true}
	r := &HostResult{Host: "hostb.example.com", Port: 443}
	mergeToolResults(r, nil, nm, goVers)

	sup := map[string]bool{}
	for _, p := range r.Protocols {
		sup[p.Name] = p.Supported
	}
	if !sup["TLS 1.0"] {
		t.Fatalf("Go-confirmed legacy TLS 1.0 not marked supported: %+v", sup)
	}
}

func hasFinding(fs []Finding, title string) bool {
	for _, f := range fs {
		if f.Title == title {
			return true
		}
	}
	return false
}
