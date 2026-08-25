package sslscan

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"scanner/internal/modules/shared"
	"strconv"
	"strings"
	"sync"
	"time"
)

// tlsVersionNames maps version IDs to human names
var tlsVersionNames = map[uint16]string{
	0x0002:           "SSL 2.0",
	tls.VersionSSL30: "SSL 3.0",
	tls.VersionTLS10: "TLS 1.0",
	tls.VersionTLS11: "TLS 1.1",
	tls.VersionTLS12: "TLS 1.2",
	tls.VersionTLS13: "TLS 1.3",
}

// tlsVersionsToTest are the versions the in-process Go sweep handshakes. It
// covers TLS 1.0–1.3: a COMPLETED handshake is authoritative proof the server
// actually accepts that version (mergeToolResults trusts it for legacy too),
// which is exactly what refutes nmap's phantom single-cipher legacy sections
// (ftpsvc.example.com) while confirming genuine legacy support (hosta/hostb).
// A completed legacy handshake IS a real exposure — even against one backend of
// a shared load-balancer IP, that backend answered TLS 1.0 on this name/cert.
// crypto/tls cannot speak SSL 2.0/3.0, so those are left to sslscan.
var tlsVersionsToTest = []uint16{
	tls.VersionTLS13,
	tls.VersionTLS12,
	tls.VersionTLS11,
	tls.VersionTLS10,
}

// untestedLegacyProtocols are protocol versions Go's crypto/tls cannot
// probe. We emit them as ProtoResult{Untested: true} so the UI can
// render an explicit "not tested — verify with sslscan/testssl.sh"
// marker instead of silently misreporting them as not supported.
var untestedLegacyProtocols = []uint16{
	0x0002,           // SSL 2.0
	tls.VersionSSL30, // SSL 3.0
}

// cipherSuitesToTest includes all known cipher suites for probing
var cipherSuitesToTest []uint16

func init() {
	// Collect all cipher suites Go knows about
	for _, cs := range tls.CipherSuites() {
		cipherSuitesToTest = append(cipherSuitesToTest, cs.ID)
	}
	for _, cs := range tls.InsecureCipherSuites() {
		cipherSuitesToTest = append(cipherSuitesToTest, cs.ID)
	}
}

// HostResult holds all findings for a single host:port
type HostResult struct {
	Host      string         `json:"host"`
	Port      int            `json:"port"`
	Reachable bool           `json:"reachable"`
	HasTLS    bool           `json:"has_tls"`
	Error     string         `json:"error,omitempty"`
	Protocols []ProtoResult  `json:"protocols"`
	Ciphers   []CipherResult `json:"ciphers"`
	CertInfo  *CertInfo      `json:"cert_info,omitempty"`
	Findings  []Finding      `json:"findings"`
	// ToolRuns are the reproducible command + real output of each external tool
	// run against this host (nmap, sslscan, openssl), shown as a per-host
	// evidence panel on the results page.
	ToolRuns []ToolRun `json:"tool_runs,omitempty"`
	// Limitations surfaces the structural false-negative scope of this
	// module so the UI can show a "not a full SSL audit" banner. The Go
	// stdlib only handshakes TLS ≥1.0 with a fixed cipher list; SSLv2,
	// SSLv3, RC4, EXPORT, DES — exactly the cipher classes a real audit
	// cares about — silently never appear as supported. Audit K12.
	Limitations []string `json:"limitations,omitempty"`
}

// ProtoResult records whether a TLS version is supported.
//
// Untested=true means this scanner did not actually probe the protocol
// (Go's crypto/tls refuses to handshake SSL 2.0 / SSL 3.0). In that
// case Supported is meaningless and the UI must render an explicit
// "not tested — run sslscan/testssl.sh to verify" marker rather than
// implying the protocol is disabled.
type ProtoResult struct {
	Version   uint16 `json:"version"`
	Name      string `json:"name"`
	Supported bool   `json:"supported"`
	Untested  bool   `json:"untested,omitempty"`
}

// CipherResult records a supported cipher suite
type CipherResult struct {
	ID       uint16   `json:"id"`
	Name     string   `json:"name"`
	Versions []string `json:"versions"`
}

// CertInfo holds certificate details
type CertInfo struct {
	Subject    string    `json:"subject"`
	Issuer     string    `json:"issuer"`
	NotBefore  time.Time `json:"not_before"`
	NotAfter   time.Time `json:"not_after"`
	IsExpired  bool      `json:"is_expired"`
	DaysLeft   int       `json:"days_left"`
	SigAlg     string    `json:"sig_alg"`
	KeySize    int       `json:"key_size"`
	SANs       []string  `json:"sans"`
	SelfSigned bool      `json:"self_signed"`
	// Chain validation — populated when extractCertInfo gets the full
	// peer chain. A "chain incomplete" finding fires if the leaf can't
	// build to a known root using the intermediates the server sent.
	ChainValid      bool   `json:"chain_valid"`
	ChainErr        string `json:"chain_err,omitempty"`
	IntermediateCNs string `json:"intermediates,omitempty"` // "CN1, CN2"
	// OCSP stapling — true if the server included an OCSP response in
	// the TLS handshake (Certificate Status extension). When false, a
	// MITM with a stolen-but-revoked cert can still impersonate the
	// host until OCSP queries become live.
	OCSPStapled bool `json:"ocsp_stapled"`
	// HostnameErr is the result of x509.Certificate.VerifyHostname(host)
	// against the leaf cert. Empty means the host matches (or the host
	// was a bare IP literal and verification was skipped). Non-empty is
	// a HIGH finding — served cert doesn't cover the scanned name.
	// Populated by extractCertInfo when host is a DNS name.
	HostnameErr string `json:"hostname_err,omitempty"`
}

// Finding is a single vulnerability or issue.
// For cipher findings, Title is the category ("3DES", "RC4") and Count is how many
// individual cipher suites matched.
type Finding struct {
	Severity    Severity `json:"severity"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	CVEs        []string `json:"cves"`
	Component   string   `json:"component"` // "protocol", "cipher", "certificate"
	Count       int      `json:"count"`     // number of affected cipher suites (cipher findings only)
	// PoCCommand / PoCOutput are the real, reproducible command and its console
	// output from the tool that produced this finding's evidence (nmap NSE,
	// sslscan, or openssl s_client) — surfaced verbatim as the report/detail PoC.
	PoCCommand string `json:"poc_command,omitempty"`
	PoCOutput  string `json:"poc_output,omitempty"`
}

// ScanConfig holds scan parameters
type ScanConfig struct {
	Timeout     time.Duration
	Ports       []int
	Concurrency int
	// StartTLS selects the plaintext upgrade dance to run before dialing TLS.
	// "" or "none" = direct TLS; "auto" = per-port default; explicit protocol
	// name (smtp/imap/pop3/ftp/ldap/postgres) = force that dance regardless
	// of port. See starttls.go.
	StartTLS string
}

// DefaultConfig returns default scan settings: 443 plus the common STARTTLS
// service ports, with StartTLS "auto" so each port negotiates correctly
// (443 → direct TLS, mail/FTP/LDAP/Postgres → the plaintext upgrade dance).
func DefaultConfig() ScanConfig {
	return ScanConfig{
		Timeout:     8 * time.Second,
		Ports:       []int{443, 25, 587, 143, 110, 21, 389, 5432},
		Concurrency: 10,
		StartTLS:    StartTLSAuto,
	}
}

// ScanHost performs a full SSL/TLS scan on a single host:port.
//
// Audit: takes context.Context so the handler's Stop button propagates
// into in-flight TLS probing. Without ctx the per-cipher loop kept
// hammering the host for the full timeout × N ciphers × M versions
// (~75 × 4 ≈ minutes per host) after the user clicked Cancel.
//
// STARTTLS-only ports (25/587/143/110/389/21/5432) are handled by
// ScanHostOpts — this thin wrapper preserves the legacy direct-TLS
// signature for callers that don't care about STARTTLS (e.g.
// advancedweb which always dials 443).
func ScanHost(ctx context.Context, host string, port int, timeout time.Duration) *HostResult {
	return ScanHostOpts(ctx, host, port, timeout, "")
}

// ScanHostOpts is ScanHost with an explicit STARTTLS selection.
// startTLS may be "" or "none" (direct TLS), "auto" (per-port default via
// AutoStartTLS), or an explicit protocol name (smtp/imap/pop3/ftp/ldap/postgres).
// It captures full per-host/finding evidence (tool transcripts + PoC) — used by
// the standalone SSL/TLS module.
func ScanHostOpts(ctx context.Context, host string, port int, timeout time.Duration, startTLS string) *HostResult {
	return scanHost(ctx, host, port, timeout, startTLS, true)
}

// ScanHostBulk is the light path for bulk callers (advancedweb's SSL stage over
// hundreds/thousands of hosts). It runs the same tool-driven DETECTION
// (protocols, ciphers, vulnerabilities) but does NOT store the heavy per-host/
// finding evidence (tool_runs + PoC command/output) and skips the openssl cert
// dump, with a much tighter per-tool timeout. Capturing full tool transcripts
// across 1500+ hosts is what ballooned an advancedweb result past 200 MB and
// froze the process; the findings themselves stay comprehensive and small.
func ScanHostBulk(ctx context.Context, host string, port int, timeout time.Duration, startTLS string) *HostResult {
	return scanHost(ctx, host, port, timeout, startTLS, false)
}

// scanHost is the shared implementation. captureEvidence toggles the heavy
// evidence collection (tool transcripts + per-finding PoC + openssl) and the
// per-tool timeout ceiling (generous for standalone, tight for bulk).
func scanHost(ctx context.Context, host string, port int, timeout time.Duration, startTLS string, captureEvidence bool) *HostResult {
	if ctx == nil {
		ctx = context.Background()
	}
	result := &HostResult{
		Host: host,
		Port: port,
	}

	// Resolve auto → per-port protocol here so probeTLS / probeVersion
	// don't repeat the lookup on every dial.
	stlsMode := ResolveStartTLS(startTLS, port)

	// net.JoinHostPort handles IPv6 bracket-wrapping ([2001:db8::]:443)
	// correctly; plain Sprintf would build "2001:db8:::443" and Dial fails.
	addr := net.JoinHostPort(host, strconv.Itoa(port))

	// TCP reachability check — uses the shared bounded dialer so the killswitch's
	// source-IP binding applies. Retried a few times so a transient blip never
	// falsely drops a live host as "Connection failed".
	var dialErr error
	for attempt := 0; attempt < 3 && !result.Reachable; attempt++ {
		if attempt > 0 {
			select {
			case <-time.After(300 * time.Millisecond):
			case <-ctx.Done():
			}
		}
		conn, err := shared.BoundDialer(nil, timeout).DialContext(ctx, "tcp", addr)
		if err == nil {
			conn.Close()
			result.Reachable = true
		} else {
			dialErr = err
		}
	}
	if !result.Reachable {
		result.Error = fmt.Sprintf("Connection failed: %v", dialErr)
		return result
	}

	if ctx.Err() != nil {
		result.Error = "Cancelled"
		return result
	}

	// Thorough, tool-driven analysis (the operator asked for completeness over
	// speed): sslscan gives protocols incl. SSLv2/SSLv3, cipher strength,
	// Heartbleed, compression and renegotiation; nmap adds A–F cipher grades
	// and the POODLE/DROWN/Logjam/Heartbleed vuln NSE scripts. Both run even if
	// one fails — mergeToolResults tolerates a nil side.
	// Tool timeout: generous for the standalone module (thoroughness), tight for
	// the bulk suite (stage-level stability across 1000s of hosts).
	toolTimeout := sslToolTimeout(timeout)
	if !captureEvidence {
		toolTimeout = sslBulkTimeout(timeout)
	}
	ss, ssRun, ssErr := runSslscan(ctx, host, port, toolTimeout, stlsMode)
	nm, nmRun, nmErr := runNmapSSL(ctx, host, port, toolTimeout)

	// Certificate details come from a Go handshake (rich CertInfo fields:
	// chain, SANs, OCSP, hostname match) — the tools don't surface all of them.
	certInfo, negVer := fetchCertInfo(ctx, addr, host, timeout, stlsMode)
	result.CertInfo = certInfo
	// openssl only produces PoC evidence for certificate findings (which come
	// from the Go handshake above), so skip its subprocess when not capturing
	// evidence — one fewer spawn per host across a bulk scan.
	var opensslRun ToolRun
	if captureEvidence {
		opensslRun = runOpenSSLCert(ctx, host, port, timeout, stlsMode)
	}

	// Authoritative in-process detection: handshake every TLS version directly.
	// This is what makes detection reliable — a host that serves TLS is proven
	// so here even when both external tools fail/timeout. Fold in the cert
	// handshake's negotiated version.
	goVersions := probeTLSVersions(ctx, addr, host, timeout, stlsMode)
	if negVer != 0 {
		goVersions[negVer] = true
	}
	// Final safety net: if NOTHING was detected on an open port (tools empty AND
	// the sweep empty), sweep once more before concluding "No TLS" — the
	// definitive guard against a transient one-off failure across all versions.
	toolsSawProto := (ss != nil && len(ss.Protocols) > 0) || (nm != nil && len(nm.Protocols) > 0)
	if len(goVersions) == 0 && !toolsSawProto {
		if retry := probeTLSVersions(ctx, addr, host, timeout, stlsMode); len(retry) > 0 {
			goVersions = retry
		}
	}

	if ss == nil && nm == nil && len(goVersions) == 0 {
		tools := detectTools()
		switch {
		case !tools.Sslscan && !tools.Nmap:
			// Tools genuinely absent AND the in-process sweep found no TLS.
			result.Error = "SSL/TLS engine requires nmap and sslscan — neither is installed (see startup banner)"
			return result
		default:
			// Tools produced nothing AND no TLS version handshakes AND no cert:
			// there is genuinely no TLS service on this port.
			if ssErr != nil && nmErr != nil {
				result.Error = fmt.Sprintf("SSL/TLS tools failed: sslscan: %v; nmap: %v", ssErr, nmErr)
			} else {
				result.Error = "No TLS/SSL service detected on this port"
			}
			return result
		}
	}

	mergeToolResults(result, ss, nm, goVersions)

	// Evidence (per-finding PoC + per-host tool transcripts) only for the
	// standalone module; the bulk suite keeps just the findings to stay small
	// and stable at 1000s-of-hosts scale.
	if captureEvidence {
		result.Findings = attachPoC(result.Findings, ssRun, nmRun, opensslRun, nm)
		result.ToolRuns = nonEmptyRuns(nmRun, ssRun, opensslRun)
	}

	// has_tls = the server speaks some TLS/SSL (any supported protocol) or a
	// certificate handshake completed.
	for _, p := range result.Protocols {
		if p.Supported {
			result.HasTLS = true
			break
		}
	}
	if !result.HasTLS && result.CertInfo != nil {
		result.HasTLS = true
	}
	if !result.HasTLS {
		result.Error = "No TLS/SSL service detected on this port"
	}
	return result
}

// probeTLSVersions is the in-process MODERN-TLS presence backstop. It attempts a
// native Go handshake for each modern version (see tlsVersionsToTest — 1.2/1.3
// only) concurrently, with a maximally permissive cipher list, so the module
// NEVER reports "No TLS" for a host that actually serves TLS merely because an
// external tool timed out, failed, or was starved. Returns the set of versions
// that completed a handshake — legacy ones (TLS1.0/1.1) only when reproducible
// (see probeOneVersion), so a stray success can't assert them. crypto/tls can't
// speak SSL 2.0/3.0, so those are left to sslscan.
func probeTLSVersions(ctx context.Context, addr, serverName string, timeout time.Duration, startTLS string) map[uint16]bool {
	versions := tlsVersionsToTest
	type vr struct {
		v  uint16
		ok bool
	}
	ch := make(chan vr, len(versions))
	for _, v := range versions {
		go func(v uint16) {
			ch <- vr{v, probeOneVersion(ctx, addr, serverName, v, timeout, startTLS)}
		}(v)
	}
	out := map[uint16]bool{}
	for range versions {
		if r := <-ch; r.ok {
			out[r.v] = true
		}
	}
	return out
}

// probeOneVersion forces exactly one TLS version with an all-inclusive cipher
// list (so even weak-cipher-only servers, e.g. RC4/3DES/CBC, complete) and
// returns true only when the server actually negotiates that version.
//
// Legacy versions (TLS 1.0/1.1) must be REPRODUCIBLE: they're marked supported
// only when TWO independent handshakes complete, so a single stray success — a
// cold-start transient, or one crossed connection to a shared load-balancer IP —
// can never manufacture a phantom "TLS 1.0/1.1" finding. A genuinely
// legacy-enabled host (hosta.example.com: 10/10 real handshakes) confirms
// immediately; one that refuses (ftp.aol: 0/10) never does. Modern versions
// (1.2/1.3) need just one success — they are not the false-positive concern, and
// a single confirmation preserves the "never drop a live TLS host as No-TLS"
// guarantee.
func probeOneVersion(ctx context.Context, addr, serverName string, v uint16, timeout time.Duration, startTLS string) bool {
	cfg := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         serverName,
		MinVersion:         v,
		MaxVersion:         v,
	}
	if v != tls.VersionTLS13 {
		// TLS 1.3 cipher suites are not configurable; for ≤1.2 offer everything
		// Go knows (including the insecure suites) so a legacy server handshakes.
		cfg.CipherSuites = cipherSuitesToTest
	}
	needed, maxAttempts := 1, 2
	if v == tls.VersionTLS10 || v == tls.VersionTLS11 {
		needed, maxAttempts = 2, 3 // legacy must be confirmed by a repeat handshake
	}
	successes := 0
	for attempt := 0; attempt < maxAttempts; attempt++ {
		if ctx.Err() != nil {
			return false
		}
		conn, err := tlsDial(ctx, addr, cfg, timeout, startTLS, serverName)
		if err == nil {
			ok := conn.ConnectionState().Version == v
			conn.Close()
			if ok {
				successes++
				if successes >= needed {
					return true
				}
			}
		}
		if attempt < maxAttempts-1 {
			select {
			case <-time.After(250 * time.Millisecond):
			case <-ctx.Done():
				return false
			}
		}
	}
	return successes >= needed
}

// fetchCertInfo grabs the served certificate via a single TLS handshake and
// parses the rich CertInfo (chain, SANs, OCSP stapling, hostname match) the
// external tools don't fully expose. It also returns the negotiated protocol
// version (0 if the handshake failed).
func fetchCertInfo(ctx context.Context, addr, serverName string, timeout time.Duration, startTLS string) (*CertInfo, uint16) {
	cfg := &tls.Config{InsecureSkipVerify: true, ServerName: serverName}
	conn, err := tlsDial(ctx, addr, cfg, timeout, startTLS, serverName)
	if err != nil {
		return nil, 0
	}
	st := conn.ConnectionState()
	conn.Close()
	ci := extractCertInfo(st.PeerCertificates, serverName)
	if ci != nil && len(st.OCSPResponse) > 0 {
		ci.OCSPStapled = true
	}
	return ci, st.Version
}

// ScanTargets scans multiple targets concurrently.
//
// Audit B40: takes context.Context now so callers can propagate cancel.
// Without ctx the nested target × port loop kept queueing work past a
// cancel — even though ScanHost itself respected its own timeout, the
// scan total time was unbounded. The for loops now bail on ctx.Done().
// Note: scaNNer's actual call sites use ScanHost directly, so this is
// defensive — keeps the helper consistent with the rest of the module.
func ScanTargets(ctx context.Context, targets []string, cfg ScanConfig) []*HostResult {
	if ctx == nil {
		ctx = context.Background()
	}
	var results []*HostResult
	var mu sync.Mutex
	sem := make(chan struct{}, cfg.Concurrency)
	var wg sync.WaitGroup

	for _, target := range targets {
		if ctx.Err() != nil {
			break
		}
		for _, port := range cfg.Ports {
			if ctx.Err() != nil {
				break
			}
			wg.Add(1)
			sem <- struct{}{}
			go func(t string, p int) {
				defer wg.Done()
				defer func() { <-sem }()
				if ctx.Err() != nil {
					return
				}
				r := ScanHostOpts(ctx, t, p, cfg.Timeout, cfg.StartTLS)
				mu.Lock()
				results = append(results, r)
				mu.Unlock()
			}(target, port)
		}
	}
	wg.Wait()
	return results
}

// probeVersion attempts TLS connection with a specific version and enumerates ciphers
func probeVersion(ctx context.Context, addr, serverName string, version uint16, timeout time.Duration, startTLS string) (bool, []tls.CipherSuite, *CertInfo) {
	// For TLS 1.3, we can't control cipher suites the same way
	if version == tls.VersionTLS13 {
		cfg := &tls.Config{
			MinVersion:         tls.VersionTLS13,
			MaxVersion:         tls.VersionTLS13,
			ServerName:         serverName,
			InsecureSkipVerify: true,
		}
		conn, err := tlsDial(ctx, addr, cfg, timeout, startTLS, serverName)
		if err != nil {
			return false, nil, nil
		}
		state := conn.ConnectionState()
		certInfo := extractCertInfo(state.PeerCertificates, serverName)
		if certInfo != nil && len(state.OCSPResponse) > 0 {
			certInfo.OCSPStapled = true
		}
		conn.Close()
		// TLS 1.3 cipher suites from connection
		var suites []tls.CipherSuite
		csName := tls.CipherSuiteName(state.CipherSuite)
		suites = append(suites, tls.CipherSuite{ID: state.CipherSuite, Name: csName})
		return true, suites, certInfo
	}

	// For TLS 1.0-1.2, try connecting with all cipher suites
	cfg := &tls.Config{
		MinVersion:         version,
		MaxVersion:         version,
		ServerName:         serverName,
		InsecureSkipVerify: true,
		CipherSuites:       cipherSuitesToTest,
	}
	conn, err := tlsDial(ctx, addr, cfg, timeout, startTLS, serverName)
	if err != nil {
		return false, nil, nil
	}
	state := conn.ConnectionState()
	conn.Close()
	// Defensive: Go's MaxVersion contract guarantees state.Version == version,
	// but a buggy server downgrading the response (or a future stdlib change)
	// could in theory slip through. Drop the result rather than misattribute
	// the cipher to a version the server didn't actually accept it on.
	if state.Version != version {
		return false, nil, nil
	}
	certInfo := extractCertInfo(state.PeerCertificates, serverName)
	if certInfo != nil && len(state.OCSPResponse) > 0 {
		// Mirror the TLS 1.3 branch so OCSP stapling isn't a version-only
		// artefact — a server that staples on 1.2 but not 1.3 still counts.
		certInfo.OCSPStapled = true
	}

	// Now enumerate which specific ciphers are accepted
	var accepted []tls.CipherSuite
	seenCiphers := map[uint16]bool{}

	// The first connection already told us one cipher
	csName := tls.CipherSuiteName(state.CipherSuite)
	accepted = append(accepted, tls.CipherSuite{ID: state.CipherSuite, Name: csName})
	seenCiphers[state.CipherSuite] = true

	// Probe remaining ciphers individually (in batches)
	for _, csID := range cipherSuitesToTest {
		// Bail on cancellation — without this the per-cipher loop kept
		// dialing every one of ~75 suites for the full handshake timeout
		// after the user clicked Stop.
		if ctx.Err() != nil {
			break
		}
		if seenCiphers[csID] {
			continue
		}
		probeCfg := &tls.Config{
			MinVersion:         version,
			MaxVersion:         version,
			ServerName:         serverName,
			InsecureSkipVerify: true,
			CipherSuites:       []uint16{csID},
		}
		probeConn, err := tlsDial(ctx, addr, probeCfg, timeout, startTLS, serverName)
		if err != nil {
			continue
		}
		probeState := probeConn.ConnectionState()
		probeConn.Close()
		// Same version-match guard for the per-cipher probes.
		if probeState.Version != version {
			continue
		}
		if !seenCiphers[probeState.CipherSuite] {
			name := tls.CipherSuiteName(probeState.CipherSuite)
			accepted = append(accepted, tls.CipherSuite{ID: probeState.CipherSuite, Name: name})
			seenCiphers[probeState.CipherSuite] = true
		}
	}

	return true, accepted, certInfo
}

// probeTLS does a quick TLS handshake to check if the port speaks TLS at all.
// When startTLS is non-empty the plaintext upgrade dance is performed on the
// raw TCP connection before wrapping in tls.Client.
func probeTLS(ctx context.Context, addr, serverName string, timeout time.Duration, startTLS string) (ok bool, version, cipher uint16) {
	cfg := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         serverName,
	}
	conn, err := tlsDial(ctx, addr, cfg, timeout, startTLS, serverName)
	if err != nil {
		return false, 0, 0
	}
	// Go's default config negotiates only TLS 1.2 or 1.3, so a successful
	// handshake here is authoritative proof the server speaks that modern
	// version — even when the per-version probes below fail (which happens
	// when the target is an IP with no SNI and the server routes SNI-based
	// vhosts, or a middlebox drops the version probes' weak-cipher ClientHello).
	st := conn.ConnectionState()
	conn.Close()
	return true, st.Version, st.CipherSuite
}

// tlsDial dials TCP + completes a TLS handshake, both bound by ctx so a
// scan cancel interrupts the in-flight handshake instead of waiting up
// to `timeout` for the server. Uses shared.BoundDialer for killswitch
// source-IP binding.
//
// If startTLS is non-empty (and not "none"), starttlsUpgrade runs the
// protocol's plaintext AUTH-then-upgrade dance on the raw connection
// before tls.Client wraps it. Failed upgrades return the underlying
// STARTTLS error so the caller can surface it instead of a generic
// "handshake failed".
func tlsDial(ctx context.Context, addr string, cfg *tls.Config, timeout time.Duration, startTLS, host string) (*tls.Conn, error) {
	dialer := shared.BoundDialer(nil, timeout)
	// Bound the dial+handshake by the per-probe timeout AND by ctx — the
	// shorter of the two wins, so a scan cancel propagates immediately
	// without waiting for the handshake timer to elapse.
	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	rawConn, err := dialer.DialContext(dialCtx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	if startTLS != "" && startTLS != StartTLSNone {
		if err := startTLSUpgrade(dialCtx, rawConn, startTLS, host, timeout); err != nil {
			rawConn.Close()
			return nil, err
		}
	}
	tlsConn := tls.Client(rawConn, cfg)
	if err := tlsConn.HandshakeContext(dialCtx); err != nil {
		rawConn.Close()
		return nil, err
	}
	return tlsConn, nil
}

// extractCertInfo parses the peer cert chain into a UI-friendly CertInfo.
// host is the DNS name being probed — used to run VerifyHostname against
// the leaf cert. For raw-IP targets the check is skipped (SAN-vs-IP
// comparison rarely matches even on correctly-configured hosts and would
// produce noise findings).
func extractCertInfo(certs []*x509.Certificate, host string) *CertInfo {
	if len(certs) == 0 {
		return nil
	}
	cert := certs[0]
	now := time.Now()
	daysLeft := int(cert.NotAfter.Sub(now).Hours() / 24)

	keySize := 0
	if cert.PublicKey != nil {
		switch k := cert.PublicKey.(type) {
		case interface{ Size() int }:
			keySize = k.Size() * 8
		default:
			_ = k
		}
	}

	selfSigned := cert.Issuer.String() == cert.Subject.String()

	// Chain validation: try to build a verified chain using the
	// intermediates the server sent + the system root store. A failure
	// here is one of the most common real-world SSL findings — server
	// admin forgot to bundle the intermediate cert, browsers cope via
	// AIA fetch but pentest tools / scripts / older clients break.
	chainValid := false
	chainErr := ""
	intermediates := ""
	if len(certs) > 1 {
		pool := x509.NewCertPool()
		var ints []string
		for _, c := range certs[1:] {
			pool.AddCert(c)
			ints = append(ints, c.Subject.CommonName)
		}
		intermediates = strings.Join(ints, ", ")
		_, err := cert.Verify(x509.VerifyOptions{Intermediates: pool})
		if err == nil {
			chainValid = true
		} else {
			chainErr = err.Error()
		}
	} else if !selfSigned {
		// Single-cert response from a CA-signed leaf means the server
		// didn't bundle any intermediates. Verify will fail unless the
		// system already trusts the issuer directly.
		_, err := cert.Verify(x509.VerifyOptions{})
		if err == nil {
			chainValid = true
		} else {
			chainErr = "no intermediates served — " + err.Error()
		}
	} else {
		chainErr = "self-signed leaf — no chain to verify"
	}

	// Hostname / SAN check — only meaningful for DNS-name targets. For
	// bare IPs skip: IP-SAN certs exist but are rare, and the finding
	// would fire on nearly every well-configured host scanned by IP.
	hostnameErr := ""
	if h := strings.TrimSpace(host); h != "" && net.ParseIP(h) == nil {
		if err := cert.VerifyHostname(h); err != nil {
			hostnameErr = err.Error()
		}
	}

	return &CertInfo{
		Subject:         cert.Subject.String(),
		Issuer:          cert.Issuer.String(),
		NotBefore:       cert.NotBefore,
		NotAfter:        cert.NotAfter,
		IsExpired:       now.After(cert.NotAfter),
		DaysLeft:        daysLeft,
		SigAlg:          cert.SignatureAlgorithm.String(),
		KeySize:         keySize,
		SANs:            cert.DNSNames,
		SelfSigned:      selfSigned,
		ChainValid:      chainValid,
		ChainErr:        chainErr,
		IntermediateCNs: intermediates,
		HostnameErr:     hostnameErr,
	}
}

// analyzeFindings generates vulnerability findings from scan results.
// Each vulnerability category appears at most once per host.
func analyzeFindings(r *HostResult) []Finding {
	var findings []Finding

	// --- Protocols ---
	for _, p := range r.Protocols {
		// Untested protocols (SSL 2.0 / SSL 3.0 — stdlib can't probe
		// them) are surfaced via the Untested marker in the UI; don't
		// emit a "supported" finding for something we never confirmed.
		if p.Untested || !p.Supported {
			continue
		}
		for _, vp := range VulnerableProtocols {
			if p.Version == vp.ID {
				findings = append(findings, Finding{
					Severity:    vp.Severity,
					Title:       vp.Name,
					Description: vp.Reason,
					CVEs:        vp.CVEs,
					Component:   "protocol",
					Count:       1,
				})
				break
			}
		}
	}

	// --- Ciphers: ONE finding per TLS VERSION, summarising that version's weak
	// cipher suites. Grouping by category instead (3DES / CBC-no-PFS / Static-RSA
	// / RC4 / …) produced 3-5 rows per host — the operator's "too many
	// vulnerabilities for one TLS version". Each cipher carries the versions it
	// was offered on; fold per version, severity = the worst category present,
	// and list the categories + a few cipher names so the row stays actionable.
	// (The UI badge still reads Count = matched-cipher count for that version.)
	type verAgg struct {
		catOrder []string
		catSeen  map[string]bool
		worst    Severity
		cves     []string
		cveSeen  map[string]bool
		count    int
		samples  []string
	}
	// A cipher counts toward a version only if that version is actually supported
	// (per the robust protocol detection). Otherwise nmap listing a cipher under a
	// phantom legacy section (e.g. a stray "TLSv1.1" from an inconsistent LB that
	// no real handshake confirms) would manufacture a "Weak Cipher Suites (TLS 1.1)"
	// finding for a version the server doesn't actually offer.
	supportedVer := map[string]bool{}
	for _, p := range r.Protocols {
		if p.Supported {
			supportedVer[p.Name] = true
		}
	}
	verMap := map[string]*verAgg{}
	for _, c := range r.Ciphers {
		cat := ClassifyCipher(c.Name)
		if cat == nil {
			continue
		}
		vers := c.Versions
		if len(vers) == 0 {
			vers = []string{""} // version unknown → single fallback bucket
		}
		for _, ver := range vers {
			if ver != "" && !supportedVer[ver] {
				continue // version not actually supported — don't attribute ciphers to it
			}
			agg := verMap[ver]
			if agg == nil {
				agg = &verAgg{catSeen: map[string]bool{}, cveSeen: map[string]bool{}}
				verMap[ver] = agg
			}
			agg.count++
			if !agg.catSeen[cat.Name] {
				agg.catSeen[cat.Name] = true
				agg.catOrder = append(agg.catOrder, cat.Name)
			}
			if SeverityScore(cat.Severity) > SeverityScore(agg.worst) {
				agg.worst = cat.Severity
			}
			for _, cve := range cat.CVEs {
				if cve != "" && cve != "N/A" && !agg.cveSeen[cve] {
					agg.cveSeen[cve] = true
					agg.cves = append(agg.cves, cve)
				}
			}
			if len(agg.samples) < 4 {
				agg.samples = append(agg.samples, c.Name)
			}
		}
	}
	emitVer := func(ver string, agg *verAgg) {
		title := "Weak Cipher Suites"
		subject := "The server"
		if ver != "" {
			title += " (" + ver + ")"
			subject = ver
		}
		plural := "s"
		if agg.count == 1 {
			plural = ""
		}
		desc := fmt.Sprintf("%s offers weak cipher suites — %s (%d cipher%s, e.g. %s).",
			subject, strings.Join(agg.catOrder, ", "), agg.count, plural, strings.Join(agg.samples, ", "))
		cves := agg.cves
		if len(cves) == 0 {
			cves = []string{"N/A"}
		}
		findings = append(findings, Finding{
			Severity:    agg.worst,
			Title:       title,
			Description: desc,
			CVEs:        cves,
			Component:   "cipher",
			Count:       agg.count,
		})
	}
	// Render oldest→newest for stable ordering; the unknown-version bucket last.
	for _, ver := range protoOrder {
		if agg := verMap[ver]; agg != nil {
			emitVer(ver, agg)
		}
	}
	if agg := verMap[""]; agg != nil {
		emitVer("", agg)
	}

	// --- Certificate ---
	if r.CertInfo != nil {
		if r.CertInfo.IsExpired {
			findings = append(findings, Finding{
				Severity:    SevHigh,
				Title:       "Expired Certificate",
				Description: fmt.Sprintf("Certificate expired on %s", r.CertInfo.NotAfter.Format("2006-01-02")),
				CVEs:        []string{"N/A"},
				Component:   "certificate",
			})
		} else if r.CertInfo.DaysLeft < 30 {
			findings = append(findings, Finding{
				Severity:    SevMedium,
				Title:       "Certificate Expiring Soon",
				Description: fmt.Sprintf("Certificate expires in %d days", r.CertInfo.DaysLeft),
				CVEs:        []string{"N/A"},
				Component:   "certificate",
			})
		}
		if r.CertInfo.SelfSigned {
			findings = append(findings, Finding{
				Severity:    SevMedium,
				Title:       "Self-Signed Certificate",
				Description: "Certificate is not signed by a trusted CA",
				CVEs:        []string{"N/A"},
				Component:   "certificate",
			})
		}
		if r.CertInfo.KeySize > 0 && r.CertInfo.KeySize < 2048 {
			findings = append(findings, Finding{
				Severity:    SevHigh,
				Title:       fmt.Sprintf("Weak Key (%d-bit)", r.CertInfo.KeySize),
				Description: "RSA keys shorter than 2048 bits are considered insecure",
				CVEs:        []string{"N/A"},
				Component:   "certificate",
			})
		}
		if strings.Contains(r.CertInfo.SigAlg, "SHA1") || strings.Contains(r.CertInfo.SigAlg, "MD5") {
			findings = append(findings, Finding{
				Severity:    SevHigh,
				Title:       "Weak Signature (" + r.CertInfo.SigAlg + ")",
				Description: "Vulnerable to collision attacks",
				CVEs:        []string{"CVE-2004-2761"},
				Component:   "certificate",
			})
		}
		// Hostname / SAN mismatch — HIGH. Non-empty HostnameErr means
		// x509.Certificate.VerifyHostname(r.Host) failed; the served cert
		// doesn't cover the name we scanned. Pentester needs to know so
		// they don't dismiss a virtual-host misconfiguration as noise.
		if r.CertInfo.HostnameErr != "" {
			findings = append(findings, Finding{
				Severity:    SevHigh,
				Title:       "Hostname Mismatch",
				Description: "Served certificate does not match the scanned host: " + r.CertInfo.HostnameErr,
				CVEs:        []string{"N/A"},
				Component:   "certificate",
			})
		}
		// Incomplete chain — MEDIUM. Server didn't bundle intermediates,
		// or the intermediates it sent don't chain to a root in the system
		// trust store. Common real-world finding: browsers rescue via AIA
		// but scripts / older clients break outright.
		if !r.CertInfo.ChainValid && r.CertInfo.ChainErr != "" && !r.CertInfo.SelfSigned {
			findings = append(findings, Finding{
				Severity:    SevMedium,
				Title:       "Incomplete Certificate Chain",
				Description: "Chain validation failed: " + r.CertInfo.ChainErr,
				CVEs:        []string{"N/A"},
				Component:   "certificate",
			})
		}
		// No OCSP stapling — LOW. Without stapling, revocation status must
		// be fetched out-of-band (CRL/OCSP), which many clients skip. A
		// stolen-but-revoked cert can impersonate the host silently.
		if !r.CertInfo.OCSPStapled {
			findings = append(findings, Finding{
				Severity:    SevLow,
				Title:       "No OCSP Stapling",
				Description: "Server did not include an OCSP response in the TLS handshake; revocation status requires an out-of-band OCSP query.",
				CVEs:        []string{"N/A"},
				Component:   "certificate",
			})
		}
	}

	// --- Protocol quality ---
	// anySupported guards against asserting a negative from missing evidence:
	// when both external tools fail to enumerate AND no handshake backstop
	// applies, r.Protocols is empty — that is "unknown", not "no modern TLS".
	// Emitting "No Modern TLS" from an empty list is the exact false positive
	// seen on hosts where sslscan died mid-run and nmap timed out but the server
	// clearly speaks TLS 1.2/1.3.
	has12, has13, anySupported := false, false, false
	for _, p := range r.Protocols {
		if !p.Supported {
			continue
		}
		anySupported = true
		if p.Version == tls.VersionTLS12 {
			has12 = true
		}
		if p.Version == tls.VersionTLS13 {
			has13 = true
		}
	}
	if anySupported {
		if !has13 && !has12 {
			findings = append(findings, Finding{
				Severity:    SevHigh,
				Title:       "No Modern TLS",
				Description: "Neither TLS 1.2 nor TLS 1.3 is supported",
				CVEs:        []string{"N/A"},
				Component:   "protocol",
			})
		} else if !has13 {
			findings = append(findings, Finding{
				Severity:    SevInfo,
				Title:       "TLS 1.3 Not Supported",
				Description: "Consider enabling TLS 1.3 for improved security and performance",
				CVEs:        []string{"N/A"},
				Component:   "protocol",
			})
		}
	}

	return findings
}
