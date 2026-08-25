package shared

import (
	"context"
	"crypto/tls"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	defaultReachTimeout = 4 * time.Second
	defaultReachConc    = 30
)

// Probe reports whether a single web target is reachable enough to scan: the TCP
// connection opens and, for https, the TLS handshake COMPLETES. A handshake that
// completes with an invalid / self-signed / expired / wrong-hostname certificate
// still counts as reachable (InsecureSkipVerify) — the tool can scan it. A
// handshake that is reset (errno 104) or times out counts as unreachable, so
// callers can skip the host instead of grinding thousands of failing requests
// against it (observed: legacyhost.example.com resets TLS → nuclei hit ~67%
// errors and 0 findings).
//
// The dial goes through BoundDialer so it honors the killswitch outbound binding
// and the network throttle, and it is bounded by both `timeout` and the caller's
// ctx (scan Stop cancels instantly). Returns (reachable, reason); reason is empty
// when reachable, else a short classification (e.g. "connection reset").
func Probe(ctx context.Context, opts *HTTPOptions, target string, timeout time.Duration) (bool, string) {
	if timeout <= 0 {
		timeout = defaultReachTimeout
	}
	scheme, host, hostport := normalizeReachTarget(target)
	if hostport == "" {
		return false, "unparseable target"
	}
	if ctx == nil {
		ctx = context.Background()
	}
	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	dialer := BoundDialer(opts, timeout)
	rawConn, err := dialer.DialContext(dialCtx, "tcp", hostport)
	if err != nil {
		return false, "TCP connect failed" + reasonSuffix(err)
	}
	defer rawConn.Close()

	if scheme != "https" {
		return true, "" // plain HTTP: an open TCP socket is enough
	}
	// Real TLS handshake, cert validation disabled. A completed handshake (even
	// with a bad cert) => reachable; a reset/timeout => unreachable.
	tlsConn := tls.Client(rawConn, &tls.Config{InsecureSkipVerify: true, ServerName: host})
	if hErr := tlsConn.HandshakeContext(dialCtx); hErr != nil {
		return false, "TLS handshake failed" + reasonSuffix(hErr)
	}
	return true, ""
}

func reasonSuffix(err error) string {
	if c := ClassifyError(err); c != "" {
		return " (" + c + ")"
	}
	return ""
}

// normalizeReachTarget splits a module target into (scheme, host, host:port).
// Accepts full URLs ("https://h/path"), bare hosts ("h"), and "host:port". Bare
// hosts default to https:443 (matching the suite's seedURLs, which emits
// https://<sub>); a scheme-less :80/:8080/:8000 is treated as http.
func normalizeReachTarget(target string) (scheme, host, hostport string) {
	t := strings.TrimSpace(target)
	if t == "" {
		return "", "", ""
	}
	if strings.Contains(t, "://") {
		u, err := url.Parse(t)
		if err != nil || u.Hostname() == "" {
			return "", "", ""
		}
		scheme = strings.ToLower(u.Scheme)
		host = u.Hostname()
		port := u.Port()
		if port == "" {
			if scheme == "http" {
				port = "80"
			} else {
				port = "443"
			}
		}
		return scheme, host, net.JoinHostPort(host, port)
	}
	if h, p, err := net.SplitHostPort(t); err == nil && h != "" {
		switch p {
		case "80", "8080", "8000":
			scheme = "http"
		default:
			scheme = "https"
		}
		return scheme, h, net.JoinHostPort(h, p)
	}
	return "https", t, net.JoinHostPort(t, "443")
}

// FilterReachable probes urls concurrently and splits them into the reachable
// subset (input order preserved, de-duplicated) and a dead map (target ->
// reason). It honors opts.Done() for cancellation; a target left un-probed by a
// mid-flight cancel appears in neither set (the caller's loop guard halts next).
// conc <= 0 uses a default; timeout <= 0 uses a default. opts may be nil.
func FilterReachable(ctx context.Context, opts *HTTPOptions, urls []string, timeout time.Duration, conc int) ([]string, map[string]string) {
	dead := map[string]string{}
	if len(urls) == 0 {
		return nil, dead
	}
	if conc <= 0 {
		conc = defaultReachConc
	}
	if conc > len(urls) {
		conc = len(urls)
	}
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, conc)
	liveSet := make(map[string]bool, len(urls))
	for _, u := range urls {
		if opts.Done() {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(t string) {
			defer wg.Done()
			defer func() { <-sem }()
			ok, reason := Probe(ctx, opts, t, timeout)
			mu.Lock()
			if ok {
				liveSet[t] = true
			} else {
				dead[t] = reason
			}
			mu.Unlock()
		}(u)
	}
	wg.Wait()

	live := make([]string, 0, len(liveSet))
	seen := make(map[string]bool, len(liveSet))
	for _, u := range urls {
		if liveSet[u] && !seen[u] {
			seen[u] = true
			live = append(live, u)
		}
	}
	return live, dead
}
