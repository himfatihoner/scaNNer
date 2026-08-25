package oob

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Interaction is one received hit on a collaborator URL or DNS query for a
// collaborator hostname.
type Interaction struct {
	Kind         string    `json:"kind"` // "http" | "dns"
	Token        string    `json:"token"`
	At           time.Time `json:"at"`
	RemoteAddr   string    `json:"remote_addr,omitempty"`
	Host         string    `json:"host,omitempty"`
	Method       string    `json:"method,omitempty"`
	Path         string    `json:"path,omitempty"`
	UserAgent    string    `json:"user_agent,omitempty"`
	BodySnippet  string    `json:"body_snippet,omitempty"`
	RawHeaders   string    `json:"raw_headers,omitempty"`
	Subdomain    string    `json:"subdomain,omitempty"`
	QueryType    string    `json:"query_type,omitempty"`
}

// Session is one set of tokens minted in a single OOB scan. Multiple tokens
// per session let users distinguish probes ("token-1 for header XYZ injection,
// token-2 for body JSON injection").
type Session struct {
	ID           string
	Tokens       []string
	BaseDomain   string         // e.g. "oob.scanner.local"
	HTTPListenOn string         // e.g. ":8088"
	startedAt    time.Time
	mu           sync.Mutex
	interactions []Interaction
	listener     net.Listener
	httpSrv      *http.Server
}

// NewSession mints a session with N tokens. baseDomain is the public DNS
// name (or IP host) clients will resolve. The server listens on httpAddr
// for HTTP callbacks and records DNS interactions reported via /__dns.
//
// In environments where the user can't expose a public DNS, the recommended
// flow is: pick a wildcard test domain and rely on the HTTP collaborator
// only — many vulnerabilities (SSRF, blind XSS) chain through HTTP alone.
func NewSession(tokens int, baseDomain, httpAddr string) (*Session, error) {
	s := &Session{
		ID:           shortRand(12),
		BaseDomain:   strings.TrimRight(baseDomain, "."),
		HTTPListenOn: httpAddr,
		startedAt:    time.Now(),
	}
	if tokens <= 0 {
		tokens = 1
	}
	for i := 0; i < tokens; i++ {
		s.Tokens = append(s.Tokens, shortRand(10))
	}
	if err := s.startHTTP(); err != nil {
		return nil, err
	}
	return s, nil
}

// URLs returns the per-token callback URLs the user can paste into payloads.
func (s *Session) URLs() []string {
	out := make([]string, 0, len(s.Tokens))
	scheme := "http://"
	host := s.BaseDomain
	if host == "" {
		// Audit fix: when no public host is configured, fall back to the
		// listener's actual host:port (HTTPListen). Previously we
		// emitted "http://127.0.0.1/<token>" — port 80 — which is
		// unreachable when the listener is bound to a random port via
		// `:0`, so copy-to-clipboard produced garbage URLs.
		host = s.HTTPListen()
		if host == "" {
			host = "127.0.0.1"
		}
	}
	for _, t := range s.Tokens {
		// Tokens are placed in the path so they're discoverable in a
		// single-host setup. For a DNS-capable setup the user can also
		// fold the token into the subdomain (left to user discretion).
		out = append(out, scheme+host+"/"+t)
	}
	return out
}

// HTTPListen returns the actual listening address (handy when port was
// auto-allocated via ":0").
func (s *Session) HTTPListen() string {
	if s.listener != nil {
		return s.listener.Addr().String()
	}
	return s.HTTPListenOn
}

// Interactions returns a defensive copy.
func (s *Session) Interactions() []Interaction {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Interaction, len(s.interactions))
	copy(out, s.interactions)
	return out
}

// RecordDNS lets the caller surface DNS interactions that were captured by
// an external resolver (e.g. via syslog tail or external collaborator).
// For pure in-process use this is mostly unused; the HTTP listener is the
// primary signal.
func (s *Session) RecordDNS(subdomain, queryType, remoteAddr string) {
	token := s.matchToken(subdomain)
	s.appendInteraction(Interaction{
		Kind: "dns", Token: token, At: time.Now(),
		RemoteAddr: remoteAddr,
		Subdomain:  subdomain,
		QueryType:  queryType,
	})
}

// Close stops the listener.
func (s *Session) Close() error {
	if s.httpSrv != nil {
		return s.httpSrv.Close()
	}
	return nil
}

func (s *Session) startHTTP() error {
	addr := s.HTTPListenOn
	if addr == "" {
		addr = ":0"
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handle)
	// Full set of timeouts (audit B52). ReadHeaderTimeout alone leaves
	// slow-body and slow-read clients pinning conns indefinitely —
	// over a long-running OOB session this surfaces as goroutine
	// + FD growth from the request handler side.
	srv := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       30 * time.Second,
	}
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	s.listener = l
	s.httpSrv = srv
	go srv.Serve(l)
	return nil
}

func (s *Session) handle(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(io.LimitReader(r.Body, 64*1024))
	r.Body.Close()
	headers := dumpHeaders(r)
	tok := s.matchToken(r.URL.Path + " " + r.Host)
	in := Interaction{
		Kind:        "http",
		Token:       tok,
		At:          time.Now(),
		RemoteAddr:  r.RemoteAddr,
		Host:        r.Host,
		Method:      r.Method,
		Path:        r.URL.RequestURI(),
		UserAgent:   r.UserAgent(),
		BodySnippet: truncate(string(body), 600),
		RawHeaders:  headers,
	}
	s.appendInteraction(in)
	// Echo back a tiny JSON ACK — useful to confirm reachability.
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"ok": true, "token": tok, "received_at": in.At,
	})
}

func (s *Session) matchToken(s2 string) string {
	low := strings.ToLower(s2)
	for _, t := range s.Tokens {
		if strings.Contains(low, strings.ToLower(t)) {
			return t
		}
	}
	return ""
}

func (s *Session) appendInteraction(in Interaction) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.interactions) > 500 {
		s.interactions = s.interactions[1:]
	}
	s.interactions = append(s.interactions, in)
}

func dumpHeaders(r *http.Request) string {
	var b strings.Builder
	for k, vs := range r.Header {
		for _, v := range vs {
			b.WriteString(k + ": " + v + "\n")
		}
	}
	return b.String()
}

func shortRand(n int) string {
	b := make([]byte, (n+1)/2)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)[:n]
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// --- Globally registered sessions ------------------------------------------------------

var (
	sessionsMu sync.Mutex
	sessions   = map[string]*Session{}
)

// Register puts a session in a global lookup table so handlers can fetch
// its interactions for a long-running scan.
func Register(s *Session) {
	sessionsMu.Lock()
	defer sessionsMu.Unlock()
	sessions[s.ID] = s
}

// Get retrieves a session by id.
func Get(id string) *Session {
	sessionsMu.Lock()
	defer sessionsMu.Unlock()
	return sessions[id]
}

// Drop removes a session.
func Drop(id string) {
	sessionsMu.Lock()
	defer sessionsMu.Unlock()
	if s, ok := sessions[id]; ok {
		s.Close()
		delete(sessions, id)
	}
}

// CallbackURL returns a sensible URL for an external probe to call. If a
// public hostname has been configured (Settings.OOBHost) the function uses
// it; otherwise it falls back to the local listener.
func CallbackURL(s *Session, token, publicHost string) string {
	host := publicHost
	if host == "" {
		host = s.BaseDomain
	}
	if host == "" {
		// Localhost fallback — only useful for in-network testing.
		host = s.HTTPListen()
	}
	scheme := "http://"
	return fmt.Sprintf("%s%s/%s", scheme, host, token)
}
