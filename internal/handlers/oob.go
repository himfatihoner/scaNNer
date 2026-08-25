package handlers

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"scanner/internal/models"
	"scanner/internal/modules/oob"
)

// OOBSession is the persisted shape of a Session as stored in the scan row.
type OOBSession struct {
	SessionID  string   `json:"session_id"`
	BaseDomain string   `json:"base_domain"`
	HTTPAddr   string   `json:"http_addr"`
	Tokens     []string `json:"tokens"`
	URLs       []string `json:"urls"`
}

// oobMaxTokens caps the number of tokens per session. Audit fix: the HTML
// form advertises max=20 but there was no server-side clamp — a curl bypass
// with tokens=2^31-1 triggered a 2.1B-iteration crypto/rand fan-out inside
// oob.NewSession.
const oobMaxTokens = 64

// validateOOBListen bounds the address the user can bind to. Prevents
// hijacking privileged ports (< 1024) or binding to arbitrary host IPs
// that aren't loopback / wildcard. Empty / ":<port>" / "0.0.0.0:<port>" /
// "127.0.0.1:<port>" and their IPv6 equivalents are accepted; anything
// else is rejected.
func validateOOBListen(addr string) (string, bool) {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return ":0", true
	}
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return "", false
	}
	switch host {
	case "", "0.0.0.0", "::", "127.0.0.1", "::1":
		// allowed
	default:
		return "", false
	}
	if portStr == "" {
		portStr = "0"
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 0 || port > 65535 {
		return "", false
	}
	// Refuse privileged ports — scanner may run with
	// CAP_NET_BIND_SERVICE (killswitch model) and would otherwise let
	// any authenticated user grab port 22 / 80 / 443 out from under
	// other services on the host.
	if port > 0 && port < 1024 {
		return "", false
	}
	return net.JoinHostPort(host, portStr), true
}

func (h *Handler) OOBPage(w http.ResponseWriter, r *http.Request) {
	data := h.baseData(r, "OOB Collaborator - scaNNer", "oob")
	ws := data["ActiveWorkspace"].(*models.Workspace)
	scans, _ := h.db.ListScansLite(ws.ID, "oob")
	data["Scans"] = scans
	h.render(w, "layout", data)
}

func (h *Handler) OOBRun(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/modules/oob", http.StatusSeeOther)
		return
	}
	r.ParseForm()
	ws := h.activeWorkspace(r)
	tokens, _ := strconv.Atoi(strings.TrimSpace(r.FormValue("tokens")))
	if tokens <= 0 {
		tokens = 3
	}
	// Audit fix: clamp tokens server-side. Without this a curl POST
	// with tokens=2^31-1 spun a 2.1B-iteration crypto/rand loop inside
	// NewSession and OOM'd the process.
	if tokens > oobMaxTokens {
		tokens = oobMaxTokens
	}
	baseDomain := strings.TrimSpace(r.FormValue("base_domain"))
	listenAddr, ok := validateOOBListen(r.FormValue("listen_addr"))
	if !ok {
		// Audit fix: reject arbitrary host bindings + privileged ports.
		// Previously any string was forwarded straight to net.Listen.
		http.Redirect(w, r, "/modules/oob?error=invalid_listen_addr", http.StatusSeeOther)
		return
	}

	sess, err := oob.NewSession(tokens, baseDomain, listenAddr)
	if err != nil {
		http.Redirect(w, r, "/modules/oob?error=listen_failed", http.StatusSeeOther)
		return
	}
	oob.Register(sess)

	ses := OOBSession{
		SessionID:  sess.ID,
		BaseDomain: sess.BaseDomain,
		HTTPAddr:   sess.HTTPListen(),
		Tokens:     sess.Tokens,
		URLs:       sess.URLs(),
	}
	cfgJSON, _ := json.Marshal(ses)
	scan, err := h.db.CreateScan(ws.ID, "oob", string(cfgJSON), 0)
	if err != nil {
		sess.Close()
		oob.Drop(sess.ID)
		http.Redirect(w, r, "/modules/oob?error=db_error", http.StatusSeeOther)
		return
	}
	h.db.MarkRunning(scan.ID)
	// Seed the console so an OOB scan isn't a blank striped bar with an empty
	// log forever: show the bound listener + the callback URLs to plant, and
	// warn about the #1 silent failure — a loopback bind with no public host,
	// which no external callback (blind SSRF/XXE/SSTI) can ever reach.
	h.db.UpdateScanProgress(scan.ID, 0, "$ oob HTTP listener on "+sess.HTTPListen())
	for _, u := range sess.URLs() {
		h.db.UpdateScanProgress(scan.ID, 0, "→ plant this callback URL: "+u)
	}
	if la := sess.HTTPListen(); (strings.HasPrefix(la, "127.") || strings.HasPrefix(la, "[::1]") || strings.HasPrefix(la, "localhost")) && sess.BaseDomain == "" {
		h.db.UpdateScanProgress(scan.ID, 0, "⚠ listener is on loopback with no public host — external callbacks cannot reach it; bind a reachable interface / set a public host (lab, VPN, or public IP)")
	}
	// Audit fix: the only writer of interactions to the DB used to be
	// OOBResults (a polling GET) which re-ran the 50 MB cap check +
	// scanstats.Compute on every poll — a write-amplification DoS
	// vector. Now the results page is a pure read and this background
	// flusher owns persistence.
	go h.oobFlusher(scan.ID, sess.ID)
	http.Redirect(w, r, "/modules/oob/results/"+scan.ID, http.StatusSeeOther)
}

// oobFlusher periodically snapshots the in-memory interactions slice to
// the DB so a server restart doesn't lose captured hits. Runs until the
// session is dropped (Stop / ScanStop / ScanDelete). Only writes when the
// interaction count has grown to keep write amplification low.
func (h *Handler) oobFlusher(scanID, sessionID string) {
	lastCount := -1
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		sess := oob.Get(sessionID)
		if sess == nil {
			return
		}
		interactions := sess.Interactions()
		if len(interactions) == lastCount {
			continue
		}
		lastCount = len(interactions)
		if n := len(interactions); n > 0 {
			last := interactions[n-1]
			where := last.RemoteAddr
			if last.Kind == "http" && last.Path != "" {
				where = last.Method + " " + last.Path + " from " + last.RemoteAddr
			}
			h.db.UpdateScanProgress(scanID, n, fmt.Sprintf("✓ %d interaction(s) captured — latest: %s %s", n, last.Kind, where))
		}
		resJSON, _ := json.Marshal(map[string]any{"interactions": interactions})
		h.db.UpdateScanResult(scanID, string(resJSON))
	}
}

func (h *Handler) OOBResults(w http.ResponseWriter, r *http.Request) {
	scanID := strings.TrimPrefix(r.URL.Path, "/modules/oob/results/")
	scan, err := h.db.GetScan(scanID)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	var ses OOBSession
	// Audit fix: check unmarshal error so a corrupted config row
	// surfaces as an empty-config render instead of the caller reading
	// zero-valued fields and silently proceeding.
	if err := json.Unmarshal([]byte(scan.Config), &ses); err != nil {
		ses = OOBSession{}
	}
	var sess *oob.Session
	if ses.SessionID != "" {
		sess = oob.Get(ses.SessionID)
	}
	var interactions []oob.Interaction
	if sess != nil {
		interactions = sess.Interactions()
	} else if scan.Result != "" {
		// When the listener is gone (server restart, scan stopped),
		// re-read what the flusher last saved so the UI still shows
		// captured interactions.
		var prev struct {
			Interactions []oob.Interaction `json:"interactions"`
		}
		if json.Unmarshal([]byte(scan.Result), &prev) == nil {
			interactions = prev.Interactions
		}
	}
	// Audit fix: pure read. Persistence now lives in oobFlusher /
	// OOBStop. Previously every polling hit triggered a full
	// UpdateScanResult write (cap check + scanstats.Compute).

	data := h.baseData(r, "OOB Results - scaNNer", "oob_results")
	data["Scan"] = scan
	data["Session"] = ses
	data["Interactions"] = interactions
	data["Live"] = sess != nil
	h.renderResults(w, r, "oob_results_inner", data)
}

func (h *Handler) OOBStatus(w http.ResponseWriter, r *http.Request) {
	scanID := strings.TrimPrefix(r.URL.Path, "/modules/oob/status/")
	scan, err := h.db.GetScan(scanID)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	h.writeScanStatus(w, scan)
}

// OOBStop tears down the listener and marks the scan done. Called by the
// generic /scans/stop/ endpoint via h.scanMgr.Cancel — but OOB doesn't use
// scanMgr, so we wire a dedicated stop hook.
func (h *Handler) OOBStop(w http.ResponseWriter, r *http.Request) {
	// Audit fix: previously accepted GET, letting a browser prefetcher
	// or an <img src=...> tag tear down any user's listener. Mirrors
	// the OOBRun POST guard.
	if r.Method != http.MethodPost {
		scanID := strings.TrimPrefix(r.URL.Path, "/modules/oob/stop/")
		http.Redirect(w, r, "/modules/oob/results/"+scanID, http.StatusSeeOther)
		return
	}
	scanID := strings.TrimPrefix(r.URL.Path, "/modules/oob/stop/")
	scan, err := h.db.GetScan(scanID)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	// Audit fix: scope to active workspace so a POST to
	// /modules/oob/stop/<other-workspace's-scan-id> can't kill
	// sessions in another workspace.
	ws := h.activeWorkspace(r)
	if ws != nil && scan.WorkspaceID != ws.ID {
		http.NotFound(w, r)
		return
	}
	var ses OOBSession
	if err := json.Unmarshal([]byte(scan.Config), &ses); err != nil || ses.SessionID == "" {
		// Corrupted / empty config — flip status but don't touch the
		// session map since we can't identify the session.
		h.db.UpdateScanStatus(scanID, "done")
		http.Redirect(w, r, "/modules/oob/results/"+scanID, http.StatusSeeOther)
		return
	}
	if sess := oob.Get(ses.SessionID); sess != nil {
		// Persist a final snapshot BEFORE Drop so the results page
		// still shows captured interactions after the flusher exits.
		interactions := sess.Interactions()
		resJSON, _ := json.Marshal(map[string]any{"interactions": interactions})
		h.db.UpdateScanResult(scanID, string(resJSON))
		oob.Drop(ses.SessionID)
	}
	h.db.UpdateScanStatus(scanID, "done")
	http.Redirect(w, r, "/modules/oob/results/"+scanID, http.StatusSeeOther)
}

// startOOBRestart mints a fresh session (new tokens, new listener) for
// a restarted OOB scan and rewrites the scan row's Config to point at
// the new session. Called from dispatchRestart. Without this, clicking
// Restart on a stopped OOB scan used to create a new row stuck in
// "pending" forever with no listener bound.
func (h *Handler) startOOBRestart(scanID string, prev OOBSession) {
	tokens := len(prev.Tokens)
	if tokens <= 0 {
		tokens = 3
	}
	if tokens > oobMaxTokens {
		tokens = oobMaxTokens
	}
	sess, err := oob.NewSession(tokens, prev.BaseDomain, ":0")
	if err != nil {
		h.db.MarkScanError(scanID, "OOB restart: "+err.Error())
		return
	}
	oob.Register(sess)
	ses := OOBSession{
		SessionID:  sess.ID,
		BaseDomain: sess.BaseDomain,
		HTTPAddr:   sess.HTTPListen(),
		Tokens:     sess.Tokens,
		URLs:       sess.URLs(),
	}
	cfgJSON, _ := json.Marshal(ses)
	h.db.UpdateScanConfig(scanID, string(cfgJSON))
	h.db.MarkRunning(scanID)
	go h.oobFlusher(scanID, sess.ID)
}
