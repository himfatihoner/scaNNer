package handlers

import (
	"crypto/tls"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// sendToBurpSem caps in-flight SendToBurp goroutines (audit B23). A user
// who spam-clicks the "→ Burp" pill on a long result list (hundreds of
// findings) could spawn one goroutine per click, each holding an HTTP
// client + proxy conn. Over a 2-day session this surfaces as goroutine
// + FD growth from a handler the operator thinks is fire-and-forget.
// 16 in-flight is generous for the actual click rate; the handler
// abandons the request if the queue is full rather than blocking the
// HTTP response.
var sendToBurpSem = make(chan struct{}, 16)

// SendToBurp pushes a single URL through the user's configured proxy
// (typically Burp at 127.0.0.1:8080) so a finding can land in Repeater
// with one click — the on-demand counterpart to the existing
// "Proxy only successful findings" auto-replay. The handler accepts:
//
//	POST /scans/send-to-burp  (form: url=<absolute URL>)
//
// 204 = sent, 400 = bad URL, 412 = proxy not configured.
func (h *Handler) SendToBurp(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	target := strings.TrimSpace(r.FormValue("url"))
	if target == "" {
		http.Error(w, "missing url", http.StatusBadRequest)
		return
	}
	parsed, err := url.Parse(target)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		http.Error(w, "invalid url", http.StatusBadRequest)
		return
	}

	settings := h.db.GetSettings()
	if !settings.UseProxy || settings.ProxyURL == "" {
		http.Error(w, "proxy not configured — set it in Settings → HTTP Proxy first", http.StatusPreconditionFailed)
		return
	}
	proxyParsed, err := url.Parse(settings.ProxyURL)
	if err != nil {
		http.Error(w, "settings proxy URL is malformed", http.StatusInternalServerError)
		return
	}

	// Acquire a slot. If 16 are already in-flight (queue saturated by
	// click spam), drop this request rather than block. Operator can
	// retry — Burp won't have lost any prior submissions.
	select {
	case sendToBurpSem <- struct{}{}:
	default:
		http.Error(w, "send-to-burp queue full — try again in a moment", http.StatusTooManyRequests)
		return
	}
	// Resolve method override before spawning so we don't touch r in the
	// goroutine (the request body is reused by net/http after return).
	methodOverride := strings.ToUpper(strings.TrimSpace(r.FormValue("method")))
	go func() {
		defer func() { <-sendToBurpSem }()
		// Fire-and-forget: the user just wants the request to land in
		// the proxy's history; we don't care about the response.
		client := &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				Proxy:           http.ProxyURL(proxyParsed),
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
				DialContext:     (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
			},
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
		req, err := http.NewRequest("GET", target, nil)
		if err != nil {
			return
		}
		if methodOverride != "" {
			req.Method = methodOverride
		}
		// Mark the request as coming from scaNNer so users can grep
		// for it in Burp's history pane.
		req.Header.Set("X-Sent-By-scaNNer", "1")
		resp, err := client.Do(req)
		if err != nil {
			return
		}
		resp.Body.Close()
	}()
	w.WriteHeader(http.StatusNoContent)
}
