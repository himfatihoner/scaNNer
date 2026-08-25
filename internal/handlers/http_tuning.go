package handlers

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"scanner/internal/capacity"
	"scanner/internal/modules/shared"
	"scanner/internal/sysmon"
)

// HTTPTuning holds per-scan overrides of the global web-scan defaults, parsed
// from the http_tuning form partial. A field left blank inherits Settings.
type HTTPTuning struct {
	TimeoutSet  bool
	Timeout     int // seconds
	ConcSet     bool
	Concurrency int
	RateSet     bool
	RateLimit   int // req/s; 0 = explicit unlimited
}

// parseHTTPTuning reads the http_tuning partial's fields (req_timeout /
// max_concurrent / rate_limit). Blank/invalid → unset (inherit).
func parseHTTPTuning(r *http.Request) HTTPTuning {
	var t HTTPTuning
	if v := strings.TrimSpace(r.FormValue("req_timeout")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			t.Timeout, t.TimeoutSet = n, true
		}
	}
	if v := strings.TrimSpace(r.FormValue("max_concurrent")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			t.Concurrency, t.ConcSet = n, true
		}
	}
	if v := strings.TrimSpace(r.FormValue("rate_limit")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			t.RateLimit, t.RateSet = n, true
		}
	}
	return t
}

// applyHTTPTuning applies per-scan tuning for a module (Class-A Go-HTTP path).
// It derives the module from the run-route path so the concurrency DEFAULT can
// be the capacity-recommended per-module value; see applyHTTPTuningFor.
func (h *Handler) applyHTTPTuning(r *http.Request, opts *shared.HTTPOptions) (concurrency, rateLimit int) {
	return h.applyHTTPTuningFor(r, opts, moduleFromRunPath(r.URL.Path))
}

// applyHTTPTuningFor sets opts.Timeout and returns the effective concurrency +
// rate limit. Concurrency precedence:
//  1. explicit per-scan form field (max_concurrent) — the operator overrides;
//  2. else capacity.Recommend(module, live limits) — the smart per-module
//     default computed from the machine's real network limits;
//  3. bounded above by an explicitly-set global (web_max_concurrent /
//     max_concurrent) if the operator set one LOWER than the recommendation.
//
// Step 3 makes a user global a CAP, not an override — so the old flat "999"
// no longer forces every module to a runaway value; it just means "no cap".
func (h *Handler) applyHTTPTuningFor(r *http.Request, opts *shared.HTTPOptions, module string) (concurrency, rateLimit int) {
	t := parseHTTPTuning(r)
	s := h.db.GetSettings()

	timeout := s.EffectiveWebTimeout()
	if t.TimeoutSet {
		timeout = t.Timeout
	}
	if opts != nil {
		opts.Timeout = time.Duration(timeout) * time.Second
	}

	if t.ConcSet {
		concurrency = t.Concurrency
	} else {
		concurrency = capacity.Recommend(module, sysmon.ReadLimits())
		// An explicitly-set global (web tier preferred, else the legacy global)
		// caps the recommendation from above; unset (0) means "no cap".
		capMax := s.WebMaxConcurrent
		if capMax == 0 {
			capMax = s.MaxConcurrent
		}
		if capMax > 0 && capMax < concurrency {
			concurrency = capMax
		}
	}

	rateLimit = s.EffectiveWebRateLimit()
	if t.RateSet {
		rateLimit = t.RateLimit
	}
	return concurrency, rateLimit
}

// moduleFromRunPath extracts "<name>" from a "/modules/<name>/run" request path
// so per-module capacity recommendations can be keyed off the live route.
func moduleFromRunPath(p string) string {
	p = strings.TrimPrefix(p, "/modules/")
	if i := strings.IndexByte(p, '/'); i >= 0 {
		p = p[:i]
	}
	return p
}
