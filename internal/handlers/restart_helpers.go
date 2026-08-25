package handlers

import (
	"encoding/json"
	"time"

	"scanner/internal/modules/direnum"
	"scanner/internal/modules/dnsenum"
	"scanner/internal/modules/spider"
)

func defaultSpiderConfig() spider.SpiderConfig {
	return spider.DefaultConfig()
}

// restartDirEnum parses stored config and launches a direnum scan
func (h *Handler) restartDirEnum(scanID, configJSON string) {
	var c struct {
		URLs            []string `json:"urls"`
		Techs           []string `json:"techs"`
		Level           int      `json:"level"`
		SmartScan       bool     `json:"smart_scan"`
		FilterCodes     []int    `json:"filter_codes"`
		Recursive       bool     `json:"recursive"`
		MaxDepth        int      `json:"max_depth"`
		ExcludePaths    []string `json:"exclude_paths"`
		CustomWordlists []string `json:"custom_wordlists"`
	}
	json.Unmarshal([]byte(configJSON), &c)

	// Pull Concurrency + Timeout from live Settings on every restart
	// rather than the stored config — those knobs are global and the
	// operator may have tuned them since the original run.
	settings := h.db.GetSettings()
	cfg := direnum.DefaultConfig()
	if len(c.Techs) > 0 {
		cfg.Techs = c.Techs
	}
	cfg.Level = direnum.ScanLevel(c.Level)
	cfg.SmartScan = c.SmartScan
	cfg.Concurrency = settings.EffectiveWebMaxConcurrent()
	cfg.Timeout = time.Duration(settings.EffectiveWebTimeout()) * time.Second
	// Audit fix: previously these four fields were dropped on Restart,
	// so a re-run had different filter codes, no recursion, default
	// depth and no exclude list — silently a different scan.
	cfg.FilterCodes = c.FilterCodes
	cfg.Recursive = c.Recursive
	cfg.MaxDepth = c.MaxDepth
	cfg.ExcludePaths = c.ExcludePaths
	cfg.CustomWordlists = c.CustomWordlists

	// Audit fix: wire up the live per-scan skip set on restart too,
	// mirroring DirEnumRun. Without this, DirEnumSkip requests during
	// the restarted scan would be recorded but never consulted by the
	// BFS recursion — the user's mid-scan blacklist would silently
	// have no effect on the re-run.
	cfg.IsSkipped = func(absURL string) bool {
		return h.scanMgr.IsSkipped(scanID, absURL)
	}

	// Audit fix: pass the BuildHTTPOptionsFromSettings() opts so the
	// restart inherits proxy / UA / killswitch binding from Settings.
	// Previously nil was passed which dropped all of those.
	h.runDirEnum(scanID, c.URLs, cfg, h.BuildHTTPOptionsFromSettings())
}

// restartDNSEnum parses stored config and launches a dnsenum scan
func (h *Handler) restartDNSEnum(scanID, configJSON string) {
	var c struct {
		Domains            []string      `json:"domains"`
		Speed              dnsenum.Speed `json:"speed"`
		AXFR               bool          `json:"axfr"`
		ReverseDNS         bool          `json:"reverse_dns"`
		CrtSh              bool          `json:"crtsh"`
		ReverseCIDR        string        `json:"reverse_cidr"`
		MaxDepth           int           `json:"max_depth"`
		ResolveConcurrency int           `json:"resolve_concurrency"`
		BruteRateLimit     int           `json:"brute_rate_limit"`
		PTRConcurrency     int           `json:"ptr_concurrency"`
		WordlistPath       string        `json:"wordlist_path"`
	}
	json.Unmarshal([]byte(configJSON), &c)

	// Pick up Settings keys on restart too — passive sources stay configured.
	settings := h.db.GetSettings()
	opts := dnsenum.Options{
		AXFR:               c.AXFR,
		ReverseDNS:         c.ReverseDNS,
		CrtSh:              c.CrtSh,
		ReverseCIDR:        c.ReverseCIDR,
		MaxDepth:           c.MaxDepth,
		VirusTotalKey:      settings.VirusTotalAPIKey,
		ShodanKey:          settings.ShodanAPIKey,
		CensysID:           settings.CensysID,
		CensysSecret:       settings.CensysSecret,
		ResolveConcurrency: c.ResolveConcurrency,
		BruteRateLimit:     c.BruteRateLimit,
		PTRConcurrency:     c.PTRConcurrency,
		WordlistPath:       c.WordlistPath,
	}
	h.runDNSEnum(scanID, c.Domains, c.Speed, opts)
}
