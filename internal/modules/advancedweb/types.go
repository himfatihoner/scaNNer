package advancedweb

import (
	"encoding/json"
	"time"
)

// Stage is the canonical id for one sub-module in the suite. Used as
// both a result-map key and as the toggle name in the form.
type Stage string

const (
	StageWhois       Stage = "whoisinfo"
	StageDNSEnum     Stage = "dnsenum"
	StageHTTPXFind   Stage = "httpxfind"
	StageSSLScan     Stage = "sslscan"
	StageWAFDetect   Stage = "wafdetect"
	StageTechDetect  Stage = "techdetect"
	StageCVEMatch    Stage = "cvematch" // fed by techdetect — requires it
	StageWPScan      Stage = "wpscan"   // fed by techdetect — only runs if WordPress detected
	StageNuclei      Stage = "nuclei"
	StageDirSpider   Stage = "dirspider" // direnum + spider iterative cross-feed
	StageHTTPMethods Stage = "httpmethods"
	StageSecHeaders  Stage = "secheaders"
)

// StageOrder is the canonical execution order — the suite never reorders
// these. Stage 9 (paramdisc) is intentionally absent: per spec it's not
// production-ready and should not run from the suite. CVE Matcher sits
// immediately after Tech Detection because it consumes its output.
var StageOrder = []Stage{
	StageWhois,
	StageDNSEnum,
	StageHTTPXFind,
	StageSSLScan,
	StageWAFDetect,
	StageTechDetect,
	StageCVEMatch,
	StageWPScan,
	StageNuclei,
	StageDirSpider,
	StageHTTPMethods,
	StageSecHeaders,
}

// StageDisplayNames maps internal ids to UI labels.
var StageDisplayNames = map[Stage]string{
	StageWhois:       "WHOIS / ASN",
	StageDNSEnum:     "DNS Enumeration",
	StageHTTPXFind:   "HTTPX Finder",
	StageSSLScan:     "SSL/TLS Scanner",
	StageWAFDetect:   "WAF / Firewall",
	StageTechDetect:  "Tech Detection",
	StageCVEMatch:    "CVE Matcher",
	StageWPScan:      "WPScan",
	StageNuclei:      "Nuclei",
	StageDirSpider:   "Directory + Spider",
	StageHTTPMethods: "HTTP Methods",
	StageSecHeaders:  "Security Headers",
}

// StageStatus is the lifecycle state of a single stage run. Unlike the
// top-level scan status (running/done/error/cancelled), stages can also
// be `skipped` (input kind made it irrelevant — e.g. WHOIS on a URL)
// or `disabled` (user didn't tick the checkbox).
type StageStatus string

const (
	StatusPending  StageStatus = "pending"
	StatusDisabled StageStatus = "disabled"
	StatusSkipped  StageStatus = "skipped"
	StatusRunning  StageStatus = "running"
	StatusDone     StageStatus = "done"
	StatusError    StageStatus = "error"
)

// StageResult carries one stage's outcome. Result is stored as
// json.RawMessage so the native module's result type round-trips
// without requiring the suite to depend on every module's struct
// definition at compile time — and so the UI can re-use each module's
// existing `*_results_inner` template by unmarshaling on demand.
type StageResult struct {
	Stage      Stage           `json:"stage"`
	Status     StageStatus     `json:"status"`
	Message    string          `json:"message,omitempty"`
	Error      string          `json:"error,omitempty"`
	StartedAt  time.Time       `json:"started_at,omitempty"`
	FinishedAt time.Time       `json:"finished_at,omitempty"`
	Result     json.RawMessage `json:"result,omitempty"`

	// Per-stage progress: ProgressDone counts items completed within
	// the stage (URLs probed, targets parsed, etc.). ProgressTotal is
	// the upfront denominator (number of inputs the stage will process).
	// ProgressMsg is the most recent free-text emitted by the module's
	// progress callback. UI uses Done/Total to render a % bar while the
	// stage is `running`. Zero values are fine — just no bar will render.
	ProgressDone  int    `json:"progress_done,omitempty"`
	ProgressTotal int    `json:"progress_total,omitempty"`
	ProgressMsg   string `json:"progress_msg,omitempty"`
}

// Config is what the handler passes to Scan(). All Enable* flags map
// 1:1 to the form checkboxes; the rest are sub-options.
type Config struct {
	// Target is the legacy single-target field — kept for back-compat
	// with older scan records. New scans populate Targets instead, but
	// Target is also auto-filled to Targets[0] for display + JSON tag
	// continuity.
	Target  string   `json:"target"`
	Targets []string `json:"targets,omitempty"`

	// ResumeStages seeds already-completed stage results when resuming a paused
	// suite (Task 0 stage-level resume). Keyed by Stage; the value is that
	// stage's stored Result JSON. Scan skips re-running a seeded stage and,
	// for the data-producing stages (DNS/HTTPX/TechDetect), reconstructs its
	// in-memory result so downstream stages still get their input. Not
	// persisted (json:"-") — it's derived from the paused scan's result row.
	ResumeStages map[Stage]json.RawMessage `json:"-"`

	EnableWhois       bool `json:"enable_whois"`
	EnableDNSEnum     bool `json:"enable_dnsenum"`
	EnableHTTPXFind   bool `json:"enable_httpxfind"`
	EnableSSLScan     bool `json:"enable_sslscan"`
	EnableWAFDetect   bool `json:"enable_wafdetect"`
	EnableTechDetect  bool `json:"enable_techdetect"`
	EnableCVEMatch    bool `json:"enable_cvematch"`
	EnableWPScan      bool `json:"enable_wpscan"`
	EnableNuclei      bool `json:"enable_nuclei"`
	EnableDirSpider   bool `json:"enable_dirspider"`
	EnableHTTPMethods bool `json:"enable_httpmethods"`
	EnableSecHeaders  bool `json:"enable_secheaders"`

	// Sub-options — per-stage customizations. Defaults come from the
	// depth preset (Quick/Normal/Deep) which the UI flips. Each field
	// is independently editable so users can deviate from any preset.
	DNSEnumSpeed       string   `json:"dnsenum_speed"`        // fast|normal|aggressive
	DNSEnumMaxDepth    int      `json:"dnsenum_max_depth"`    // recursion depth (1-3)
	HTTPXMode          string   `json:"httpx_mode"`         // common | full | custom
	HTTPXConcurrency   int      `json:"httpx_concurrency"`  // HTTP probe concurrency override; 0 → module default (20)
	HTTPXCustomPorts   string   `json:"httpx_custom_ports"` // CSV+range port spec ("80,443,8000-8100"); only honoured when HTTPXMode == "custom"
	// SSLScanPorts is the port set the SSL/TLS stage probes on each discovered
	// host. The stage is INDEPENDENT of HTTPX (it no longer consumes HTTPX's
	// live-service list, so TLS on ports HTTPX didn't surface isn't skipped);
	// HTTPX output still feeds the later web stages. CSV+range ("443,8443,993").
	// Empty → the default set (443,8443).
	SSLScanPorts       string   `json:"sslscan_ports"`
	// SSLScanFullEvidence forces the SSL/TLS stage onto the full-evidence path
	// (nmap + sslscan + openssl, tool transcripts + per-finding PoC) instead of
	// the light bulk path. Off for normal suite runs (evidence over 1000s of
	// hosts blew results past 200 MB); a single-finding rescan sets it so the
	// verified finding gets its complete PoC/tool output.
	SSLScanFullEvidence bool `json:"sslscan_full_evidence,omitempty"`
	DirEnumLevel       string   `json:"direnum_level"`        // light|normal|aggressive
	DirEnumSmartScan   bool     `json:"direnum_smart_scan"`
	DirEnumRecursive   bool     `json:"direnum_recursive"`
	DirEnumMaxDepth    int      `json:"direnum_max_depth"`
	SpiderMaxDepth     int      `json:"spider_max_depth"`
	SpiderMaxPages     int      `json:"spider_max_pages"`
	NucleiSeverities   []string `json:"nuclei_severities"`
	NucleiLevel        string   `json:"nuclei_level"`                   // aggressiveness: polite|normal|aggressive (rate/concurrency/bulk preset)
	NucleiTemplateIDs  []string `json:"nuclei_template_ids,omitempty"`   // when set, run ONLY these templates (-t) — used by a single-finding rescan
	TechDetectAggressive bool   `json:"techdetect_aggressive"` // run whatweb -a 3 on every live service (deeper, slower) instead of the fast prefetched path
	WPScanSpeed        string   `json:"wpscan_speed"` // fast | normal | aggressive
	SecHeadersMethods  []string `json:"secheaders_methods"`
	SecHeadersOverride bool     `json:"secheaders_override"`  // when true, use SecHeadersMethods as-is (skip auto-derive from Stage 10)
}

// ScanResult is the single JSON blob persisted in scans.result for an
// advancedweb run. It carries enough context (Target, Kind, StageOrder)
// for the UI to render even partially-completed scans coherently.
type ScanResult struct {
	Target     string                 `json:"target"`
	Kind       string                 `json:"kind"`
	StartedAt  time.Time              `json:"started_at"`
	FinishedAt time.Time              `json:"finished_at,omitempty"`
	StageOrder []Stage                `json:"stage_order"`
	Stages     map[Stage]*StageResult `json:"stages"`
	// PracticalNotes is a top-of-page narrative: short bullet list of
	// suite-level observations (e.g. "input is URL — DNS skipped",
	// "tech detection found IIS → DirEnum auto-included asp profile").
	Notes []string `json:"notes,omitempty"`
	// Error captures a suite-wide fatal — e.g. an unrecovered panic in
	// a stage, or input validation failure mid-scan. Per-stage errors
	// live in StageResult.Error; this field is for "the whole suite
	// died" cases that would otherwise leave a blank/cryptic page.
	Error string `json:"error,omitempty"`
	// Incomplete is set when a stage was cut short (e.g. nuclei hit its
	// time cap, DirSpider hit its deadline) so the suite finished but did
	// NOT fully cover the target. Unlike Error (a fatal), the suite still
	// produced usable partial results — but the handler must finalize the
	// scan with a non-"done" outcome so the Scans list / dashboard don't
	// present a truncated run as a clean green success.
	Incomplete       bool   `json:"incomplete,omitempty"`
	IncompleteReason string `json:"incomplete_reason,omitempty"`
}
