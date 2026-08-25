package models

import (
	"strings"
	"time"
)

type ScanStatus string

const (
	ScanPending   ScanStatus = "pending"
	ScanRunning   ScanStatus = "running"
	ScanDone      ScanStatus = "done"
	ScanError     ScanStatus = "error"
	ScanCancelled ScanStatus = "cancelled"
	// ScanPaused: the connectivity monitor detected internet loss and paused
	// the scan instead of hard-erroring it. The partial result + config +
	// progress are preserved; the resume path re-runs only the remaining work
	// (config − done) and appends into the same row. No DB migration needed —
	// status is a plain TEXT column with no CHECK constraint.
	ScanPaused ScanStatus = "paused"
	// ScanQueued: the operator ticked "start after the current scan finishes"
	// on the launch form (sequential scanning). The scan row is created with
	// its full config but NOT dispatched; the scan-queue scheduler
	// (StartScanQueue) flips it queued→pending and replays it via
	// dispatchRestart once its workspace has no other running/pending scan.
	// FIFO by created_at. Survives a process restart untouched (the orphan
	// sweep only reaps running/pending), so the scheduler picks it back up.
	ScanQueued ScanStatus = "queued"
)

type Scan struct {
	ID            string     `db:"id"              json:"id"`
	WorkspaceID   string     `db:"workspace_id"    json:"workspace_id"`
	Module        string     `db:"module"          json:"module"`
	Status        ScanStatus `db:"status"          json:"status"`
	Config        string     `db:"config"          json:"config"`
	Result        string     `db:"result"          json:"result"`
	ProgressDone  int        `db:"progress_done"   json:"progress_done"`
	ProgressTotal int        `db:"progress_total"  json:"progress_total"`
	ProgressMsg   string     `db:"progress_msg"    json:"progress_msg"`
	StartedAt     *time.Time `db:"started_at"      json:"started_at"`
	FinishedAt    *time.Time `db:"finished_at"     json:"finished_at"`
	CreatedAt     time.Time  `db:"created_at"      json:"created_at"`
	Archived      bool       `db:"archived"        json:"archived"`
	// Commands holds every external command the scanner ran (newline-separated,
	// each line begins with "$ "). Persisted by UpdateScanProgress whenever the
	// running module emits a `$ ...` progress message.
	Commands string `db:"commands" json:"commands,omitempty"`

	// ConsoleLog is the FULL progress-message stream (every line the module
	// emitted, newline-separated, trimmed to the last ~200 KB). Unlike
	// Commands (only "$ " crumbs) and ProgressMsg (only the latest line), this
	// is lossless, so the live console can be seeded on page load and a
	// finished/reloaded scan still shows the whole run. Appended by every
	// progress writer via DB.appendConsoleLog.
	ConsoleLog string `db:"console_log" json:"console_log,omitempty"`

	// SeverityCount + OpenConnectionsCount are denormalized counters kept
	// in sync with Result on every UpdateScanResult write (see
	// internal/scanstats.Compute). The dashboard chart aggregator reads
	// them directly instead of re-parsing each scan's multi-megabyte
	// Result blob — turning a multi-second page render into a few ms.
	// Older rows backfilled at startup.
	SeverityCount        int `db:"severity_count"         json:"severity_count"`
	OpenConnectionsCount int `db:"open_connections_count" json:"open_connections_count"`
}

// CommandLines splits the persisted Commands log into individual lines.
func (s Scan) CommandLines() []string {
	if s.Commands == "" {
		return nil
	}
	out := []string{}
	for _, l := range strings.Split(s.Commands, "\n") {
		l = strings.TrimSpace(l)
		if l != "" {
			out = append(out, l)
		}
	}
	return out
}

// ConsoleLines splits the persisted full console log into individual lines.
// Used to seed the live console on page load and to render the console panel
// on a finished/reloaded scan.
func (s Scan) ConsoleLines() []string {
	if s.ConsoleLog == "" {
		return nil
	}
	out := []string{}
	for _, l := range strings.Split(s.ConsoleLog, "\n") {
		if strings.TrimSpace(l) != "" {
			out = append(out, l)
		}
	}
	return out
}

// ModuleDisplayName returns human-readable module names
func ModuleDisplayName(module string) string {
	switch module {
	case "sslscan":
		return "SSL/TLS Scanner"
	case "httpxfind":
		return "HTTPX Finder"
	case "httpmethods":
		return "HTTP Method Tester"
	case "wafdetect":
		return "WAF Detector"
	case "wpscan":
		return "WPScan"
	case "dnsenum":
		return "DNS Enumerator"
	case "techdetect":
		return "Tech Detector"
	case "spider":
		return "Web Spider"
	case "direnum":
		return "Directory Enumerator"
	case "secheaders":
		return "Security Headers"
	case "nuclei":
		return "Nuclei"
	case "hostdiscovery":
		return "Host Discovery"
	case "portservice":
		return "Advanced Host Scanner"
	case "smbenum":
		return "SMB Enum"
	case "brutef":
		return "Service Brute Forcer"
	case "whoisinfo":
		return "WHOIS / ASN Lookup"
	case "emailharvest":
		return "Email Harvester"
	case "leakscan":
		return "GitHub Leak Scanner"
	case "snmpenum":
		return "SNMP Enum"
	case "jwt":
		return "JWT Analyzer"
	case "paramdisc":
		return "Parameter Discovery"
	case "concurtest":
		return "Concurrency Tester"
	case "advancedweb":
		return "Advanced Web Application Scanner"
	case "takeover":
		return "Subdomain Takeover"
	case "corsscan":
		return "CORS Misconfig"
	case "openredirect":
		return "Open Redirect"
	case "cvematch":
		return "CVE Matcher"
	case "graphqlscan":
		return "GraphQL Scanner"
	case "authtest":
		return "Auth Tester"
	case "assetdisc":
		return "Asset Discovery"
	case "oob":
		return "OOB Collaborator"
	case "sstiscan":
		return "SSTI Probe"
	case "cachepoison":
		return "Cache & Smuggle"
	default:
		return module
	}
}
