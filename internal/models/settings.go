package models

// AppSettings holds global application configuration. Web-tier settings
// govern HTTP-based modules (spider, direnum, httpxfind, secheaders, …);
// network-tier settings govern nmap / hydra / SNMP-style sweeps. The legacy
// flat fields (DefaultTimeout, MaxConcurrent, RateLimit) are kept as
// fallback so existing databases keep working — when a tier-specific value
// is 0 we fall back to the legacy global.
type AppSettings struct {
	// Legacy globals (fallback when web/network tier values are 0 / blank)
	DefaultTimeout int `db:"default_timeout"   json:"default_timeout"` // seconds
	MaxConcurrent  int `db:"max_concurrent"    json:"max_concurrent"`  // parallel ops
	RateLimit      int `db:"rate_limit"        json:"rate_limit"`      // req/s (0=∞)

	// Web-scan tier — HTTP modules.
	WebTimeout       int `db:"web_timeout"        json:"web_timeout"`        // per-request timeout (sec)
	WebMaxConcurrent int `db:"web_max_concurrent" json:"web_max_concurrent"` // parallel HTTP requests
	WebRateLimit     int `db:"web_rate_limit"     json:"web_rate_limit"`     // req/s (0=∞)

	// WebReachabilityPreflight (default ON): before a web module scans, probe
	// each target with a TCP+TLS handshake and skip any that can't complete it
	// (a host that resets/times out the TLS handshake would otherwise make the
	// tool grind through thousands of failing requests). Skipped targets still
	// appear as explicit "unreachable" rows. WebPreflightTimeout caps each probe
	// (seconds; 0 = default 4).
	WebReachabilityPreflight bool `db:"web_reachability_preflight" json:"web_reachability_preflight"`
	WebPreflightTimeout      int  `db:"web_preflight_timeout"      json:"web_preflight_timeout"`

	// Network-scan tier — nmap / hydra / snmp.
	NetworkTimeout       int `db:"network_timeout"        json:"network_timeout"`        // host timeout (sec)
	NetworkMaxConcurrent int `db:"network_max_concurrent" json:"network_max_concurrent"` // parallel host scans
	NetworkRateLimit     int `db:"network_rate_limit"     json:"network_rate_limit"`     // pkts/s for nmap (0=∞)
	BruteThreads         int `db:"brute_threads"          json:"brute_threads"`          // hydra/medusa -t

	// MaxCPUPercent is the fraction of CPU cores (as a percent, 10..100) the
	// capacity governor lets CPU-bound modules (e.g. techdetect/whatweb) consume.
	// 0 = use the built-in default (75). Feeds capacity.SetCPUBudget.
	MaxCPUPercent int `db:"max_cpu_percent" json:"max_cpu_percent"`

	// HTTP-only options (used by web modules)
	ProxyURL        string `db:"proxy_url"             json:"proxy_url"`
	UseProxy        bool   `db:"use_proxy"             json:"use_proxy"`
	BurpSuccessOnly bool   `db:"burp_success_only"     json:"burp_success_only"` // route only confirmed hits to proxy
	UserAgent       string `db:"user_agent"            json:"user_agent"`

	// Data
	DefaultExportFmt string `db:"default_export_fmt" json:"default_export_fmt"` // csv, json, pdf

	// Outbound network binding (killswitch). When NetworkInterface is
	// non-empty, ALL scan traffic must originate from that interface.
	// NetworkInterfaceIP is the cached primary IPv4 of that interface
	// at the time the setting was saved — the iface_monitor verifies
	// this still matches at scan time and aborts if not.
	//
	// Empty NetworkInterface = default mode: scans use the OS default
	// route, no binding enforced, killswitch dormant.
	NetworkInterface   string `db:"network_interface"    json:"network_interface,omitempty"`
	NetworkInterfaceIP string `db:"network_interface_ip" json:"network_interface_ip,omitempty"`

	// VPN watchdog. When VPNAutoReconnect is on, the connectivity monitor also
	// watches VPNInterface (e.g. tun0): if it drops — even while the box still
	// has plain internet via another iface — running scans are PAUSED (so no
	// traffic leaks off the VPN), then after VPNReconnectAfterSec the monitor
	// runs `nmcli connection up <VPNConnection>` to bring the tunnel back, and
	// resumes the paused scans from their checkpoint once it's healthy again.
	// Default ON; the user can disable it in Settings.
	VPNAutoReconnect     bool   `db:"vpn_auto_reconnect"      json:"vpn_auto_reconnect"`
	VPNConnection        string `db:"vpn_connection"          json:"vpn_connection,omitempty"`         // NetworkManager connection name (nmcli id)
	VPNInterface         string `db:"vpn_interface"           json:"vpn_interface,omitempty"`          // device to watch (blank → "tun0")
	VPNReconnectAfterSec int    `db:"vpn_reconnect_after_sec" json:"vpn_reconnect_after_sec"`         // grace before a reconnect attempt

	// API keys for third-party services.
	WPScanAPIKey string `db:"wpscan_api_key"  json:"wpscan_api_key,omitempty"`
	HIBPAPIKey   string `db:"hibp_api_key"    json:"hibp_api_key,omitempty"`
	GitHubToken  string `db:"github_token"    json:"github_token,omitempty"`
	ShodanAPIKey     string `db:"shodan_api_key"     json:"shodan_api_key,omitempty"`
	CensysID         string `db:"censys_id"          json:"censys_id,omitempty"`
	CensysSecret     string `db:"censys_secret"      json:"censys_secret,omitempty"`
	VirusTotalAPIKey string `db:"virustotal_api_key" json:"virustotal_api_key,omitempty"`

	// SMTP — used to deliver 2FA e-mail codes and admin notifications. These
	// are read fresh from the DB at send time (the mailer holds no cached
	// state), so saving new values takes effect immediately — no restart.
	// SMTP dials the HOST network directly (never the killswitch interface)
	// so mail still goes out while a scan-bound VPN is armed.
	SMTPHost     string `db:"smtp_host"     json:"smtp_host,omitempty"`
	SMTPPort     int    `db:"smtp_port"     json:"smtp_port,omitempty"`
	SMTPUser     string `db:"smtp_user"     json:"smtp_user,omitempty"`
	SMTPPassword string `db:"smtp_password" json:"smtp_password,omitempty"`
	SMTPFrom     string `db:"smtp_from"     json:"smtp_from,omitempty"`
	// SMTPTLSMode: "starttls" (submission :587), "ssl" (implicit TLS :465),
	// or "none" (plaintext — discouraged, dev only).
	SMTPTLSMode string `db:"smtp_tls_mode" json:"smtp_tls_mode,omitempty"`

	// TwoFactorAvailable exposes the "e-mail code" 2FA option to users. It is
	// only meaningful once SMTP is configured; TOTP is always available.
	TwoFactorAvailable bool `db:"two_factor_available" json:"two_factor_available"`

	// NTPServer, when set, is queried periodically to correct TOTP verification
	// time against host-clock drift (the system clock is never modified). Empty
	// = trust the local clock. TOTP only tolerates ~90s of skew, so a drifting
	// server clock silently breaks authenticator logins without this.
	NTPServer string `db:"ntp_server" json:"ntp_server,omitempty"`
}

// EffectiveSMTPPort returns the SMTP port, defaulting by TLS mode when unset.
func (s AppSettings) EffectiveSMTPPort() int {
	if s.SMTPPort > 0 {
		return s.SMTPPort
	}
	// Blank port → the standard port for the chosen encryption.
	switch s.SMTPTLSMode {
	case "ssl": // implicit TLS
		return 465
	case "none": // plaintext SMTP
		return 25
	default: // "starttls" (submission)
		return 587
	}
}

// SMTPConfigured reports whether enough SMTP settings exist to send mail.
func (s AppSettings) SMTPConfigured() bool {
	return s.SMTPHost != "" && s.SMTPFrom != ""
}

// EffectiveWebTimeout returns the web-tier timeout, falling back to the
// legacy global when the tier value is unset (0).
func (s AppSettings) EffectiveWebTimeout() int {
	if s.WebTimeout > 0 {
		return s.WebTimeout
	}
	if s.DefaultTimeout > 0 {
		return s.DefaultTimeout
	}
	return 30
}

// EffectiveWebMaxConcurrent returns the web-tier concurrency.
func (s AppSettings) EffectiveWebMaxConcurrent() int {
	if s.WebMaxConcurrent > 0 {
		return s.WebMaxConcurrent
	}
	if s.MaxConcurrent > 0 {
		return s.MaxConcurrent
	}
	return 30
}

// EffectiveWebRateLimit returns the web-tier rate limit (0 = unlimited).
func (s AppSettings) EffectiveWebRateLimit() int {
	if s.WebRateLimit > 0 {
		return s.WebRateLimit
	}
	return s.RateLimit
}

// EffectiveNetworkTimeout returns the network-tier host timeout.
func (s AppSettings) EffectiveNetworkTimeout() int {
	if s.NetworkTimeout > 0 {
		return s.NetworkTimeout
	}
	if s.DefaultTimeout > 0 {
		return s.DefaultTimeout
	}
	return 60
}

// EffectiveNetworkMaxConcurrent returns the network-tier concurrency.
func (s AppSettings) EffectiveNetworkMaxConcurrent() int {
	if s.NetworkMaxConcurrent > 0 {
		return s.NetworkMaxConcurrent
	}
	// network defaults are intentionally lower than web (nmap is heavier).
	if s.MaxConcurrent > 0 && s.MaxConcurrent <= 8 {
		return s.MaxConcurrent
	}
	return 4
}

// EffectiveNetworkRateLimit returns the nmap --max-rate value (0 = unlimited).
func (s AppSettings) EffectiveNetworkRateLimit() int {
	if s.NetworkRateLimit > 0 {
		return s.NetworkRateLimit
	}
	return 0
}

// EffectiveBruteThreads returns the brute-force tool's parallel-task count.
func (s AppSettings) EffectiveBruteThreads() int {
	if s.BruteThreads > 0 {
		return s.BruteThreads
	}
	return 16
}

// EffectiveMaxCPUPercent returns the CPU-budget percent (10..100) the capacity
// governor gives CPU-bound modules; 0/out-of-range → the built-in default (75).
func (s AppSettings) EffectiveMaxCPUPercent() int {
	if s.MaxCPUPercent >= 10 && s.MaxCPUPercent <= 100 {
		return s.MaxCPUPercent
	}
	return 75
}

// EffectiveVPNInterface returns the VPN device the watchdog monitors, defaulting
// to the conventional OpenVPN tun device when unset.
func (s AppSettings) EffectiveVPNInterface() string {
	if s.VPNInterface != "" {
		return s.VPNInterface
	}
	return "tun0"
}

// EffectiveVPNReconnectAfterSec returns the grace (seconds) the watchdog waits
// with the VPN down before firing a reconnect; clamped to a sane floor.
func (s AppSettings) EffectiveVPNReconnectAfterSec() int {
	if s.VPNReconnectAfterSec >= 5 {
		return s.VPNReconnectAfterSec
	}
	return 20
}

// DefaultSettings returns sane defaults
func DefaultSettings() AppSettings {
	return AppSettings{
		DefaultTimeout:       30,
		MaxConcurrent:        30,
		RateLimit:            0,
		WebTimeout:           30,
		WebMaxConcurrent:     30,
		WebRateLimit:         0,
		NetworkTimeout:       60,
		NetworkMaxConcurrent: 4,
		NetworkRateLimit:     0,
		BruteThreads:         16,
		MaxCPUPercent:        75,
		ProxyURL:             "",
		UseProxy:             false,
		UserAgent:            "scaNNer/1.0",
		DefaultExportFmt:     "csv",
		VPNAutoReconnect:         true, // watchdog on by default
		VPNReconnectAfterSec:     20,
		WebReachabilityPreflight: true, // skip TLS-dead targets by default
		WebPreflightTimeout:      4,
		SMTPTLSMode:              "starttls",
	}
}

// EffectiveWebPreflightTimeout returns the reachability-probe timeout in seconds
// (default 4 — a TLS reset returns in ~4s).
func (s AppSettings) EffectiveWebPreflightTimeout() int {
	if s.WebPreflightTimeout > 0 {
		return s.WebPreflightTimeout
	}
	return 4
}
