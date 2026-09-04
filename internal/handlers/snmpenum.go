package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"scanner/internal/models"
	"scanner/internal/modules/shared"
	"scanner/internal/modules/snmpenum"
)

type snmpEnumConfig struct {
	Targets         []string `json:"targets"`
	Communities     []string `json:"communities"`
	Walks           []string `json:"walks"`
	SkipBrute       bool     `json:"skip_brute"`
	ForcedCommunity string   `json:"forced_community,omitempty"`
	Concurrency     int      `json:"concurrency,omitempty"`
	// SNMPv3 USM (User-based Security Model). If V3User is non-empty
	// the scanner switches every snmpget/snmpwalk to v3 mode and skips
	// the v2c community brute.
	V3User      string `json:"v3_user,omitempty"`
	V3AuthPass  string `json:"v3_auth_pass,omitempty"`
	V3PrivPass  string `json:"v3_priv_pass,omitempty"`
	V3AuthProto string `json:"v3_auth_proto,omitempty"` // SHA | MD5
	V3PrivProto string `json:"v3_priv_proto,omitempty"` // AES | DES
	V3SecLevel  string `json:"v3_sec_level,omitempty"`  // noAuthNoPriv | authNoPriv | authPriv
}

func (h *Handler) SNMPEnumPage(w http.ResponseWriter, r *http.Request) {
	data := h.baseData(r, "SNMP Enum - scaNNer", "snmpenum")
	ws := data["ActiveWorkspace"].(*models.Workspace)
	scans, _ := h.db.ListScansLite(ws.ID, "snmpenum")
	data["Scans"] = scans
	targets, _ := h.db.ListTargets(ws.ID, "")
	data["WSTargets"] = targets
	data["WSTargetGroups"] = h.groupTargetsByList(ws.ID)
	// Audit fix (MEDIUM quality): expose the extended Branches map added
	// in scanner.go (arp/routes/ipaddrs/shares/win32-services/cdp) so the
	// pentester can actually enumerate the OIDs snmp-check reads.
	branches := []string{
		"system", "interfaces", "ipaddrs", "arp", "routes",
		"tcp", "udp", "processes", "software", "installed-services",
		"shares", "users", "win32-services", "cdp",
	}
	data["Branches"] = branches
	data["DefaultCommunities"] = strings.Join(snmpenum.DefaultCommunities, "\n")
	h.render(w, "layout", data)
}

func parseSNMPEnumForm(r *http.Request) snmpEnumConfig {
	cfg := snmpEnumConfig{}
	for _, t := range r.Form["targets"] {
		t = strings.TrimSpace(t)
		if t != "" {
			cfg.Targets = append(cfg.Targets, t)
		}
	}
	for _, line := range strings.Split(r.FormValue("manual_targets"), "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			cfg.Targets = append(cfg.Targets, line)
		}
	}
	for _, line := range strings.Split(r.FormValue("communities"), "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			cfg.Communities = append(cfg.Communities, line)
		}
	}
	cfg.Walks = r.Form["walks"]
	cfg.SkipBrute = r.FormValue("skip_brute") == "on"
	cfg.ForcedCommunity = strings.TrimSpace(r.FormValue("forced_community"))
	cfg.V3User = strings.TrimSpace(r.FormValue("v3_user"))
	cfg.V3AuthPass = r.FormValue("v3_auth_pass")
	cfg.V3PrivPass = r.FormValue("v3_priv_pass")
	cfg.V3AuthProto = strings.TrimSpace(r.FormValue("v3_auth_proto"))
	cfg.V3PrivProto = strings.TrimSpace(r.FormValue("v3_priv_proto"))
	cfg.V3SecLevel = strings.TrimSpace(r.FormValue("v3_sec_level"))
	// Audit fix (MEDIUM perf): expose the per-target fan-out concurrency
	// to the operator. Default 16 (applied in scanner.go when zero) is a
	// reasonable middle ground for UDP-bound enumeration; hard-cap at
	// 128 so a typo doesn't fork-bomb the host.
	if v, err := strconv.Atoi(strings.TrimSpace(r.FormValue("concurrency"))); err == nil && v >= 1 && v <= 128 {
		cfg.Concurrency = v
	}
	return cfg
}

func (h *Handler) SNMPEnumRun(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/modules/snmpenum", http.StatusSeeOther)
		return
	}
	r.ParseForm()
	ws := h.activeWorkspace(r)
	cfg := parseSNMPEnumForm(r)
	if len(cfg.Targets) == 0 {
		http.Redirect(w, r, "/modules/snmpenum?error=no_targets", http.StatusSeeOther)
		return
	}
	// Audit fix (MEDIUM quality): fail-closed when SNMPv3 is requested
	// with auth but no (or too-short) passphrase. Previously the empty
	// -A / -X passphrase flowed straight into snmpget/snmpwalk, which
	// silently returned nothing on every OID — the results page then
	// showed a host with the v3 label but no data and no error, giving
	// the impression the box was locked down when the scan was just
	// mis-configured.
	if cfg.V3User != "" {
		lvl := cfg.V3SecLevel
		if lvl == "" {
			lvl = "authPriv"
		}
		if lvl == "authNoPriv" || lvl == "authPriv" {
			if len(cfg.V3AuthPass) < 8 {
				http.Redirect(w, r, "/modules/snmpenum?error=v3_missing_auth", http.StatusSeeOther)
				return
			}
		}
		if lvl == "authPriv" {
			if len(cfg.V3PrivPass) < 8 {
				http.Redirect(w, r, "/modules/snmpenum?error=v3_missing_priv", http.StatusSeeOther)
				return
			}
		}
	}
	// Expand CIDR/range entries so each IP gets its own progress tick.
	cfg.Targets = shared.ExpandTargets(cfg.Targets, 1024)
	// Audit fix (HIGH): SNMPv3 passphrases used to be stored verbatim
	// in the scans.config DB column. Anyone with read access to
	// data/scanner.db could harvest USM credentials weeks later.
	// Persist a redacted copy; the in-memory cfg keeps the real values
	// for the running scan goroutine. Restart of a v3 scan now requires
	// the user to re-enter the passphrases.
	persistCfg := cfg
	if persistCfg.V3AuthPass != "" {
		persistCfg.V3AuthPass = "[REDACTED]"
	}
	if persistCfg.V3PrivPass != "" {
		persistCfg.V3PrivPass = "[REDACTED]"
	}
	cfgJSON, _ := json.Marshal(persistCfg)
	scan, err := h.db.CreateScan(ws.ID, "snmpenum", string(cfgJSON), len(cfg.Targets))
	if err != nil {
		http.Redirect(w, r, "/modules/snmpenum?error=db_error", http.StatusSeeOther)
		return
	}
	if h.queueIfSequential(w, r, scan) {
		return
	}
	go h.runSNMPEnum(scan.ID, cfg)
	http.Redirect(w, r, "/modules/snmpenum/results/"+scan.ID, http.StatusSeeOther)
}

func (h *Handler) SNMPEnumResults(w http.ResponseWriter, r *http.Request) {
	scanID := strings.TrimPrefix(r.URL.Path, "/modules/snmpenum/results/")
	scan, err := h.db.GetScan(scanID)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	data := h.baseData(r, "SNMP Enum Results - scaNNer", "snmpenum_results")
	var result snmpenum.ScanResult
	json.Unmarshal([]byte(scan.Result), &result)
	openHosts, totalCommunities := 0, 0
	for _, tr := range result.Results {
		if len(tr.ValidCommunities) > 0 {
			openHosts++
		}
		totalCommunities += len(tr.ValidCommunities)
	}
	data["Scan"] = scan
	data["Results"] = result.Results
	data["Warnings"] = result.Warnings
	data["OpenHosts"] = openHosts
	data["TotalCommunities"] = totalCommunities
	h.renderResults(w, r, "snmpenum_results_inner", data)
}

func (h *Handler) SNMPEnumStatus(w http.ResponseWriter, r *http.Request) {
	scanID := strings.TrimPrefix(r.URL.Path, "/modules/snmpenum/status/")
	scan, err := h.db.GetScan(scanID)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	h.writeScanStatus(w, scan)
}

func (h *Handler) runSNMPEnum(scanID string, cfg snmpEnumConfig) {
	if !h.db.MarkRunning(scanID) {
		return
	}
	ctx := h.scanMgr.Register(scanID)
	defer h.FinishScan(scanID)
	scanCfg := snmpenum.Config{
		Targets:         cfg.Targets,
		Communities:     cfg.Communities,
		Walks:           cfg.Walks,
		SkipBrute:       cfg.SkipBrute,
		ForcedCommunity: cfg.ForcedCommunity,
		Concurrency:     cfg.Concurrency,
		V3User:          cfg.V3User,
		V3AuthPass:      cfg.V3AuthPass,
		V3PrivPass:      cfg.V3PrivPass,
		V3AuthProto:     cfg.V3AuthProto,
		V3PrivProto:     cfg.V3PrivProto,
		V3SecLevel:      cfg.V3SecLevel,
	}

	var latest []byte
	var mu sync.Mutex
	doneCh := make(chan struct{})
	defer close(doneCh) // audit B20: panic-safe ticker shutdown
	go func() {
		t := time.NewTicker(2 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-doneCh:
				return
			case <-t.C:
				mu.Lock()
				b := latest
				mu.Unlock()
				if b != nil {
					h.db.UpdateScanResult(scanID, string(b))
				}
			}
		}
	}()

	result := snmpenum.Scan(ctx, scanCfg,
		func(done int, msg string) { h.db.UpdateScanProgress(scanID, done, msg) },
		func(p *snmpenum.ScanResult) {
			b, err := json.Marshal(p)
			if err == nil {
				mu.Lock()
				latest = b
				mu.Unlock()
			}
		})
	resJSON, _ := json.Marshal(result)
	h.db.UpdateScanResult(scanID, string(resJSON))

	// Hard-failure surfacing: if every unit errored, mark the scan failed
	// with a translated reason rather than a silent "done" with zero findings.
	if ctx.Err() == nil {
		var errs []string
		for _, tr := range result.Results {
			if tr.Error != "" {
				errs = append(errs, tr.Error)
			}
		}
		h.markHardFailure(scanID, errs, len(cfg.Targets))
	}
}
