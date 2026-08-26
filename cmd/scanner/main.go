package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	_ "net/http/pprof" // handlers register on DefaultServeMux; gated at the mux wrap below
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"scanner/internal/capacity"
	"scanner/internal/certs"
	"scanner/internal/database"
	"scanner/internal/handlers"
	"scanner/internal/modules"
	"scanner/internal/modules/shared"
	scannet "scanner/internal/network"
	"scanner/internal/sysmon"
	"scanner/internal/modules/adpentest"
	"scanner/internal/modules/advancedweb"
	"scanner/internal/modules/assetdisc"
	"scanner/internal/modules/authtest"
	"scanner/internal/modules/brutef"
	"scanner/internal/modules/cachepoison"
	"scanner/internal/modules/concurtest"
	"scanner/internal/modules/corsscan"
	"scanner/internal/modules/cvematch"
	"scanner/internal/modules/direnum"
	"scanner/internal/modules/dnsenum"
	"scanner/internal/modules/emailharvest"
	"scanner/internal/modules/graphqlscan"
	"scanner/internal/modules/hostdiscovery"
	"scanner/internal/modules/httpmethods"
	"scanner/internal/modules/httpxfind"
	"scanner/internal/modules/jwt"
	"scanner/internal/modules/leakscan"
	"scanner/internal/modules/nuclei"
	"scanner/internal/modules/oob"
	"scanner/internal/modules/openredirect"
	"scanner/internal/modules/paramdisc"
	"scanner/internal/modules/portservice"
	"scanner/internal/modules/secheaders"
	"scanner/internal/modules/smbenum"
	"scanner/internal/modules/snmpenum"
	"scanner/internal/modules/spider"
	"scanner/internal/modules/sslscan"
	"scanner/internal/modules/sstiscan"
	"scanner/internal/modules/takeover"
	"scanner/internal/modules/techdetect"
	"scanner/internal/modules/wafdetect"
	"scanner/internal/modules/whoisinfo"
	"scanner/internal/modules/wpscan"
)

func main() {
	// Lightweight smoke-test hook used by the self-update flow: a freshly-built
	// binary is run as `scanner -version` to confirm it executes (package inits
	// have already run by the time we reach here) before it replaces the running
	// one. Exits immediately without opening the DB or binding the port.
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "-version", "--version", "-check":
			fmt.Println("scaNNer")
			return
		}
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "9090"
	}

	dataDir := os.Getenv("DATA_DIR")
	if dataDir == "" {
		dataDir = "data"
	}
	os.MkdirAll(dataDir, 0755)

	// External tool PATH validation (audit B78). The scanner shells out
	// to nmap, nuclei, wpscan, hydra, smbclient, whatweb, snmpwalk,
	// theHarvester, dig, subfinder, amass, puredns, masscan. If any of
	// these is missing the corresponding module silently fails — the
	// scan completes with empty results but no clear error in the UI.
	// Surface a startup banner listing what's missing so the operator
	// knows what to install BEFORE wasting a 2-hour scan.
	tools := []string{
		"nmap", "nuclei", "wpscan", "hydra", "smbclient",
		"whatweb", "snmpwalk", "snmpset", "theHarvester", "dig",
		"subfinder", "amass", "puredns", "masscan",
		"enum4linux", "onesixtyone", "whois",
		"sslscan", "openssl", // SSL/TLS Scanner's tool-driven engine
	}
	missing := []string{}
	for _, t := range tools {
		if _, err := exec.LookPath(t); err != nil {
			missing = append(missing, t)
		}
	}
	if len(missing) > 0 {
		log.Printf("⚠ External tools missing from $PATH (corresponding modules will silently fail): %s",
			strings.Join(missing, ", "))
	}

	// Network-tuning status: surface the ephemeral-port budget + fin_timeout the
	// capacity governor works within, and nudge toward scripts/install.sh when
	// the stack is at stock (small port range / slow recycle) — the "network
	// fills up under load" footgun.
	if lim := sysmon.ReadLimits(); lim.UsablePorts() > 0 {
		tuned := lim.UsablePorts() >= 50000 && lim.FinTimeout <= 30
		status := "stock (run scripts/install.sh to widen the port budget)"
		if tuned {
			status = "tuned"
		}
		log.Printf("Network tuning: %d ephemeral ports, tcp_fin_timeout=%ds, %d cores, nofile=%d — %s",
			lim.UsablePorts(), lim.FinTimeout, lim.Cores, lim.NoFile, status)
	}

	// Startup /tmp sweep (audit B19). Crashed prior scans may have left
	// orphaned temp files behind — scanner-brute-*, harvest-*.json,
	// nuclei-urls-*.txt etc. Without this housekeeping, /tmp gradually
	// fills until the OS-side cleanup kicks in (often days). Best
	// effort: silently ignore filesystem errors.
	tmpDir := os.TempDir()
	if entries, err := os.ReadDir(tmpDir); err == nil {
		sweepPrefixes := []string{
			"scanner-brute-", "scanner-users-", "scanner-pass-",
			"harvest-", "nuclei-urls-", "dnsenum-",
		}
		swept := 0
		for _, e := range entries {
			n := e.Name()
			for _, p := range sweepPrefixes {
				if strings.HasPrefix(n, p) {
					if err := os.RemoveAll(tmpDir + "/" + n); err == nil {
						swept++
					}
					break
				}
			}
		}
		if swept > 0 {
			log.Printf("Startup /tmp sweep: removed %d orphaned scanner temp file(s)", swept)
		}
	}

	// Initialize database
	db, err := database.New(dataDir + "/scanner.db")
	if err != nil {
		log.Fatal("Failed to open database: ", err)
	}
	defer db.Close()

	// Sweep any scans left in running/pending status from a previous server
	// process — those goroutines are gone, so the rows would otherwise stay
	// "running" forever. Marking them as `error` makes them visible to the
	// user (and Restart-able) instead of being silently stuck.
	if n, err := db.MarkOrphanedScans(); err == nil && n > 0 {
		log.Printf("Marked %d orphaned scan(s) as error (left running by previous instance)", n)
	}

	// Backfill denormalized dashboard counts (severity_count,
	// open_connections_count) for any rows that pre-date the columns or
	// were never re-written by a UpdateScanResult call after upgrade.
	// Runs in a goroutine so a multi-GB legacy database doesn't delay
	// the server's TCP listener — the dashboard will simply show zeros
	// for un-backfilled rows until the goroutine catches up.
	go func() {
		t0 := time.Now()
		if n, err := db.BackfillScanStats(); err != nil {
			log.Printf("Scan stats backfill: %v", err)
		} else if n > 0 {
			log.Printf("Scan stats backfill: %d row(s) recomputed in %s", n, time.Since(t0).Truncate(time.Millisecond))
		}
	}()

	// Initialize module registry
	registry := modules.NewRegistry()
	registry.Register(&sslscan.Module{})
	registry.Register(&httpxfind.Module{})
	registry.Register(&httpmethods.Module{})
	registry.Register(&wafdetect.Module{})
	registry.Register(&wpscan.Module{})
	registry.Register(&dnsenum.Module{})
	registry.Register(&techdetect.Module{})
	registry.Register(&spider.Module{})
	registry.Register(&direnum.Module{})
	registry.Register(&secheaders.Module{})
	registry.Register(&nuclei.Module{})
	registry.Register(&hostdiscovery.Module{})
	registry.Register(&portservice.Module{})
	registry.Register(&smbenum.Module{})
	registry.Register(&adpentest.Module{})
	registry.Register(&brutef.Module{})
	registry.Register(&whoisinfo.Module{})
	registry.Register(&emailharvest.Module{})
	registry.Register(&leakscan.Module{})
	registry.Register(&snmpenum.Module{})
	registry.Register(&jwt.Module{})
	registry.Register(&paramdisc.Module{})
	registry.Register(&concurtest.Module{})
	registry.Register(&advancedweb.Module{})
	// A-group (pentest expansion)
	registry.Register(&takeover.Module{})
	registry.Register(&corsscan.Module{})
	registry.Register(&openredirect.Module{})
	registry.Register(&cvematch.Module{})
	registry.Register(&graphqlscan.Module{})
	registry.Register(&authtest.Module{})
	registry.Register(&assetdisc.Module{})
	registry.Register(&oob.Module{})
	registry.Register(&sstiscan.Module{})
	registry.Register(&cachepoison.Module{})

	// Initialize handlers
	h, err := handlers.New(registry, db, "web/templates")
	if err != nil {
		log.Fatal("Failed to load templates: ", err)
	}

	// First-run bootstrap: create the initial admin with a random password,
	// printed once here. The account must change its password on first login.
	if username, password, created, err := h.EnsureAdminUser(); err != nil {
		log.Fatal("Failed to bootstrap admin user: ", err)
	} else if created {
		log.Printf("╔══════════════════════════════════════════════════════════════╗")
		log.Printf("║  INITIAL ADMIN ACCOUNT CREATED — SAVE THIS PASSWORD NOW        ║")
		log.Printf("║  It is shown ONLY this once and cannot be recovered.          ║")
		log.Printf("║                                                                ║")
		log.Printf("║    username: %-49s ║", username)
		log.Printf("║    password: %-49s ║", password)
		log.Printf("║                                                                ║")
		log.Printf("║  You will be required to change it on first login.            ║")
		log.Printf("╚══════════════════════════════════════════════════════════════╝")
	}

	// Daily NVD auto-refresh background loop (audit B71). Kicks off
	// only when the cache is >7 days old; respects the same lock as
	// the manual refresh button so it never preempts an operator-
	// triggered sync.
	h.StartCVEAutoRefresh()

	// Connectivity monitor (Task 0b/0c): pauses running scans on internet loss
	// (preserving partial results) and auto-resumes them when it's back. Also
	// resumes any scans left 'paused' from a prior process — in a goroutine so
	// the reachability probe never blocks the server from listening.
	h.StartConnectivityMonitor()

	// Reclaim expired/abandoned session rows on an hourly sweep (lazy deletion
	// only happens when an expired cookie is re-presented).
	h.StartSessionJanitor()
	go func() {
		if n := h.ResumePausedOnStartup(); n > 0 {
			log.Printf("startup: resumed %d paused scan(s) from a prior run", n)
		}
	}()

	// Sequential-scan scheduler: dispatches scans the operator queued with
	// "start after the current scan finishes" (name="run_sequential"), FIFO,
	// one per workspace, as each workspace goes idle. Queued rows survive the
	// orphan sweep, so a queue outlives a restart.
	h.StartScanQueue()

	// Load any calibrated per-module resource profiles (written by prior
	// calibration runs) over the embedded seed, so capacity.Recommend uses the
	// measured coefficients.
	handlers.LoadPersistedProfiles()
	// Apply the operator's CPU budget (% of cores) to the capacity governor so
	// CPU-bound modules (techdetect/whatweb) are sized to it.
	capacity.SetCPUBudget(float64(db.GetSettings().EffectiveMaxCPUPercent()) / 100)

	// Live performance monitor: samples OS resource pressure (ephemeral ports,
	// socket states, load, CPU) correlated with scan throughput into a ring
	// buffer the dashboard polls. Powers the "Live Network & Performance" panel.
	h.StartPerfMonitor()

	// Re-arm the outbound-binding killswitch at startup if the user had
	// previously pinned an interface. The killswitch has two layers:
	//
	//   1. Network namespace (subprocess isolation) — built via
	//      scannet.Setup(). iptables FORWARD chain drops any namespace
	//      egress that doesn't go through the chosen interface.
	//   2. Go HTTP source-IP binding (defense in depth) — installed via
	//      shared.SetGlobalLocalAddr() so every Go-side dialer in the
	//      scanner pipeline also binds to the iface's primary IPv4.
	//
	// If the privilege check fails (no CAP_NET_ADMIN, not root), we log
	// a warning and fall through to default routing. Settings retain
	// the pinned iface so a fix + restart re-engages without re-saving.
	if s := db.GetSettings(); s.NetworkInterface != "" {
		if err := scannet.RequiresPrivilege(); err != nil {
			log.Printf("⚠ Killswitch unavailable: %v — falling back to default routing", err)
		} else if err := scannet.Setup(s.NetworkInterface); err != nil {
			log.Printf("⚠ Killswitch setup failed: %v — falling back to default routing", err)
		} else {
			// Belt-and-braces Go-side binding.
			if ip := net.ParseIP(s.NetworkInterfaceIP); ip != nil {
				shared.SetGlobalLocalAddr(&net.TCPAddr{IP: ip})
			}
			scannet.StartMonitor(
				s.NetworkInterface,
				s.NetworkInterfaceIP,
				h.ScanMgr().CancelAll,
				db.MarkScanError,
			)
			log.Printf("Killswitch armed: scanner-ns ↔ %s (%s)", s.NetworkInterface, s.NetworkInterfaceIP)
		}
	} else {
		log.Printf("Outbound binding: default routing (killswitch disabled)")
	}

	// Tear down the namespace cleanly on graceful shutdown. The existing
	// signal handler below cancels in-flight HTTP via srv.Shutdown; we
	// piggy-back on it for netns cleanup so we don't orphan rules/links.
	defer func() {
		if scannet.IsActive() {
			if err := scannet.Teardown(); err != nil {
				log.Printf("Killswitch teardown: %v", err)
			} else {
				log.Println("Killswitch torn down (namespace removed)")
			}
		}
	}()

	// Seed built-in curated CVE list into the SQLite cve_records table.
	// Built-ins live under source='builtin' so a "Clear NVD" / "Clear OSV"
	// re-sync doesn't wipe them. Idempotent: re-running on each startup
	// upserts the same set with their version-range tuples.
	{
		seedFn := func(cveID, source, productKey, productName, lo, hi string,
			loInc, hiInc bool, fixedIn, severity string, cvss float64,
			description, remediation, reference string, pub, mod time.Time) error {
			return db.CVEUpsert(cveID, source, productKey, productName, lo, hi,
				loInc, hiInc, fixedIn, severity, cvss, description, remediation, reference, pub, mod)
		}
		if n, err := cvematch.SeedBuiltin(seedFn); err != nil {
			log.Printf("CVE builtin seed failed: %v", err)
		} else if n > 0 {
			log.Printf("CVE builtin seed: %d curated records upserted", n)
		}
	}

	// Static files
	fs := http.FileServer(http.Dir("web/static"))
	http.Handle("/static/", http.StripPrefix("/static/", fs))
	// Serve the browser's automatic /favicon.ico probe (the templates also link
	// the SVG/PNG icons explicitly; this covers the bare request + old tabs).
	http.HandleFunc("/favicon.ico", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "web/static/favicon.ico")
	})

	// Gated pprof exposure. The `net/http/pprof` blank import's init()
	// auto-registers /debug/pprof/{,heap,profile,...} on DefaultServeMux,
	// which is the SAME mux we register our own routes on. We can't
	// "unregister" them, and re-registering panics. The gate is a thin
	// middleware applied to the mux below — when SCANNER_PPROF is not
	// set, any /debug/pprof request short-circuits to NotFound.
	pprofEnabled := os.Getenv("SCANNER_PPROF") == "1"
	if pprofEnabled {
		log.Printf("pprof enabled at /debug/pprof/ (SCANNER_PPROF=1)")
	}

	// Page routes
	http.HandleFunc("/", h.Dashboard)
	http.HandleFunc("/dashboard/charts.json", h.DashboardChartsAPI)
	http.HandleFunc("/api/health", h.Health)
	http.HandleFunc("/monitor/metrics.json", h.MonitorMetrics)
	http.HandleFunc("/monitor/calibrate", h.CalibrateStart)
	http.HandleFunc("/monitor/calibrate/status", h.CalibrateStatus)

	// CVE Database management — used by the Settings page to drive NVD
	// feed refresh and surface cache stats.
	http.HandleFunc("/settings/cvedb/refresh", h.CVEDBRefresh)
	http.HandleFunc("/settings/cvedb/status", h.CVEDBStatus)
	http.HandleFunc("/settings/network-tune", h.SettingsNetworkTune)
	http.HandleFunc("/settings/cvedb/cancel", h.CVEDBCancel)
	http.HandleFunc("/targets", h.Targets)
	http.HandleFunc("/modules", h.Modules)
	http.HandleFunc("/scans", h.Scans)
	http.HandleFunc("/settings", h.Settings)
	http.HandleFunc("/settings/save", h.SettingsSave)
	http.HandleFunc("/settings/vacuum", h.SettingsVacuum)
	http.HandleFunc("/settings/api", h.SettingsAPI)
	http.HandleFunc("/settings/smtp-test", h.SMTPTest)

	// Authentication / account (login, 2FA, logout, self-service account).
	http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			h.LoginSubmit(w, r)
		} else {
			h.LoginPage(w, r)
		}
	})
	http.HandleFunc("/login/2fa", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			h.TwoFactorSubmit(w, r)
		} else {
			h.TwoFactorPage(w, r)
		}
	})
	http.HandleFunc("/logout", h.Logout)
	http.HandleFunc("/account", h.AccountPage)
	http.HandleFunc("/account/password", h.AccountPassword)
	http.HandleFunc("/account/2fa", h.AccountEnroll2FA)

	// Admin: user management + permissions + audit logs (admin-gated by the
	// auth middleware).
	http.HandleFunc("/users", h.UsersPage)
	http.HandleFunc("/users/create", h.UserCreate)
	http.HandleFunc("/users/edit", h.UserEdit)
	http.HandleFunc("/users/delete", h.UserDelete)
	http.HandleFunc("/users/reset-password", h.UserResetPassword)
	http.HandleFunc("/users/reset-2fa", h.UserResetTwoFactor)
	http.HandleFunc("/users/permissions", h.UserPermissions)
	http.HandleFunc("/logs", h.LogsPage)

	// Software self-update (admin-gated by the auth middleware).
	http.HandleFunc("/update", h.UpdatePage)
	http.HandleFunc("/update/check", h.UpdateCheck)
	http.HandleFunc("/update/apply", h.UpdateApply)

	// Workspace actions
	http.HandleFunc("/workspace/switch", h.SwitchWorkspace)
	http.HandleFunc("/workspace/create", h.WorkspaceCreate)
	http.HandleFunc("/workspace/delete", h.WorkspaceDelete)
	http.HandleFunc("/workspace/reset", h.WorkspaceReset)

	// Target actions
	http.HandleFunc("/targets/add", h.TargetAdd)
	http.HandleFunc("/targets/bulk", h.TargetBulkAdd)
	http.HandleFunc("/targets/delete", h.TargetDelete)
	http.HandleFunc("/targets/lists/create", h.TargetListCreate)
	http.HandleFunc("/targets/lists/delete", h.TargetListDelete)
	http.HandleFunc("/targets/export", h.TargetListExport)
	http.HandleFunc("/targets/lists/add", h.TargetListAddTargets)
	http.HandleFunc("/targets/categories", h.TargetSetCategories)

	// Assets
	http.HandleFunc("/assets", h.Assets)
	http.HandleFunc("/vulnerabilities", h.Vulnerabilities)
	http.HandleFunc("/vulnerabilities/export", h.VulnExport)
	http.HandleFunc("/vulnerabilities/detail", h.VulnDetail)
	http.HandleFunc("/vulnerabilities/rescan", h.VulnRescan)
	http.HandleFunc("/vulnerabilities/archive", h.VulnArchiveToggle)
	// /assets/lists/* and /assets/membership routes were removed when
	// the user-curated asset-lists feature was retired.
	http.HandleFunc("/assets/", h.AssetDetail)

	// SSL/TLS Scanner
	http.HandleFunc("/modules/sslscan", h.SSLScanPage)
	http.HandleFunc("/modules/sslscan/run", h.SSLScanRun)
	http.HandleFunc("/modules/sslscan/results/", h.SSLScanResults)
	http.HandleFunc("/modules/sslscan/status/", h.SSLScanStatus)

	// HTTPX Finder
	http.HandleFunc("/modules/httpxfind", h.HTTPXFindPage)
	http.HandleFunc("/modules/httpxfind/run", h.HTTPXFindRun)
	http.HandleFunc("/modules/httpxfind/results/", h.HTTPXFindResults)
	http.HandleFunc("/modules/httpxfind/status/", h.HTTPXFindStatus)

	// HTTP Method Tester
	http.HandleFunc("/modules/httpmethods", h.HTTPMethodsPage)
	http.HandleFunc("/modules/httpmethods/run", h.HTTPMethodsRun)
	http.HandleFunc("/modules/httpmethods/results/", h.HTTPMethodsResults)
	http.HandleFunc("/modules/httpmethods/status/", h.HTTPMethodsStatus)

	// Universal export
	http.HandleFunc("/export/sections/", h.ExportSectionsAPI)
	http.HandleFunc("/export/", h.ExportScan)

	// Send-to-Burp on-demand replay (per-finding action). The user
	// clicks a button on a result row; we POST through the configured
	// proxy so the request appears in Burp's history.
	http.HandleFunc("/scans/send-to-burp", h.SendToBurp)

	// Scan control (stop / restart / delete / archive)
	http.HandleFunc("/scans/stop/", h.ScanStop)
	http.HandleFunc("/scans/resume/", h.ScanResume)
	http.HandleFunc("/scans/restart/", h.ScanRestart)
	http.HandleFunc("/scans/delete/", h.ScanDelete)
	http.HandleFunc("/scans/archive/", h.ScanArchive)
	http.HandleFunc("/scans/archive", h.ScansArchive)

	// WAF Detector
	http.HandleFunc("/modules/wafdetect", h.WAFDetectPage)
	http.HandleFunc("/modules/wafdetect/run", h.WAFDetectRun)
	http.HandleFunc("/modules/wafdetect/results/", h.WAFDetectResults)
	http.HandleFunc("/modules/wafdetect/status/", h.WAFDetectStatus)

	// DNS Enumerator
	http.HandleFunc("/modules/dnsenum", h.DNSEnumPage)
	http.HandleFunc("/modules/dnsenum/run", h.DNSEnumRun)
	http.HandleFunc("/modules/dnsenum/results/", h.DNSEnumResults)
	http.HandleFunc("/modules/dnsenum/status/", h.DNSEnumStatus)
	http.HandleFunc("/modules/dnsenum/import/", h.DNSEnumImportTargets)

	// Security Headers
	http.HandleFunc("/modules/secheaders", h.SecHeadersPage)
	http.HandleFunc("/modules/secheaders/run", h.SecHeadersRun)
	http.HandleFunc("/modules/secheaders/results/", h.SecHeadersResults)
	http.HandleFunc("/modules/secheaders/status/", h.SecHeadersStatus)

	// Directory Enumerator
	http.HandleFunc("/modules/direnum", h.DirEnumPage)
	http.HandleFunc("/modules/direnum/run", h.DirEnumRun)
	http.HandleFunc("/modules/direnum/results/", h.DirEnumResults)
	http.HandleFunc("/modules/direnum/status/", h.DirEnumStatus)
	http.HandleFunc("/modules/direnum/skip/", h.DirEnumSkip)
	http.HandleFunc("/modules/direnum/skipped/", h.DirEnumSkippedList)

	// Concurrency Tester
	http.HandleFunc("/modules/concurtest", h.ConcurTestPage)
	http.HandleFunc("/modules/concurtest/run", h.ConcurTestRun)
	http.HandleFunc("/modules/concurtest/results/", h.ConcurTestResults)
	http.HandleFunc("/modules/concurtest/status/", h.ConcurTestStatus)

	// Advanced Web Application Scanner Suite — register both the
	// hyphenated URL (used by modules.html and human-friendly links)
	// and the slug-matching URL (used by scan_progress.html's JS,
	// which builds /modules/{{.Scan.Module}}/status/<id> against the
	// raw module name `advancedweb`).
	http.HandleFunc("/modules/advanced-web", h.AdvancedWebPage)
	http.HandleFunc("/modules/advanced-web/run", h.AdvancedWebRun)
	http.HandleFunc("/modules/advanced-web/results/", h.AdvancedWebResults)
	http.HandleFunc("/modules/advanced-web/status/", h.AdvancedWebStatus)
	http.HandleFunc("/modules/advancedweb", h.AdvancedWebPage)
	http.HandleFunc("/modules/advancedweb/run", h.AdvancedWebRun)
	http.HandleFunc("/modules/advancedweb/results/", h.AdvancedWebResults)
	http.HandleFunc("/modules/advancedweb/status/", h.AdvancedWebStatus)

	// Web Spider
	http.HandleFunc("/modules/spider", h.SpiderPage)
	http.HandleFunc("/modules/spider/run", h.SpiderRun)
	http.HandleFunc("/modules/spider/results/", h.SpiderResults)
	http.HandleFunc("/modules/spider/status/", h.SpiderStatus)

	// Tech Detector
	http.HandleFunc("/modules/techdetect", h.TechDetectPage)
	http.HandleFunc("/modules/techdetect/run", h.TechDetectRun)
	http.HandleFunc("/modules/techdetect/results/", h.TechDetectResults)
	http.HandleFunc("/modules/techdetect/status/", h.TechDetectStatus)

	// WPScan
	http.HandleFunc("/modules/wpscan", h.WPScanPage)
	http.HandleFunc("/modules/wpscan/run", h.WPScanRun)
	http.HandleFunc("/modules/wpscan/results/", h.WPScanResults)
	http.HandleFunc("/modules/wpscan/status/", h.WPScanStatus)

	// Nuclei
	http.HandleFunc("/modules/nuclei", h.NucleiPage)
	http.HandleFunc("/modules/nuclei/run", h.NucleiRun)
	http.HandleFunc("/modules/nuclei/results/", h.NucleiResults)
	http.HandleFunc("/modules/nuclei/status/", h.NucleiStatus)

	// Host Discovery
	http.HandleFunc("/modules/hostdiscovery", h.HostDiscoveryPage)
	http.HandleFunc("/modules/hostdiscovery/run", h.HostDiscoveryRun)
	http.HandleFunc("/modules/hostdiscovery/results/", h.HostDiscoveryResults)
	http.HandleFunc("/modules/hostdiscovery/status/", h.HostDiscoveryStatus)

	// Port + Service Scanner
	http.HandleFunc("/modules/portservice", h.PortServicePage)
	http.HandleFunc("/modules/portservice/run", h.PortServiceRun)
	http.HandleFunc("/modules/portservice/results/", h.PortServiceResults)
	http.HandleFunc("/modules/portservice/status/", h.PortServiceStatus)

	// SMB Enum
	http.HandleFunc("/modules/smbenum", h.SMBEnumPage)
	http.HandleFunc("/modules/smbenum/run", h.SMBEnumRun)
	http.HandleFunc("/modules/smbenum/results/", h.SMBEnumResults)
	http.HandleFunc("/modules/smbenum/status/", h.SMBEnumStatus)
	http.HandleFunc("/modules/adpentest", h.AdpentestPage)
	http.HandleFunc("/modules/adpentest/run", h.AdpentestRun)
	http.HandleFunc("/modules/adpentest/results/", h.AdpentestResults)
	http.HandleFunc("/modules/adpentest/status/", h.AdpentestStatus)

	// Service Brute Forcer (SSH/FTP/RDP)
	http.HandleFunc("/modules/brutef", h.BruteFPage)
	http.HandleFunc("/modules/brutef/run", h.BruteFRun)
	http.HandleFunc("/modules/brutef/results/", h.BruteFResults)
	http.HandleFunc("/modules/brutef/status/", h.BruteFStatus)

	// WHOIS / ASN Lookup
	http.HandleFunc("/modules/whoisinfo", h.WhoisInfoPage)
	http.HandleFunc("/modules/whoisinfo/run", h.WhoisInfoRun)
	http.HandleFunc("/modules/whoisinfo/results/", h.WhoisInfoResults)
	http.HandleFunc("/modules/whoisinfo/status/", h.WhoisInfoStatus)

	// Email Harvester
	http.HandleFunc("/modules/emailharvest", h.EmailHarvestPage)
	http.HandleFunc("/modules/emailharvest/run", h.EmailHarvestRun)
	http.HandleFunc("/modules/emailharvest/results/", h.EmailHarvestResults)
	http.HandleFunc("/modules/emailharvest/status/", h.EmailHarvestStatus)

	// GitHub Leak Scanner
	http.HandleFunc("/modules/leakscan", h.LeakScanPage)
	http.HandleFunc("/modules/leakscan/run", h.LeakScanRun)
	http.HandleFunc("/modules/leakscan/results/", h.LeakScanResults)
	http.HandleFunc("/modules/leakscan/status/", h.LeakScanStatus)

	// SNMP Enum
	http.HandleFunc("/modules/snmpenum", h.SNMPEnumPage)
	http.HandleFunc("/modules/snmpenum/run", h.SNMPEnumRun)
	http.HandleFunc("/modules/snmpenum/results/", h.SNMPEnumResults)
	http.HandleFunc("/modules/snmpenum/status/", h.SNMPEnumStatus)

	// JWT Analyzer
	http.HandleFunc("/modules/jwt", h.JWTPage)
	http.HandleFunc("/modules/jwt/run", h.JWTRun)
	http.HandleFunc("/modules/jwt/results/", h.JWTResults)
	http.HandleFunc("/modules/jwt/status/", h.JWTStatus)

	// Parameter Discovery
	http.HandleFunc("/modules/paramdisc", h.ParamDiscPage)
	http.HandleFunc("/modules/paramdisc/run", h.ParamDiscRun)
	http.HandleFunc("/modules/paramdisc/results/", h.ParamDiscResults)
	http.HandleFunc("/modules/paramdisc/status/", h.ParamDiscStatus)

	// === A-group (pentest expansion) =====================================

	// A1: Subdomain Takeover
	http.HandleFunc("/modules/takeover", h.TakeoverPage)
	http.HandleFunc("/modules/takeover/run", h.TakeoverRun)
	http.HandleFunc("/modules/takeover/results/", h.TakeoverResults)
	http.HandleFunc("/modules/takeover/status/", h.TakeoverStatus)

	// A2: CORS Misconfig
	http.HandleFunc("/modules/corsscan", h.CORSScanPage)
	http.HandleFunc("/modules/corsscan/run", h.CORSScanRun)
	http.HandleFunc("/modules/corsscan/results/", h.CORSScanResults)
	http.HandleFunc("/modules/corsscan/status/", h.CORSScanStatus)

	// A3: Open Redirect
	http.HandleFunc("/modules/openredirect", h.OpenRedirectPage)
	http.HandleFunc("/modules/openredirect/run", h.OpenRedirectRun)
	http.HandleFunc("/modules/openredirect/results/", h.OpenRedirectResults)
	http.HandleFunc("/modules/openredirect/status/", h.OpenRedirectStatus)

	// A4: CVE Matcher
	http.HandleFunc("/modules/cvematch", h.CVEMatchPage)
	http.HandleFunc("/modules/cvematch/run", h.CVEMatchRun)
	http.HandleFunc("/modules/cvematch/results/", h.CVEMatchResults)
	http.HandleFunc("/modules/cvematch/status/", h.CVEMatchStatus)

	// A5: GraphQL Scanner
	http.HandleFunc("/modules/graphqlscan", h.GraphQLScanPage)
	http.HandleFunc("/modules/graphqlscan/run", h.GraphQLScanRun)
	http.HandleFunc("/modules/graphqlscan/results/", h.GraphQLScanResults)
	http.HandleFunc("/modules/graphqlscan/status/", h.GraphQLScanStatus)

	// A7: Auth Tester
	http.HandleFunc("/modules/authtest", h.AuthTestPage)
	http.HandleFunc("/modules/authtest/run", h.AuthTestRun)
	http.HandleFunc("/modules/authtest/results/", h.AuthTestResults)
	http.HandleFunc("/modules/authtest/status/", h.AuthTestStatus)

	// A8: Asset Discovery (Shodan/Censys)
	http.HandleFunc("/modules/assetdisc", h.AssetDiscPage)
	http.HandleFunc("/modules/assetdisc/run", h.AssetDiscRun)
	http.HandleFunc("/modules/assetdisc/results/", h.AssetDiscResults)
	http.HandleFunc("/modules/assetdisc/status/", h.AssetDiscStatus)
	http.HandleFunc("/modules/assetdisc/promote", h.AssetDiscPromote)

	// A9: OOB Collaborator
	http.HandleFunc("/modules/oob", h.OOBPage)
	http.HandleFunc("/modules/oob/run", h.OOBRun)
	http.HandleFunc("/modules/oob/results/", h.OOBResults)
	http.HandleFunc("/modules/oob/status/", h.OOBStatus)
	http.HandleFunc("/modules/oob/stop/", h.OOBStop)

	// A10: SSTI Probe
	http.HandleFunc("/modules/sstiscan", h.SSTIScanPage)
	http.HandleFunc("/modules/sstiscan/run", h.SSTIScanRun)
	http.HandleFunc("/modules/sstiscan/results/", h.SSTIScanResults)
	http.HandleFunc("/modules/sstiscan/status/", h.SSTIScanStatus)

	// A11: Cache Poisoning + HTTP Smuggling
	http.HandleFunc("/modules/cachepoison", h.CachePoisonPage)
	http.HandleFunc("/modules/cachepoison/run", h.CachePoisonRun)
	http.HandleFunc("/modules/cachepoison/results/", h.CachePoisonResults)
	http.HandleFunc("/modules/cachepoison/status/", h.CachePoisonStatus)

	// HTTP server timeouts (audit B50). Without these, a single slowloris-
	// style client holding a connection open with trickle bytes pins a
	// goroutine + FD forever. Over 2 days of running, even non-malicious
	// stalled connections (NAT hiccup, browser tab left on a long-poll)
	// accumulate and exhaust the process. Numbers are generous enough for
	// real workloads (export of large scan, long template render) while
	// killing the actual abuse cases.
	// Build the server handler. Default is http.DefaultServeMux (where
	// all our routes — and net/http/pprof's auto-registered ones — live).
	// When SCANNER_PPROF is not set, wrap the mux so any /debug/pprof
	// request short-circuits to 404. We can't unregister the pprof
	// handlers (Go's mux has no remove) so middleware is the gate.
	var handler http.Handler = http.DefaultServeMux
	if !pprofEnabled {
		base := handler
		handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasPrefix(r.URL.Path, "/debug/pprof") {
				http.NotFound(w, r)
				return
			}
			base.ServeHTTP(w, r)
		})
	}
	// Audit S5 / 85 high-medium findings: CSRF same-origin guard.
	// scaNNer is a local pentest console — every state-changing POST
	// (start scan / save settings / delete / restart) was previously
	// unprotected. A drive-by page on another origin in the same browser
	// could POST to localhost:9090 and trigger scans. We enforce two
	// independent layers:
	//   1. Sec-Fetch-Site: same-origin / none / same-site — modern
	//      browsers send this on every request (Chrome 76+, FF 90+, Safari 16+).
	//   2. Fallback for older clients: Origin / Referer header must match
	//      the request's Host (so cross-origin POSTs without Sec-Fetch
	//      headers get blocked too).
	// GET / HEAD / OPTIONS are pass-through (read-only). We also exempt
	// the dashboard JSON endpoints (chart polling).
	{
		base := handler
		handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost && r.Method != http.MethodPut && r.Method != http.MethodDelete && r.Method != http.MethodPatch {
				base.ServeHTTP(w, r)
				return
			}
			// Layer 1 — Sec-Fetch-Site
			switch r.Header.Get("Sec-Fetch-Site") {
			case "same-origin", "same-site", "none":
				base.ServeHTTP(w, r)
				return
			case "cross-site":
				http.Error(w, "cross-origin POST blocked (Sec-Fetch-Site=cross-site)", http.StatusForbidden)
				return
			}
			// Layer 2 — Origin / Referer host check (no Sec-Fetch header).
			expected := r.Host
			for _, header := range []string{"Origin", "Referer"} {
				v := r.Header.Get(header)
				if v == "" {
					continue
				}
				u, err := url.Parse(v)
				if err != nil || u.Host == "" {
					continue
				}
				if u.Host == expected {
					base.ServeHTTP(w, r)
					return
				}
				http.Error(w, "cross-origin POST blocked (Origin/Referer mismatch)", http.StatusForbidden)
				return
			}
			// No Sec-Fetch-Site AND no Origin AND no Referer. Modern
			// browsers always send at least one; curl / htmx without a
			// page context might not. Accept (localhost-only by default).
			base.ServeHTTP(w, r)
		})
	}
	// Outermost: authentication + authorization gate. Every request passes
	// here first; unauthenticated requests are bounced to /login (or 401'd for
	// background polls), and per-workspace-module grants are enforced before a
	// handler ever runs. The /login, /logout, /static and favicon paths are
	// allow-listed inside the middleware.
	handler = h.AuthMiddleware(handler)

	srv := &http.Server{
		Addr:              ":" + port,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,  // headers must arrive promptly
		ReadTimeout:       60 * time.Second,  // full request body — bigger to allow large POST bodies (target lists)
		WriteTimeout:      120 * time.Second, // result pages can be a few MB rendered HTML
		IdleTimeout:       120 * time.Second, // close keep-alive after 2 min idle
	}

	// Graceful shutdown
	go func() {
		quit := make(chan os.Signal, 1)
		signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
		<-quit
		log.Println("Shutting down...")
		// Cancel in-flight scans FIRST so their subprocesses (nmap, sslscan,
		// amass, subfinder, …) are killed via context cancellation instead of
		// being orphaned to init and left running long after the scanner exits.
		// srv.Shutdown only drains HTTP handlers; scan goroutines run
		// independently, so without this a SIGTERM leaves a pile of pentest
		// tools churning against targets in the background.
		if ids := h.ScanMgr().CancelAll("server shutting down"); len(ids) > 0 {
			log.Printf("Cancelled %d in-flight scan(s) on shutdown", len(ids))
			for _, id := range ids {
				db.MarkScanError(id, "Scan stopped — server shutting down")
			}
			time.Sleep(1 * time.Second) // let the subprocess SIGKILLs land before we exit
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		srv.Shutdown(ctx)
	}()

	// Transport security. By default scaNNer serves HTTPS with a self-signed
	// cert (generated once under DATA_DIR/tls) so login credentials and 2FA
	// codes are never sent in cleartext. Set SCANNER_TLS=0 for plain HTTP
	// (localhost dev only — the session cookie then drops its Secure flag).
	tlsEnabled := os.Getenv("SCANNER_TLS") != "0"
	h.SetSecureCookies(tlsEnabled)
	if tlsEnabled {
		certPath, keyPath, err := certs.EnsureSelfSigned(dataDir + "/tls")
		if err != nil {
			log.Fatal("Failed to prepare TLS certificate: ", err)
		}
		fmt.Printf("scaNNer running at https://localhost:%s (self-signed cert — expect a browser warning)\n", port)
		if err := srv.ListenAndServeTLS(certPath, keyPath); err != http.ErrServerClosed {
			log.Fatal(err)
		}
	} else {
		fmt.Printf("scaNNer running at http://localhost:%s (SCANNER_TLS=0 — plaintext, session cookie NOT Secure)\n", port)
		if err := srv.ListenAndServe(); err != http.ErrServerClosed {
			log.Fatal(err)
		}
	}
	log.Println("Server stopped")
}
