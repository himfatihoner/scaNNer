package brutef

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"scanner/internal/modules/shared"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Protocol identifies which hydra service module to use.
type Protocol string

const (
	ProtoSSH      Protocol = "ssh"
	ProtoFTP      Protocol = "ftp"
	ProtoRDP      Protocol = "rdp"
	ProtoSMB      Protocol = "smb"
	ProtoMSSQL    Protocol = "mssql"
	ProtoMySQL    Protocol = "mysql"
	ProtoPostgres Protocol = "postgres"
	ProtoVNC      Protocol = "vnc"
	// LDAP: hydra module name is "ldap3" (LDAPv3 simple bind). Kept the
	// Go-side constant value equal to hydra's module name so the string
	// passed to hydra's argv is a straight cast.
	ProtoLDAP   Protocol = "ldap3"
	ProtoTelnet Protocol = "telnet"
)

func (p Protocol) Valid() bool {
	switch p {
	case ProtoSSH, ProtoFTP, ProtoRDP,
		ProtoSMB, ProtoMSSQL, ProtoMySQL, ProtoPostgres,
		ProtoVNC, ProtoLDAP, ProtoTelnet:
		return true
	}
	return false
}

// DefaultPort returns the conventional port for each supported protocol.
func (p Protocol) DefaultPort() int {
	switch p {
	case ProtoSSH:
		return 22
	case ProtoFTP:
		return 21
	case ProtoRDP:
		return 3389
	case ProtoSMB:
		return 445
	case ProtoMSSQL:
		return 1433
	case ProtoMySQL:
		return 3306
	case ProtoPostgres:
		return 5432
	case ProtoVNC:
		return 5900
	case ProtoLDAP:
		return 389
	case ProtoTelnet:
		return 23
	}
	return 0
}

// Credential is a successful (user, pass) pair as found by hydra.
type Credential struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Username string `json:"username"`
	Password string `json:"password"`
}

type TargetResult struct {
	Target     string       `json:"target"`
	Port       int          `json:"port"`
	Protocol   Protocol     `json:"protocol"`
	Found      []Credential `json:"found"`
	Attempts   int          `json:"attempts"`
	HydraRaw   string       `json:"hydra_raw,omitempty"`
	Error      string       `json:"error,omitempty"`
	InProgress bool         `json:"in_progress,omitempty"`
}

type ScanResult struct {
	Results []TargetResult `json:"results"`
}

type Config struct {
	Targets       []string
	Protocol      Protocol
	Port          int      // 0 = use protocol default
	UserList      []string // each line written to a temp file
	PassList      []string
	UseSingleUser string // alternative: -l <user> instead of -L <list>
	UsePassList   bool
	StopOnFirst   bool // hydra -f: stop a target on first valid creds
	Threads       int  // hydra -t (max parallel logins per target)
	Concurrency   int  // parallel hydra processes (one per target)
	// IncludeDefaults augments the user/pass list with built-in default
	// credentials for the chosen protocol. Pentests turn up vendor
	// defaults (admin:admin, cisco:cisco, root:calvin, postgres:postgres)
	// disproportionately often — running these as a quick pre-pass
	// before the long wordlist saves hours.
	IncludeDefaults bool
}

// DefaultCredentials returns service-specific built-in user:pass pairs.
// Sourced from Hydra's own defaults files + SecLists 'common-creds' —
// curated to the ones still found in real pentest engagements.
// Per (user, pass) pair, NOT the cartesian product, so the brute is
// bounded.
var DefaultCredentials = map[Protocol][]struct{ User, Pass string }{
	ProtoSSH: {
		{"root", "root"}, {"root", "toor"}, {"root", "admin"},
		{"root", "password"}, {"root", "calvin"}, {"root", "raspberry"},
		{"admin", "admin"}, {"admin", "password"}, {"admin", "1234"},
		{"pi", "raspberry"}, {"ubuntu", "ubuntu"}, {"oracle", "oracle"},
		{"postgres", "postgres"}, {"vagrant", "vagrant"}, {"test", "test"},
		{"user", "user"}, {"guest", "guest"},
	},
	ProtoFTP: {
		{"anonymous", ""}, {"anonymous", "anonymous@"},
		{"ftp", "ftp"}, {"admin", "admin"}, {"root", "root"},
		{"test", "test"}, {"user", "user"}, {"guest", "guest"},
		{"administrator", "password"},
	},
	ProtoRDP: {
		{"administrator", "administrator"}, {"administrator", "password"},
		{"administrator", "Password1"}, {"administrator", "P@ssw0rd"},
		{"admin", "admin"}, {"admin", "password"},
		{"guest", ""}, {"user", "user"},
	},
	ProtoSMB: {
		{"administrator", "administrator"}, {"administrator", "password"},
		{"administrator", "Password1"}, {"administrator", "P@ssw0rd"},
		{"admin", "admin"}, {"admin", "password"},
		{"guest", ""}, {"guest", "guest"},
	},
	ProtoMSSQL: {
		{"sa", ""}, {"sa", "sa"}, {"sa", "password"},
		{"sa", "Password1"}, {"sa", "P@ssw0rd"},
		{"admin", "admin"}, {"administrator", "password"},
	},
	ProtoMySQL: {
		{"root", ""}, {"root", "root"}, {"root", "password"},
		{"root", "toor"}, {"root", "mysql"},
		{"mysql", "mysql"}, {"admin", "admin"},
	},
	ProtoPostgres: {
		{"postgres", "postgres"}, {"postgres", ""}, {"postgres", "password"},
		{"admin", "admin"}, {"admin", "password"},
	},
	ProtoVNC: {
		{"", "password"}, {"", "vnc"}, {"", "admin"},
		{"", "1234"}, {"", "12345678"},
	},
	ProtoLDAP: {
		{"admin", "admin"}, {"administrator", "password"},
		{"cn=admin,dc=example,dc=com", "admin"},
	},
	ProtoTelnet: {
		{"root", "root"}, {"root", ""}, {"root", "toor"},
		{"admin", "admin"}, {"admin", "password"},
		{"cisco", "cisco"}, {"user", "user"}, {"guest", "guest"},
	},
}

type ProgressFunc func(done int, msg string)
type PartialFunc func(*ScanResult)

func Scan(ctx context.Context, cfg Config, progress ProgressFunc, partial PartialFunc) *ScanResult {
	if ctx == nil {
		ctx = context.Background()
	}
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = 2
	}
	if cfg.Threads <= 0 {
		cfg.Threads = 16
	}
	// IncludeDefaults: prepend service-specific default user/pass pairs
	// so common vendor backdoors (admin:admin, root:calvin, postgres:postgres)
	// are tried before the user's long wordlist. We add to both lists
	// (hydra does the cartesian itself); duplicates with the existing
	// lists are harmless.
	if cfg.IncludeDefaults {
		if defaults, ok := DefaultCredentials[cfg.Protocol]; ok {
			seenU := map[string]bool{}
			seenP := map[string]bool{}
			for _, u := range cfg.UserList {
				seenU[u] = true
			}
			for _, p := range cfg.PassList {
				seenP[p] = true
			}
			for _, d := range defaults {
				if !seenU[d.User] {
					cfg.UserList = append([]string{d.User}, cfg.UserList...)
					seenU[d.User] = true
				}
				if !seenP[d.Pass] {
					cfg.PassList = append([]string{d.Pass}, cfg.PassList...)
					seenP[d.Pass] = true
				}
			}
		}
	}
	out := &ScanResult{}
	var mu sync.Mutex
	// inFlight tracks targets that are currently being brute-forced so
	// pushPartial can surface live progress (attempt counters, freshly
	// found credentials) in the UI rather than waiting for each target's
	// hydra process to exit (audit ER fix: "Streams successful logins
	// live" was previously broken — the snapshot only contained finished
	// targets). Goroutine inserts on start, mutates under mu, removes
	// when appending to out.Results.
	inFlight := map[string]*TargetResult{}
	sem := make(chan struct{}, cfg.Concurrency)
	var wg sync.WaitGroup
	done := 0

	// Materialize wordlists into a single temp dir (audit B16). The
	// previous code created two free-standing temp files via
	// os.CreateTemp + per-file defer os.Remove. If a SIGTERM hit between
	// the two creates (or if writeTempList panicked), one file leaked.
	// Wrapping both inside os.MkdirTemp + a single defer RemoveAll
	// guarantees atomic cleanup: either both are gone or neither has
	// been created.
	bruteDir, err := os.MkdirTemp("", "scanner-brutef-*")
	if err != nil {
		// Caller will see empty user/pass paths and surface the failure.
		bruteDir = ""
	} else {
		defer os.RemoveAll(bruteDir)
	}
	userListPath := ""
	if cfg.UseSingleUser == "" && bruteDir != "" {
		if p, err := writeListInDir(bruteDir, "users.txt", cfg.UserList); err == nil {
			userListPath = p
		}
	}
	passListPath := ""
	if bruteDir != "" {
		if p, err := writeListInDir(bruteDir, "pass.txt", cfg.PassList); err == nil {
			passListPath = p
		}
	}

	// Audit S2: throttle hydra-log-driven partials (was per-log-line marshal).
	throttle := shared.NewPartialThrottler(2 * time.Second)
	pushPartial := func() {
		if partial == nil {
			return
		}
		if !throttle.ShouldFire() {
			return
		}
		mu.Lock()
		// Compose snapshot from finished + in-flight target results so the
		// UI can show streaming hits and attempt counters.
		snap := &ScanResult{Results: append([]TargetResult(nil), out.Results...)}
		for _, tr := range inFlight {
			cp := *tr
			cp.InProgress = true
			snap.Results = append(snap.Results, cp)
		}
		mu.Unlock()
		partial(snap)
	}

	for _, t := range cfg.Targets {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(target string) {
			defer wg.Done()
			defer func() { <-sem }()
			// Register an in-flight placeholder so pushPartial can surface
			// live state. log() and runHydra mutate this entry under mu.
			port := cfg.Port
			if port <= 0 {
				port = cfg.Protocol.DefaultPort()
			}
			placeholder := &TargetResult{Target: target, Port: port, Protocol: cfg.Protocol, InProgress: true}
			mu.Lock()
			inFlight[target] = placeholder
			cur := done
			mu.Unlock()
			if progress != nil {
				progress(cur, fmt.Sprintf("Brute-forcing %s ...", target))
			}
			// Rate-limit the DB-write progress callbacks from inside the
			// hydra log stream (audit perf): hydra is chatty and the
			// callback fires on every hit + every 50th attempt per target.
			// 1s/target floor prevents UpdateScanProgress hammering SQLite.
			var lastProgress time.Time
			tr := runHydra(ctx, target, cfg, userListPath, passListPath, placeholder, &mu, func(msg string) {
				// Don't pushPartial here — the 2s ticker already flushes.
				if progress == nil {
					return
				}
				// "$ "-prefixed messages are command-line crumbs the DB
				// captures into scans.commands. Pass them through unthrottled
				// and without the target-context wrap so the prefix survives
				// for the extractor to see.
				if strings.HasPrefix(msg, "$ ") {
					mu.Lock()
					curCrumb := done
					mu.Unlock()
					progress(curCrumb, msg)
					return
				}
				now := time.Now()
				if now.Sub(lastProgress) < 1*time.Second {
					return
				}
				lastProgress = now
				mu.Lock()
				curMsg := done
				mu.Unlock()
				progress(curMsg, fmt.Sprintf("%s · %s", target, msg))
			})
			mu.Lock()
			done++
			delete(inFlight, target)
			out.Results = append(out.Results, *tr)
			cur = done
			mu.Unlock()
			if progress != nil {
				progress(cur, fmt.Sprintf("[%d/%d] %s — %d valid creds in %d attempts", cur, len(cfg.Targets), target, len(tr.Found), tr.Attempts))
			}
			pushPartial()
		}(t)
	}
	wg.Wait()
	throttle.Force()
	pushPartial()
	return out
}

// writeListInDir writes a wordlist into the caller-managed temp dir so
// the dir's defer RemoveAll cleans everything in one call (audit B16).
// Returns the absolute file path.
func writeListInDir(dir, name string, lines []string) (string, error) {
	if len(lines) == 0 {
		return "", fmt.Errorf("empty list")
	}
	p := filepath.Join(dir, name)
	f, err := os.Create(p)
	if err != nil {
		return "", err
	}
	defer f.Close()
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l == "" {
			continue
		}
		fmt.Fprintln(f, l)
	}
	return p, nil
}

func runHydra(ctx context.Context, target string, cfg Config, userListPath, passListPath string, live *TargetResult, liveMu *sync.Mutex, log func(string)) *TargetResult {
	port := cfg.Port
	if port <= 0 {
		port = cfg.Protocol.DefaultPort()
	}
	tr := &TargetResult{Target: target, Port: port, Protocol: cfg.Protocol}

	// Reject targets with command-line metacharacters / leading dashes
	// before letting them reach hydra's argv (audit security: argument
	// injection / flag injection via target value).
	if _, ok := shared.SafeTarget(target); !ok {
		tr.Error = "unsafe target value rejected"
		return tr
	}
	if cfg.UseSingleUser != "" {
		if strings.HasPrefix(cfg.UseSingleUser, "-") {
			tr.Error = "unsafe username value rejected"
			return tr
		}
	}

	// Build hydra arg list.
	args := []string{}
	if cfg.UseSingleUser != "" {
		args = append(args, "-l", cfg.UseSingleUser)
	} else if userListPath != "" {
		args = append(args, "-L", userListPath)
	} else {
		tr.Error = "no usernames provided"
		return tr
	}
	if passListPath != "" {
		args = append(args, "-P", passListPath)
	} else {
		tr.Error = "no password list provided"
		return tr
	}
	if cfg.StopOnFirst {
		args = append(args, "-f")
	}
	// "--" terminates option parsing so a target that begins with "-"
	// (e.g. "-R" for restore) can't be reinterpreted as a flag. hydra's
	// getopt-style parser respects this.
	args = append(args,
		"-t", strconv.Itoa(cfg.Threads),
		"-s", strconv.Itoa(port),
		"-V", "-I",
		"--",
		target,
		string(cfg.Protocol),
	)

	if log != nil {
		log("$ " + shared.FormatCommand("hydra", args))
	}
	// Preflight: name a missing hydra binary consistently. With the killswitch
	// armed the spawn is wrapped in `ip netns exec scanner-ns hydra …`, so a
	// missing hydra would otherwise surface as an opaque `ip` failure at Wait()
	// instead of a clean "hydra not installed". LookPath is a host-PATH stat
	// (no process spawned), so it never bypasses the killswitch; its error
	// routes through TranslateToolError, which names the tool (audit
	// silent-missing-tool fix).
	if _, lpErr := exec.LookPath("hydra"); lpErr != nil {
		if friendly, ok := shared.TranslateToolError(lpErr.Error()); ok {
			tr.Error = friendly
		} else {
			tr.Error = "hydra not found: " + lpErr.Error()
		}
		return tr
	}
	cmd := shared.Command(ctx, "hydra", args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		tr.Error = "hydra stdout: " + err.Error()
		return tr
	}
	stderr, _ := cmd.StderrPipe()
	if err := cmd.Start(); err != nil {
		// FD leak fix (audit B27): pipe FDs survive a failed Start.
		// hydra missing / OOM-killed at start was leaking 2 FDs every
		// invocation. Cumulative over a 2-day soak of intermittent
		// brutef scans, this surfaces as 'too many open files'.
		stdout.Close()
		if stderr != nil {
			stderr.Close()
		}
		tr.Error = "hydra start: " + err.Error()
		return tr
	}

	var rawBuf strings.Builder
	var bufMu sync.Mutex
	// rawBudget caps the in-memory raw-output buffer at ~64 KB so a long
	// hydra run (10k passwords × 10 users = 100k [ATTEMPT] lines, ~5-15 MB)
	// doesn't sit in RAM for the lifetime of the scan. The final result is
	// truncated to 32 KB anyway — keep the budget slightly larger so the
	// trailing context (final summary, errors) survives. Audit perf.
	const rawBudget = 64 * 1024
	appendRaw := func(s string) {
		bufMu.Lock()
		defer bufMu.Unlock()
		if rawBuf.Len() >= rawBudget {
			return
		}
		remaining := rawBudget - rawBuf.Len()
		if len(s)+1 > remaining {
			if remaining > 0 {
				if len(s) > remaining {
					rawBuf.WriteString(s[:remaining])
				} else {
					rawBuf.WriteString(s)
				}
			}
			return
		}
		rawBuf.WriteString(s)
		rawBuf.WriteByte('\n')
	}
	// CRITICAL: stderr drain must run CONCURRENTLY with the stdout reader
	// or hydra deadlocks once the ~64 KB stderr pipe buffer fills (which it
	// does almost immediately — hydra is very chatty). Same pattern as the
	// nuclei runner.
	stderrDone := make(chan struct{})
	if stderr != nil {
		go func() {
			defer close(stderrDone)
			b := bufio.NewScanner(stderr)
			b.Buffer(make([]byte, 1024*1024), 4*1024*1024)
			for b.Scan() {
				appendRaw(b.Text())
			}
		}()
	} else {
		close(stderrDone)
	}

	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 1024*1024), 4*1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		appendRaw(line)
		// Hit lines look like: "[22][ssh] host: 1.2.3.4   login: root   password: toor"
		if c := parseHydraHit(line); c != nil {
			c.Host = target
			tr.Found = append(tr.Found, *c)
			// Mirror onto the live in-flight result so the streaming UI
			// snapshot can show the hit immediately.
			if live != nil && liveMu != nil {
				liveMu.Lock()
				live.Found = append(live.Found, *c)
				liveMu.Unlock()
			}
			if log != nil {
				log(fmt.Sprintf("✓ %s : %s", c.Username, c.Password))
			}
		}
		// Attempt counter — hydra prints "[ATTEMPT] target X.Y.Z.W - login..."
		if strings.Contains(line, "[ATTEMPT]") {
			tr.Attempts++
			if live != nil && liveMu != nil {
				liveMu.Lock()
				live.Attempts = tr.Attempts
				liveMu.Unlock()
			}
			if log != nil && tr.Attempts%50 == 0 {
				// hydra appends "- N of M [child C]" to each attempt — parse it
				// for a REAL per-target percentage instead of a bare count.
				msg := fmt.Sprintf("%d attempts so far · %d found", tr.Attempts, len(tr.Found))
				if oi := strings.Index(line, " of "); oi > 0 {
					if ci := strings.Index(line[oi:], " [child"); ci > 0 {
						pre := strings.TrimSpace(line[:oi])
						nTok := pre[strings.LastIndex(pre, " ")+1:]
						mTok := strings.TrimSpace(line[oi+4 : oi+ci])
						if n, e1 := strconv.Atoi(nTok); e1 == nil {
							if m, e2 := strconv.Atoi(mTok); e2 == nil && m > 0 {
								msg = fmt.Sprintf("→ %s brute: %d/%d (%d%%) · %d found", target, n, m, n*100/m, len(tr.Found))
							}
						}
					}
				}
				log(msg)
			}
		}
	}
	<-stderrDone
	if err := cmd.Wait(); err != nil {
		// hydra exits 0 on success and non-zero on real problems: fail2ban /
		// account-lockout ("all children were disabled"), rate-limiting, a
		// build without libssh, flag/protocol drift, or the binary vanishing
		// mid-run. Surface the reason ONLY when this target yielded no
		// credentials — a non-zero exit AFTER real hits is hydra noise and must
		// never clobber found creds. The previous guard also required
		// Attempts==0, which silently swallowed the most important case: a run
		// that made attempts and was THEN locked out exits non-zero with
		// Attempts>0 and Found==0, and was being reported as a clean "done"
		// with zero results (audit silent-tool-error fix). Route the raw tail
		// through TranslateToolError so lockout / missing-libssh / flag-drift
		// runs get a plain-language reason instead of a bare exit code.
		if len(tr.Found) == 0 {
			raw := strings.TrimSpace(rawBuf.String())
			combined := err.Error()
			if raw != "" {
				combined += "\n" + raw
			}
			if friendly, ok := shared.TranslateToolError(combined); ok {
				tr.Error = friendly
			} else if snippet := hydraErrorLine(raw); snippet != "" {
				tr.Error = "hydra exited non-zero: " + snippet
			} else {
				tr.Error = "hydra exited non-zero: " + err.Error()
			}
		}
	}
	tr.HydraRaw = truncateRaw(rawBuf.String(), 32*1024)
	return tr
}

// parseHydraHit extracts (user, pass) from a hydra success line.
// Format: "[<port>][<service>] host: <host>   login: <u>   password: <p>"
func parseHydraHit(line string) *Credential {
	if !strings.Contains(line, "login:") || !strings.Contains(line, "password:") {
		return nil
	}
	// Find login:
	loginIdx := strings.Index(line, "login:")
	passIdx := strings.Index(line, "password:")
	if loginIdx < 0 || passIdx < 0 || passIdx < loginIdx {
		return nil
	}
	user := strings.TrimSpace(line[loginIdx+len("login:") : passIdx])
	user = strings.TrimSpace(user)
	pass := strings.TrimSpace(line[passIdx+len("password:"):])
	// Also extract port if present at the start
	port := 0
	if strings.HasPrefix(line, "[") {
		end := strings.Index(line, "]")
		if end > 1 {
			if n, err := strconv.Atoi(line[1:end]); err == nil {
				port = n
			}
		}
	}
	return &Credential{Username: user, Password: pass, Port: port}
}

func truncateRaw(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "\n\n... [truncated " + strconv.Itoa(len(s)-max) + " bytes]"
}

// hydraErrorLine returns a credential-safe one-line summary of a failed hydra
// run, used only as a fallback when TranslateToolError has no specific rule for
// the output. It prefers the first "[ERROR]" line hydra emitted, else the last
// non-empty line (usually hydra's completion summary). "[ATTEMPT]" lines are
// skipped on purpose — they echo candidate passwords from the wordlist, and
// those must never be surfaced in an error banner. The result is trimmed to
// ~180 chars.
func hydraErrorLine(raw string) string {
	const max = 180
	lines := strings.Split(raw, "\n")
	for _, ln := range lines {
		ln = strings.TrimSpace(ln)
		if strings.Contains(ln, "[ERROR]") {
			return clip(ln, max)
		}
	}
	for i := len(lines) - 1; i >= 0; i-- {
		ln := strings.TrimSpace(lines[i])
		if ln == "" || strings.Contains(ln, "[ATTEMPT]") {
			continue
		}
		return clip(ln, max)
	}
	return ""
}

func clip(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}

// LoadList reads a wordlist file and returns its lines.
func LoadList(path string) ([]string, error) {
	abs, _ := filepath.Abs(path)
	f, err := os.Open(abs)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1024*1024), 8*1024*1024)
	for sc.Scan() {
		l := strings.TrimSpace(sc.Text())
		if l != "" && !strings.HasPrefix(l, "#") {
			out = append(out, l)
		}
	}
	return out, sc.Err()
}
