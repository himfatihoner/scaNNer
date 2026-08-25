package smbenum

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"scanner/internal/modules/shared"
)

// Share represents one SMB share enumerated on a target.
type Share struct {
	Name    string `json:"name"`
	Type    string `json:"type,omitempty"`
	Comment string `json:"comment,omitempty"`
	Access  string `json:"access,omitempty"` // READ, READ/WRITE, NO ACCESS, etc.
	// Top-level file/dir listing — populated when the share is at
	// least readable and the user enabled WalkShares. Capped at 200
	// entries to keep result sizes sane.
	Listing       []string `json:"listing,omitempty"`
	ListingErr    string   `json:"listing_err,omitempty"`
	InterestingHits []string `json:"interesting_hits,omitempty"` // entries matching common-secret patterns
}

type ScriptOutput struct {
	ID     string `json:"id"`
	Output string `json:"output"`
}

type TargetResult struct {
	Target        string         `json:"target"`
	IP            string         `json:"ip,omitempty"`
	OS            string         `json:"os,omitempty"`
	Domain        string         `json:"domain,omitempty"`
	Workgroup     string         `json:"workgroup,omitempty"`
	NetbiosName   string         `json:"netbios_name,omitempty"`
	Shares        []Share        `json:"shares"`
	Users         []string       `json:"users"`
	Groups        []string       `json:"groups"`
	Sessions      []string       `json:"sessions"`
	NmapScripts   []ScriptOutput `json:"nmap_scripts"`
	Enum4LinuxRaw string         `json:"enum4linux_raw,omitempty"`
	SmbClientRaw  string         `json:"smbclient_raw,omitempty"`
	Error         string         `json:"error,omitempty"`
	SMBPortOpen   bool           `json:"smb_port_open"`
}

type ScanResult struct {
	Results []TargetResult `json:"results"`
}

type Config struct {
	Targets       []string
	UseEnum4Linux bool
	UseNmap       bool
	UseSmbClient  bool
	Username      string // for authenticated enumeration; empty = anonymous
	Password      string
	Concurrency   int
	// WalkShares: after enumerating share names, attempt to list the
	// top-level contents of each readable share via `smbclient ... -c
	// "ls"`. Interesting entries (config, password, key, db, backup
	// patterns) are auto-flagged. Off by default — listing is loud
	// and may show up in fileserver audit logs.
	WalkShares bool
}

type ProgressFunc func(done int, msg string)
type PartialFunc func(*ScanResult)

func Scan(ctx context.Context, cfg Config, progress ProgressFunc, partial PartialFunc) *ScanResult {
	if ctx == nil {
		ctx = context.Background()
	}
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = 3
	}
	out := &ScanResult{}
	var mu sync.Mutex
	sem := make(chan struct{}, cfg.Concurrency)
	var wg sync.WaitGroup
	done := 0

	// Audit S2: per-target deep-copy + handler-side marshal was O(N²).
	throttle := shared.NewPartialThrottler(2 * time.Second)
	pushPartial := func() {
		if partial == nil {
			return
		}
		if !throttle.ShouldFire() {
			return
		}
		mu.Lock()
		snap := &ScanResult{Results: append([]TargetResult(nil), out.Results...)}
		mu.Unlock()
		partial(snap)
	}

	for _, t := range cfg.Targets {
		if ctx.Err() != nil {
			break
		}
		// audit K09: target string is interpolated into nmap/smbclient/
		// enum4linux argv; a value starting with "-" or containing shell
		// metachars would inject scripts/flags. Reject early.
		safe, ok := shared.SafeTarget(t)
		if !ok {
			mu.Lock()
			out.Results = append(out.Results, TargetResult{Target: t, Error: "rejected: contains shell/flag characters"})
			done++
			cur := done
			mu.Unlock()
			pushPartial()
			if progress != nil {
				// audit M1: read done under mu so a concurrent
				// goroutine's done++ doesn't tear the value.
				progress(cur, fmt.Sprintf("✗ rejected unsafe target %q", t))
			}
			continue
		}
		t = safe
		wg.Add(1)
		sem <- struct{}{}
		go func(target string) {
			defer wg.Done()
			defer func() { <-sem }()
			if progress != nil {
				mu.Lock()
				cur := done
				mu.Unlock()
				progress(cur, fmt.Sprintf("Enumerating %s ...", target))
			}
			tr := enumerate(ctx, target, cfg, func(msg string) {
				mu.Lock()
				cur := done
				mu.Unlock()
				if progress != nil {
					progress(cur, fmt.Sprintf("%s · %s", target, msg))
				}
			})
			mu.Lock()
			done++
			out.Results = append(out.Results, *tr)
			cur := done
			mu.Unlock()
			if progress != nil {
				progress(cur, fmt.Sprintf("[%d/%d] %s — %d shares, %d users", cur, len(cfg.Targets), target, len(tr.Shares), len(tr.Users)))
			}
			pushPartial()
		}(t)
	}
	wg.Wait()
	throttle.Force()
	pushPartial()
	return out
}

func enumerate(ctx context.Context, target string, cfg Config, log func(string)) *TargetResult {
	tr := &TargetResult{Target: target}

	// Step 1: confirm SMB port is open. Skip remaining steps if it's not.
	if log != nil {
		log("checking SMB port (445)")
	}
	smbOpen, ip := smbPortCheck(ctx, target, log)
	tr.IP = ip
	tr.SMBPortOpen = smbOpen
	if !smbOpen {
		tr.Error = "TCP/445 closed or filtered — SMB enumeration skipped"
		return tr
	}

	// Step 2: nmap smb-* scripts (parallel-safe, gives shares + OS + vuln)
	if cfg.UseNmap {
		if log != nil {
			log("nmap smb-* scripts")
		}
		runNmapSMB(ctx, target, tr, log)
	}

	// Step 3: smbclient -L for share listing (works without creds against open shares)
	if cfg.UseSmbClient {
		if log != nil {
			log("smbclient -L (share listing)")
		}
		runSmbClient(ctx, target, cfg, tr, log)
	}

	// Step 3b: walk the contents of each readable share. Off by default
	// because the listing operation shows up in fileserver audit logs.
	if cfg.WalkShares && len(tr.Shares) > 0 {
		if log != nil {
			log(fmt.Sprintf("walking %d share contents", len(tr.Shares)))
		}
		for i := range tr.Shares {
			share := &tr.Shares[i]
			// Skip system / admin shares — IPC$ has no filesystem,
			// ADMIN$ requires SYSTEM credentials, print$ is loud.
			if share.Name == "IPC$" || share.Name == "ADMIN$" || share.Name == "print$" {
				continue
			}
			listing, err := walkShare(ctx, target, share.Name, cfg, log)
			if err != nil {
				share.ListingErr = err.Error()
				continue
			}
			share.Listing = listing
			share.InterestingHits = filterInteresting(listing)
		}
	}

	// Step 4: enum4linux for users/groups/policy
	if cfg.UseEnum4Linux {
		if log != nil {
			log("enum4linux (users / groups / policy)")
		}
		runEnum4Linux(ctx, target, cfg, tr, log)
	}

	return tr
}

func smbPortCheck(ctx context.Context, target string, log func(string)) (bool, string) {
	args := []string{"-T4", "-n", "-Pn", "-p", "445", target}
	if log != nil {
		log("$ " + shared.FormatNmap(args))
	}
	res, _, err := shared.RunNmap(ctx, args)
	if err != nil || len(res.Hosts) == 0 {
		return false, ""
	}
	h := res.Hosts[0]
	ip := h.PrimaryAddress()
	for _, p := range h.Ports.Ports {
		if p.PortID == 445 && p.State.State == "open" {
			return true, ip
		}
	}
	return false, ip
}

func runNmapSMB(ctx context.Context, target string, tr *TargetResult, log func(string)) {
	args := []string{
		"-T4", "-n", "-Pn", "-sV",
		"-p", "139,445",
		"--script", "smb-os-discovery,smb-enum-shares,smb-enum-users,smb-enum-sessions,smb-enum-domains,smb-protocols,smb-security-mode,smb-vuln-ms17-010,smb2-security-mode",
		target,
	}
	if log != nil {
		log("$ " + shared.FormatNmap(args))
	}
	res, _, err := shared.RunNmapProgress(ctx, args, func(pct float64, _ string) {
		if log != nil {
			log(fmt.Sprintf("→ %s SMB script scan: about %.0f%% done", target, pct))
		}
	})
	if err != nil || len(res.Hosts) == 0 {
		return
	}
	h := res.Hosts[0]
	for _, p := range h.Ports.Ports {
		for _, s := range p.Scripts {
			tr.NmapScripts = append(tr.NmapScripts, ScriptOutput{ID: s.ID, Output: s.Output})
			parseScriptOutput(s.ID, s.Output, tr)
		}
	}
}

func parseScriptOutput(id, output string, tr *TargetResult) {
	switch id {
	case "smb-os-discovery":
		for _, line := range strings.Split(output, "\n") {
			line = strings.TrimSpace(line)
			switch {
			case strings.HasPrefix(line, "OS:"):
				tr.OS = strings.TrimSpace(strings.TrimPrefix(line, "OS:"))
			case strings.HasPrefix(line, "Computer name:"):
				tr.NetbiosName = strings.TrimSpace(strings.TrimPrefix(line, "Computer name:"))
			case strings.HasPrefix(line, "NetBIOS computer name:"):
				if tr.NetbiosName == "" {
					tr.NetbiosName = strings.TrimSpace(strings.TrimPrefix(line, "NetBIOS computer name:"))
				}
			case strings.HasPrefix(line, "Domain name:"):
				tr.Domain = strings.TrimSpace(strings.TrimPrefix(line, "Domain name:"))
			case strings.HasPrefix(line, "Workgroup:"):
				tr.Workgroup = strings.TrimSpace(strings.TrimPrefix(line, "Workgroup:"))
			}
		}
	case "smb-enum-shares":
		// Format includes lines like "  \\10.0.0.1\IPC$:" then "    Type: STYPE_IPC_HIDDEN"
		// Parse share names by anchor on backslash-prefixed lines.
		var current Share
		for _, line := range strings.Split(output, "\n") {
			t := strings.TrimSpace(line)
			if strings.HasPrefix(t, `\\`) && strings.HasSuffix(t, ":") {
				if current.Name != "" {
					tr.Shares = append(tr.Shares, current)
				}
				name := strings.TrimSuffix(t, ":")
				if i := strings.LastIndex(name, `\`); i >= 0 {
					name = name[i+1:]
				}
				current = Share{Name: name}
			} else if strings.HasPrefix(t, "Type:") {
				current.Type = strings.TrimSpace(strings.TrimPrefix(t, "Type:"))
			} else if strings.HasPrefix(t, "Comment:") {
				current.Comment = strings.TrimSpace(strings.TrimPrefix(t, "Comment:"))
			} else if strings.HasPrefix(t, "Anonymous access:") {
				current.Access = strings.TrimSpace(strings.TrimPrefix(t, "Anonymous access:"))
			}
		}
		if current.Name != "" {
			tr.Shares = append(tr.Shares, current)
		}
	case "smb-enum-users":
		for _, line := range strings.Split(output, "\n") {
			t := strings.TrimSpace(line)
			if strings.HasPrefix(t, `\\`) || strings.Contains(t, "Domain") || t == "" {
				continue
			}
			// Extract usernames in lines like "  HOSTNAME\username (RID: ...)"
			if i := strings.Index(t, `\`); i >= 0 && i < len(t)-1 {
				name := t[i+1:]
				if sp := strings.Index(name, " "); sp >= 0 {
					name = name[:sp]
				}
				if name != "" {
					tr.Users = append(tr.Users, name)
				}
			}
		}
	case "smb-enum-sessions":
		for _, line := range strings.Split(output, "\n") {
			t := strings.TrimSpace(line)
			if t == "" || strings.HasPrefix(t, `\\`) {
				continue
			}
			tr.Sessions = append(tr.Sessions, t)
		}
	}
}

func runSmbClient(ctx context.Context, target string, cfg Config, tr *TargetResult, log func(string)) {
	if ctx.Err() != nil {
		return
	}
	args := []string{"-L", "//" + target, "-N", "-g"}
	if cfg.Username != "" {
		args = []string{"-L", "//" + target, "-U", cfg.Username + "%" + cfg.Password, "-g"}
	}
	if log != nil {
		log("$ " + shared.FormatCommand("smbclient", redactSmbArgs(args, cfg.Username)))
	}
	cmd := shared.Command(ctx, "smbclient", args...)
	out, err := cmd.CombinedOutput()
	// Surface non-cancel errors so a "smbclient: command not found"
	// (or a connect refusal) is visible (audit B60).
	if err != nil && ctx.Err() == nil {
		tr.Error = appendError(tr.Error, "smbclient: "+err.Error())
	}
	tr.SmbClientRaw = truncateRaw(string(out), maxRawStdoutBytes)
	// -g format: lines like "Disk|share|comment"
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.Split(line, "|")
		if len(parts) >= 2 && (parts[0] == "Disk" || parts[0] == "IPC" || parts[0] == "Printer") {
			share := Share{Name: parts[1], Type: parts[0]}
			if len(parts) >= 3 {
				share.Comment = parts[2]
			}
			// Avoid duplicates from nmap pass
			if !shareExists(tr.Shares, share.Name) {
				tr.Shares = append(tr.Shares, share)
			}
		}
	}
}

func shareExists(shares []Share, name string) bool {
	for _, s := range shares {
		if strings.EqualFold(s.Name, name) {
			return true
		}
	}
	return false
}

func runEnum4Linux(ctx context.Context, target string, cfg Config, tr *TargetResult, log func(string)) {
	if ctx.Err() != nil {
		return
	}
	args := []string{"-a", target}
	if cfg.Username != "" {
		args = []string{"-u", cfg.Username, "-p", cfg.Password, "-a", target}
	}
	if log != nil {
		// Redact the -p <password> pair before surfacing to the UI's
		// commands panel. Audit M4/M9: credentials must not leak into
		// scans.commands.
		log("$ " + shared.FormatCommand("enum4linux", redactEnum4LinuxArgs(args)))
	}
	cmd := shared.Command(ctx, "enum4linux", args...)
	out, err := cmd.CombinedOutput()
	if err != nil && ctx.Err() == nil {
		tr.Error = appendError(tr.Error, "enum4linux: "+err.Error())
	}
	raw := string(out)
	tr.Enum4LinuxRaw = truncateRaw(raw, maxRawStdoutBytes)
	parseEnum4Linux(raw, tr)
}

// appendError accumulates messages on tr.Error so multiple subprocesses
// failing within a single target both surface to the operator instead of
// the last one stomping the rest.
func appendError(existing, msg string) string {
	if existing == "" {
		return msg
	}
	return existing + " | " + msg
}

func parseEnum4Linux(text string, tr *TargetResult) {
	lines := strings.Split(text, "\n")
	inUserSection := false
	inGroupSection := false
	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		// Domain / workgroup
		if strings.Contains(line, "Domain Name:") {
			tr.Domain = strings.TrimSpace(strings.TrimPrefix(line, "Domain Name:"))
		}
		if strings.Contains(line, "Workgroup:") && tr.Workgroup == "" {
			tr.Workgroup = strings.TrimSpace(strings.TrimPrefix(line, "Workgroup:"))
		}
		// Section markers
		if strings.Contains(line, "Users on") {
			inUserSection = true
			inGroupSection = false
			continue
		}
		if strings.Contains(line, "Groups on") {
			inGroupSection = true
			inUserSection = false
			continue
		}
		if strings.HasPrefix(line, "==") || strings.HasPrefix(line, "---") {
			inUserSection = false
			inGroupSection = false
			continue
		}
		// User RID lines: "user:[name] rid:[0x..]"
		if inUserSection && strings.Contains(line, "user:") {
			start := strings.Index(line, "user:[")
			if start >= 0 {
				rest := line[start+6:]
				if end := strings.Index(rest, "]"); end > 0 {
					name := rest[:end]
					if name != "" && !contains(tr.Users, name) {
						tr.Users = append(tr.Users, name)
					}
				}
			}
		}
		if inGroupSection && strings.Contains(line, "group:") {
			start := strings.Index(line, "group:[")
			if start >= 0 {
				rest := line[start+7:]
				if end := strings.Index(rest, "]"); end > 0 {
					name := rest[:end]
					if name != "" && !contains(tr.Groups, name) {
						tr.Groups = append(tr.Groups, name)
					}
				}
			}
		}
	}
}

func contains(slice []string, val string) bool {
	for _, s := range slice {
		if s == val {
			return true
		}
	}
	return false
}

// walkShare runs `smbclient //host/share -c "ls"` to list the top-level
// entries inside a readable share. Returns up to 200 entries (names
// only). Empty listing + non-nil error = unauthorized / not found.
// Bounded depth: just the root directory — recursive walk would
// generate huge results and is loud against real fileservers.
func walkShare(ctx context.Context, target, share string, cfg Config, log func(string)) ([]string, error) {
	args := []string{"//" + target + "/" + share, "-c", "ls", "-N"}
	if cfg.Username != "" {
		args = append(args, "-U", cfg.Username+"%"+cfg.Password)
	}
	if log != nil {
		log("$ " + shared.FormatCommand("smbclient", redactSmbArgs(args, cfg.Username)))
	}
	cmd := shared.Command(ctx, "smbclient", args...)
	out, err := cmd.CombinedOutput()
	if err != nil && len(out) == 0 {
		return nil, err
	}
	var entries []string
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "smb:") || strings.HasPrefix(line, "WARNING") {
			continue
		}
		// smbclient ls lines: "  name    Type   size    date"
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		name := fields[0]
		if name == "." || name == ".." {
			continue
		}
		entries = append(entries, line)
		if len(entries) >= 200 {
			break
		}
	}
	return entries, nil
}

// filterInteresting flags listing entries whose name hints at secrets,
// configs, dumps, or backups — the file types pentesters dive into
// first when given a readable share.
var interestingShareNames = []string{
	"password", "passwd", "secret", "shadow", "credential",
	".env", "config", "settings.ini", "wp-config", "web.config",
	".ssh", "id_rsa", "id_dsa", "id_ed25519", ".pem", ".key", ".pfx", ".pkcs",
	"backup", ".bak", ".sql", ".db", ".sqlite", ".mdb",
	"history", ".bash_history", ".zsh_history",
	"kdbx", "keepass", "1password",
	"unattend.xml", "sysprep.xml", "groups.xml",
}

func filterInteresting(listing []string) []string {
	var hits []string
	for _, line := range listing {
		lower := strings.ToLower(line)
		for _, needle := range interestingShareNames {
			if strings.Contains(lower, needle) {
				hits = append(hits, line)
				break
			}
		}
	}
	return hits
}

// maxRawStdoutBytes caps SmbClientRaw / Enum4LinuxRaw per target. Audit
// M12/M12dup: enum4linux -a stdout is routinely 100-500 KB per host —
// against a /24 the aggregate result blob overshoots database.go's
// 50 MB MaxResultBytes cap silently. 64 KB is well over what the human
// eye consumes on the results page but keeps a /24 worst-case at
// ~64*512 ≈ 32 MB.
const maxRawStdoutBytes = 64 * 1024

func truncateRaw(s string, max int) string {
	if max <= 0 || len(s) <= max {
		return s
	}
	return s[:max] + "\n... [truncated " + itoa(len(s)-max) + " bytes]"
}

// itoa avoids pulling in strconv purely for this one use — the smbenum
// import list stays lean.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := false
	if n < 0 {
		neg = true
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

// redactSmbArgs walks smbclient argv and replaces the password half of a
// "user%pass" -U value with "***". The plaintext still reaches smbclient
// itself (the arg slice mutated here is a fresh copy); only what the UI
// sees in the "commands" column and progress feed is redacted.
func redactSmbArgs(args []string, username string) []string {
	if username == "" {
		return args
	}
	out := make([]string, len(args))
	copy(out, args)
	for i := 0; i < len(out)-1; i++ {
		if out[i] == "-U" {
			if idx := strings.IndexByte(out[i+1], '%'); idx >= 0 {
				out[i+1] = out[i+1][:idx] + "%***"
			}
		}
	}
	return out
}

// redactEnum4LinuxArgs replaces the `-p <password>` value with ***.
func redactEnum4LinuxArgs(args []string) []string {
	out := make([]string, len(args))
	copy(out, args)
	for i := 0; i < len(out)-1; i++ {
		if out[i] == "-p" {
			out[i+1] = "***"
		}
	}
	return out
}
