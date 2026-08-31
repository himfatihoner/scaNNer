package hashcat

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"scanner/internal/modules/shared"
)

// Config is the module-internal launch config the handler builds from the
// form and hands to Scan. No network targets — the "targets" are the hashes.
type Config struct {
	Hashes        []string // one raw hash per line
	ModeID        int      // hashcat -m (e.g. 1000 = NTLM)
	ModeName      string   // display only ("NTLM")
	Attack        int      // 0 = dictionary+rules, 3 = mask/brute-force
	Wordlist      string   // path (attack 0)
	Rules         []string // rule file paths (attack 0; hashcat stacks -r)
	Mask          string   // hashcat mask (attack 3), e.g. "?d?d?d?d?d?d"
	Workload      int      // -w 1..4 (intensity)
	CPUOnly       bool     // -D 1
	AffinityCores int      // pin to this many cores via --cpu-affinity (0 = all)
	RuntimeSec    int      // --runtime seconds (0 = unlimited)
}

// HashResult is one submitted hash and its outcome.
type HashResult struct {
	Hash      string `json:"hash"`
	Plaintext string `json:"plaintext,omitempty"`
	Cracked   bool   `json:"cracked"`
}

// Summary is the live/final roll-up shown in the stats strip.
type Summary struct {
	Total       int    `json:"total"`
	Cracked     int    `json:"cracked"`
	ModeID      int    `json:"mode_id"`
	ModeName    string `json:"mode_name,omitempty"`
	Attack      string `json:"attack"` // "dictionary" | "mask"
	Status      string `json:"status"` // running|paused|exhausted|cracked|aborted|error
	ProgressPct   int    `json:"progress_pct"`
	HashrateHs    int64  `json:"hashrate_hs"`
	HashrateHuman string `json:"hashrate_h,omitempty"` // e.g. "422.1 MH/s"
	ETA           string `json:"eta,omitempty"`
	DeviceType  string `json:"device_type,omitempty"` // CPU|GPU
	DeviceName  string `json:"device_name,omitempty"`
	LiveUtilPct int    `json:"live_util_pct"` // current device utilisation %
	PeakUtilPct int    `json:"peak_util_pct"`
	DurationSec int    `json:"duration_sec"`
	Warning     string `json:"warning,omitempty"`
}

type ScanResult struct {
	Summary Summary      `json:"summary"`
	Hashes  []HashResult `json:"hashes"`
}

type ProgressFunc func(done int, msg string)
type PartialFunc func(*ScanResult)

// hcStatus mirrors the fields we read from one hashcat --status-json line.
type hcStatus struct {
	Status          int     `json:"status"`
	Progress        []int64 `json:"progress"`         // [done, keyspace_total]
	RecoveredHashes []int   `json:"recovered_hashes"` // [cracked, total]
	EstimatedStop   int64   `json:"estimated_stop"`   // unix seconds
	Devices         []struct {
		DeviceType string `json:"device_type"`
		DeviceName string `json:"device_name"`
		Speed      int64  `json:"speed"` // hashes/sec
		Util       int    `json:"util"`  // 0..100
		Temp       int    `json:"temp"`
	} `json:"devices"`
}

// Scan runs a single hashcat process and streams --status-json progress.
func Scan(ctx context.Context, cfg Config, progress ProgressFunc, partial PartialFunc) *ScanResult {
	if ctx == nil {
		ctx = context.Background()
	}
	out := &ScanResult{}
	out.Summary.Total = len(cfg.Hashes)
	out.Summary.ModeID = cfg.ModeID
	out.Summary.ModeName = cfg.ModeName
	out.Summary.Status = "running"
	if cfg.Attack == 3 {
		out.Summary.Attack = "mask"
	} else {
		out.Summary.Attack = "dictionary"
	}
	for _, h := range cfg.Hashes {
		out.Hashes = append(out.Hashes, HashResult{Hash: h})
	}

	prog := func(done int, msg string) {
		if progress != nil {
			progress(done, msg)
		}
	}
	fail := func(msg string) *ScanResult {
		out.Summary.Status = "error"
		out.Summary.Warning = msg
		out.Summary.ProgressPct = 0
		prog(0, "hashcat error: "+msg)
		if partial != nil {
			partial(out)
		}
		return out
	}

	// Write the hashes to a temp file (never inline them on the command line —
	// keeps the "$ " command crumb clean and avoids arg-length limits).
	hashFile, err := os.CreateTemp("", "hashcat-in-*.txt")
	if err != nil {
		return fail("could not create temp hash file: " + err.Error())
	}
	for _, h := range cfg.Hashes {
		hashFile.WriteString(h + "\n")
	}
	hashFile.Close()
	defer os.Remove(hashFile.Name())
	outFile := hashFile.Name() + ".out"
	defer os.Remove(outFile)

	args := buildArgs(cfg, hashFile.Name(), outFile)
	prog(0, "$ "+shared.FormatCommand("hashcat", args))
	prog(0, fmt.Sprintf("Cracking %d hash(es) — mode %d (%s), %s attack",
		len(cfg.Hashes), cfg.ModeID, cfg.ModeName, out.Summary.Attack))

	cmd := shared.Command(ctx, "hashcat", args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fail("stdout pipe: " + err.Error())
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	start := time.Now()
	if err := cmd.Start(); err != nil {
		return fail("could not start hashcat (installed?): " + err.Error())
	}

	var mu sync.Mutex
	throttle := shared.NewPartialThrottler(1 * time.Second)
	pushPartial := func(force bool) {
		if partial == nil {
			return
		}
		if !force && !throttle.ShouldFire() {
			return
		}
		mu.Lock()
		snap := &ScanResult{Summary: out.Summary, Hashes: append([]HashResult(nil), out.Hashes...)}
		mu.Unlock()
		partial(snap)
	}

	sawStatus := false
	sc := bufio.NewScanner(stdout)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if !strings.HasPrefix(line, "{") {
			continue // banners, session lines, cracked pairs → ignored (we read the outfile)
		}
		var st hcStatus
		if json.Unmarshal([]byte(line), &st) != nil {
			continue
		}
		sawStatus = true
		mu.Lock()
		applyStatus(&out.Summary, st)
		pct := out.Summary.ProgressPct
		rate := out.Summary.HashrateHs
		cracked := out.Summary.Cracked
		util := out.Summary.LiveUtilPct
		eta := out.Summary.ETA
		mu.Unlock()
		prog(pct, fmt.Sprintf("%d%% · %s · %d/%d cracked · CPU %d%%%s",
			pct, humanRate(rate), cracked, out.Summary.Total, util, etaSuffix(eta)))
		pushPartial(false)
	}
	waitErr := cmd.Wait()
	out.Summary.DurationSec = int(time.Since(start).Seconds())

	// Read the cracked pairs from the outfile (hash:plain, split on the LAST
	// colon — some hashes contain colons). This is the source of truth for
	// plaintexts; --status-json only carries the recovered COUNT.
	applyCracked(out, outFile)

	// Finalise status.
	if ctx.Err() != nil {
		out.Summary.Status = "aborted"
	} else if out.Summary.Total > 0 && out.Summary.Cracked >= out.Summary.Total {
		out.Summary.Status = "cracked"
	} else if !sawStatus {
		// hashcat produced no status at all → almost always a bad hash/mode.
		msg := lastLines(stderr.String(), 3)
		if msg == "" && waitErr != nil {
			msg = waitErr.Error()
		}
		if msg == "" {
			msg = "hashcat produced no output — check the hash format matches the selected mode"
		}
		out.Summary.Status = "error"
		out.Summary.Warning = msg
	} else if out.Summary.Status == "running" || out.Summary.Status == "paused" {
		out.Summary.Status = "exhausted"
	}
	out.Summary.ProgressPct = 100

	prog(100, fmt.Sprintf("Done — %d/%d cracked (%s)", out.Summary.Cracked, out.Summary.Total, out.Summary.Status))
	pushPartial(true)
	return out
}

func buildArgs(cfg Config, hashFile, outFile string) []string {
	args := []string{"-m", strconv.Itoa(cfg.ModeID), hashFile}
	if cfg.Attack == 3 {
		args = append(args, cfg.Mask, "-a", "3")
	} else {
		args = append(args, cfg.Wordlist, "-a", "0")
		for _, r := range cfg.Rules {
			if strings.TrimSpace(r) != "" {
				args = append(args, "-r", r)
			}
		}
	}
	w := cfg.Workload
	if w < 1 || w > 4 {
		w = 2
	}
	args = append(args, "-w", strconv.Itoa(w))
	if cfg.CPUOnly {
		args = append(args, "-D", "1")
	}
	if cfg.AffinityCores > 0 {
		args = append(args, "--cpu-affinity="+affinityList(cfg.AffinityCores))
	}
	if cfg.RuntimeSec > 0 {
		args = append(args, "--runtime", strconv.Itoa(cfg.RuntimeSec))
	}
	args = append(args,
		"-o", outFile, "--outfile-format", "1,2", // 1=hash[:salt] + 2=plain → "hash:plain"
		"--potfile-disable", "--status", "--status-json", "--status-timer", "2", "--force")
	return args
}

func applyStatus(s *Summary, st hcStatus) {
	switch st.Status {
	case 3:
		s.Status = "running"
	case 4:
		s.Status = "paused"
	case 5:
		s.Status = "exhausted"
	case 6:
		s.Status = "cracked"
	case 7, 8:
		s.Status = "aborted"
	}
	if len(st.Progress) == 2 && st.Progress[1] > 0 {
		p := int(st.Progress[0] * 100 / st.Progress[1])
		if p > 100 {
			p = 100
		}
		s.ProgressPct = p
	}
	if len(st.RecoveredHashes) == 2 {
		s.Cracked = st.RecoveredHashes[0]
	}
	var rate int64
	util := 0
	for i, d := range st.Devices {
		rate += d.Speed
		if d.Util > util {
			util = d.Util
		}
		if i == 0 && d.DeviceType != "" {
			s.DeviceType = d.DeviceType
			s.DeviceName = d.DeviceName
		}
	}
	s.HashrateHs = rate
	s.HashrateHuman = humanRate(rate)
	s.LiveUtilPct = util
	if util > s.PeakUtilPct {
		s.PeakUtilPct = util
	}
	if st.EstimatedStop > 0 {
		if d := time.Until(time.Unix(st.EstimatedStop, 0)); d > time.Second {
			s.ETA = d.Round(time.Second).String()
		} else {
			s.ETA = ""
		}
	}
}

func applyCracked(out *ScanResult, outFile string) {
	data, err := os.ReadFile(outFile)
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		idx := strings.LastIndex(line, ":")
		if idx < 0 || idx+1 > len(line) {
			continue
		}
		hashPart := strings.TrimSpace(line[:idx])
		plain := line[idx+1:]
		for i := range out.Hashes {
			if out.Hashes[i].Cracked {
				continue
			}
			h := out.Hashes[i].Hash
			if h == hashPart || strings.Contains(hashPart, h) || strings.Contains(h, hashPart) {
				out.Hashes[i].Cracked = true
				out.Hashes[i].Plaintext = plain
				break
			}
		}
	}
	c := 0
	for _, h := range out.Hashes {
		if h.Cracked {
			c++
		}
	}
	out.Summary.Cracked = c
}

func affinityList(n int) string {
	ids := make([]string, 0, n)
	for i := 1; i <= n; i++ {
		ids = append(ids, strconv.Itoa(i))
	}
	return strings.Join(ids, ",")
}

func humanRate(hs int64) string {
	f := float64(hs)
	switch {
	case f >= 1e9:
		return fmt.Sprintf("%.1f GH/s", f/1e9)
	case f >= 1e6:
		return fmt.Sprintf("%.1f MH/s", f/1e6)
	case f >= 1e3:
		return fmt.Sprintf("%.1f kH/s", f/1e3)
	default:
		return fmt.Sprintf("%d H/s", hs)
	}
}

func etaSuffix(eta string) string {
	if eta == "" {
		return ""
	}
	return " · ETA " + eta
}

func lastLines(s string, n int) string {
	lines := []string{}
	for _, l := range strings.Split(strings.TrimSpace(s), "\n") {
		if strings.TrimSpace(l) != "" {
			lines = append(lines, strings.TrimSpace(l))
		}
	}
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, " · ")
}

// ---------------------------------------------------------------------------
// Environment enumeration — consumed by the handler to build the launch form.
// ---------------------------------------------------------------------------

// HashMode is one row of `hashcat --help`'s hash-mode table.
type HashMode struct {
	ID       int    `json:"id"`
	Name     string `json:"name"`
	Category string `json:"category"`
}

var (
	modesOnce  sync.Once
	modesCache []HashMode
)

var modeRowRe = regexp.MustCompile(`^\s*(\d+)\s*\|\s*(.+?)\s*\|\s*(.+?)\s*$`)

// HashModes parses hashcat's hash-mode table once and caches it. Returns the
// full list of {id, name, category} so the UI can offer search-by-name. Empty
// if hashcat is missing.
func HashModes() []HashMode {
	modesOnce.Do(func() {
		out, err := shared.Command(context.Background(), "hashcat", "-hh").Output()
		if err != nil || len(out) == 0 {
			return
		}
		inSection := false
		for _, line := range strings.Split(string(out), "\n") {
			if strings.Contains(line, "[ Hash Modes ]") {
				inSection = true
				continue
			}
			if inSection && strings.HasPrefix(strings.TrimSpace(line), "- [") {
				break // next section
			}
			if !inSection {
				continue
			}
			m := modeRowRe.FindStringSubmatch(line)
			if m == nil {
				continue
			}
			id, err := strconv.Atoi(m[1])
			if err != nil {
				continue
			}
			name := strings.TrimSpace(m[2])
			if name == "" || strings.EqualFold(name, "Name") {
				continue // header row
			}
			modesCache = append(modesCache, HashMode{ID: id, Name: name, Category: strings.TrimSpace(m[3])})
		}
	})
	return modesCache
}

// ModeName returns the display name for a mode id (or "" if unknown).
func ModeName(id int) string {
	for _, m := range HashModes() {
		if m.ID == id {
			return m.Name
		}
	}
	return ""
}

// WordlistOption is a selectable wordlist discovered on disk.
type WordlistOption struct {
	Path  string `json:"path"`
	Label string `json:"label"`
	Size  int64  `json:"size"`
	Gz    bool   `json:"gz"`
}

var wordlistGlobs = []string{
	"/usr/share/wordlists/*.txt",
	"/usr/share/wordlists/*.txt.gz",
	"/usr/share/seclists/Passwords/*.txt",
	"/usr/share/seclists/Passwords/Common-Credentials/*.txt",
	"/usr/share/seclists/Passwords/Leaked-Databases/*.txt",
}

// Wordlists enumerates common wordlists on the host (deduped, sorted with
// rockyou-class lists first). hashcat reads .gz natively.
func Wordlists() []WordlistOption {
	seen := map[string]bool{}
	var out []WordlistOption
	for _, g := range wordlistGlobs {
		matches, _ := filepath.Glob(g)
		for _, p := range matches {
			if seen[p] {
				continue
			}
			seen[p] = true
			fi, err := os.Stat(p)
			if err != nil || fi.IsDir() {
				continue
			}
			out = append(out, WordlistOption{Path: p, Label: filepath.Base(p), Size: fi.Size(), Gz: strings.HasSuffix(p, ".gz")})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		ri, rj := strings.HasPrefix(out[i].Label, "rockyou"), strings.HasPrefix(out[j].Label, "rockyou")
		if ri != rj {
			return ri
		}
		return out[i].Label < out[j].Label
	})
	return out
}

// RuleOption is a selectable hashcat rule file.
type RuleOption struct {
	Path   string `json:"path"`
	Label  string `json:"label"`
	Size   int64  `json:"size"`
	Famous bool   `json:"famous"`
}

// famousRules are the well-known rule sets surfaced first in the picker. Only
// those present on disk are shown; others fall into the "all rules" list.
var famousRules = map[string]bool{
	"best66.rule": true, "rockyou-30000.rule": true, "dive.rule": true,
	"d3ad0ne.rule": true, "T0XlC.rule": true, "T0XlCv2.rule": true,
	"generated2.rule": true, "leetspeak.rule": true, "combinator.rule": true,
	"toggles1.rule": true, "toggles3.rule": true, "toggles5.rule": true,
	"top10_2025.rule": true, "Incisive-leetspeak.rule": true,
}

// Rules enumerates /usr/share/hashcat/rules/*.rule, famous ones first.
func Rules() []RuleOption {
	matches, _ := filepath.Glob("/usr/share/hashcat/rules/*.rule")
	var out []RuleOption
	for _, p := range matches {
		fi, err := os.Stat(p)
		if err != nil || fi.IsDir() {
			continue
		}
		base := filepath.Base(p)
		out = append(out, RuleOption{Path: p, Label: base, Size: fi.Size(), Famous: famousRules[base]})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Famous != out[j].Famous {
			return out[i].Famous
		}
		return out[i].Label < out[j].Label
	})
	return out
}
