package hashcat

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"scanner/internal/modules/shared"
)

// maxDetectTry bounds how many auto-detected candidate modes we'll actually
// attempt (each is a full hashcat pass, so we cap the work).
const maxDetectTry = 5

// Config is the module-internal launch config the handler builds from the
// form. No network targets — the "targets" are the hashes.
type Config struct {
	Hashes        []string // one raw hash per line
	ModeID        int      // hashcat -m (ignored when DetectMode is true)
	ModeName      string   // display only ("NTLM")
	DetectMode    bool     // no mode chosen → auto-detect via hashid and try candidates
	Attack        int      // 0 = dictionary+rules, 3 = mask/brute-force
	Wordlist      string   // path (attack 0)
	Rules         []string // rule file paths (attack 0; hashcat stacks -r)
	Mask          string   // hashcat mask (attack 3)
	Workload      int      // -w 1..4
	CPUOnly       bool     // -D 1
	AffinityCores int      // pin to this many cores via --cpu-affinity (0 = all)
	RuntimeSec    int      // --runtime seconds (0 = unlimited)
}

type HashResult struct {
	Hash      string `json:"hash"`
	Plaintext string `json:"plaintext,omitempty"`
	Cracked   bool   `json:"cracked"`
}

type Summary struct {
	Total         int    `json:"total"`
	Cracked       int    `json:"cracked"`
	ModeID        int    `json:"mode_id"`
	ModeName      string `json:"mode_name,omitempty"`
	DetectedModes string `json:"detected_modes,omitempty"` // auto-detect candidates shown to the user
	Attack        string `json:"attack"` // "dictionary" | "mask"
	Status        string `json:"status"` // running|exhausted|cracked|aborted|error
	ProgressPct   int    `json:"progress_pct"`
	HashrateHs    int64  `json:"hashrate_hs"`
	HashrateHuman string `json:"hashrate_h,omitempty"`
	ETA           string `json:"eta,omitempty"`
	DeviceType    string `json:"device_type,omitempty"`
	DeviceName    string `json:"device_name,omitempty"`
	LiveUtilPct   int    `json:"live_util_pct"`
	PeakUtilPct   int    `json:"peak_util_pct"`
	DurationSec   int    `json:"duration_sec"`
	Warning       string `json:"warning,omitempty"`
}

type ScanResult struct {
	Summary Summary      `json:"summary"`
	Hashes  []HashResult `json:"hashes"`
}

type ProgressFunc func(done int, msg string)
type PartialFunc func(*ScanResult)

type hcStatus struct {
	Status          int     `json:"status"`
	Progress        []int64 `json:"progress"`
	RecoveredHashes []int   `json:"recovered_hashes"`
	EstimatedStop   int64   `json:"estimated_stop"`
	Devices         []struct {
		DeviceType string `json:"device_type"`
		DeviceName string `json:"device_name"`
		Speed      int64  `json:"speed"`
		Util       int    `json:"util"`
		Temp       int    `json:"temp"`
	} `json:"devices"`
}

// Scan cracks the submitted hashes. If cfg.DetectMode, it auto-detects the
// algorithm (via hashid) and tries each candidate mode until one cracks.
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
	prog := func(done int, msg string) {
		if progress != nil {
			progress(done, msg)
		}
	}
	fail := func(msg string) *ScanResult {
		out.Summary.Status = "error"
		out.Summary.Warning = msg
		prog(0, "hashcat: "+msg)
		if partial != nil {
			partial(out)
		}
		return out
	}

	if len(cfg.Hashes) == 0 {
		return fail("no hashes provided")
	}

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

	// Decide which mode(s) to try.
	var modes []int
	if cfg.DetectMode {
		cands := DetectModes(cfg.Hashes[0])
		if len(cands) == 0 {
			return fail("could not auto-detect the hash type (hashid found no candidates) — pick the algorithm manually")
		}
		for _, c := range cands {
			modes = append(modes, c.ID)
		}
		if len(modes) > maxDetectTry {
			modes = modes[:maxDetectTry]
		}
		labels := make([]string, 0, len(modes))
		for _, mid := range modes {
			labels = append(labels, fmt.Sprintf("%d %s", mid, ModeName(mid)))
		}
		out.Summary.DetectedModes = strings.Join(labels, ", ")
		prog(0, "Auto-detect candidates: "+out.Summary.DetectedModes)
	} else {
		modes = []int{cfg.ModeID}
	}

	start := time.Now()
	lastExit := 0
	lastErr := ""
	anyClean := false // any pass reached a normal exit (0/1) → not a hard error

	for i, mid := range modes {
		if ctx.Err() != nil {
			break
		}
		mu.Lock()
		out.Summary.ModeID = mid
		out.Summary.ModeName = ModeName(mid)
		out.Summary.ProgressPct = 0
		mu.Unlock()
		if cfg.DetectMode {
			prog(0, fmt.Sprintf("Trying mode %d (%s) — candidate %d/%d", mid, ModeName(mid), i+1, len(modes)))
		}
		_ = os.Remove(outFile) // fresh outfile per pass

		exit, errTail := crackPass(ctx, cfg, mid, hashFile.Name(), outFile, prog, &out.Summary, &mu, pushPartial)
		lastExit, lastErr = exit, errTail
		if exit == 0 || exit == 1 {
			anyClean = true
		}
		applyCracked(out, outFile)
		if out.Summary.Cracked > 0 {
			break // solved — stop trying other candidates
		}
	}
	out.Summary.DurationSec = int(time.Since(start).Seconds())

	// Finalise status from the LAST pass's exit code (hashcat: 0=cracked,
	// 1=exhausted, 2/3/4=aborted, negative/other=error). An exhaust that
	// finished in under one --status-timer tick emits no status-json at all —
	// exit-code logic is what stops that from being mislabeled an error.
	switch {
	case ctx.Err() != nil:
		out.Summary.Status = "aborted"
	case out.Summary.Cracked > 0:
		out.Summary.Status = "cracked"
	case lastExit == 1 || (anyClean && lastExit == 0):
		out.Summary.Status = "exhausted"
	case lastExit == 2 || lastExit == 3 || lastExit == 4:
		out.Summary.Status = "aborted"
	case anyClean:
		out.Summary.Status = "exhausted"
	default:
		out.Summary.Status = "error"
		if lastErr != "" {
			out.Summary.Warning = lastErr
		} else {
			out.Summary.Warning = "hashcat exited with code " + strconv.Itoa(lastExit) + " — check the hash format matches the mode"
		}
	}
	out.Summary.ProgressPct = 100

	verb := out.Summary.Status
	if cfg.DetectMode && out.Summary.Cracked > 0 {
		verb = fmt.Sprintf("cracked as mode %d (%s)", out.Summary.ModeID, out.Summary.ModeName)
	}
	prog(100, fmt.Sprintf("Done — %d/%d cracked (%s)", out.Summary.Cracked, out.Summary.Total, verb))
	pushPartial(true)
	return out
}

// crackPass runs ONE hashcat invocation for a single mode, streaming
// --status-json into the shared summary. Returns the process exit code and a
// short stderr tail (for error reporting).
func crackPass(ctx context.Context, cfg Config, modeID int, hashFile, outFile string,
	prog func(int, string), sum *Summary, mu *sync.Mutex, pushPartial func(bool)) (int, string) {

	args := buildArgs(cfg, modeID, hashFile, outFile)
	prog(0, "$ "+shared.FormatCommand("hashcat", args))

	cmd := shared.Command(ctx, "hashcat", args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return -1, "stdout pipe: " + err.Error()
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		return -1, "could not start hashcat (installed?): " + err.Error()
	}

	sc := bufio.NewScanner(stdout)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if !strings.HasPrefix(line, "{") {
			continue
		}
		var st hcStatus
		if json.Unmarshal([]byte(line), &st) != nil {
			continue
		}
		mu.Lock()
		applyStatus(sum, st)
		pct, rate, cracked, util, eta, total := sum.ProgressPct, sum.HashrateHuman, sum.Cracked, sum.LiveUtilPct, sum.ETA, sum.Total
		mu.Unlock()
		prog(pct, fmt.Sprintf("%d%% · %s · %d/%d cracked · CPU %d%%%s", pct, rate, cracked, total, util, etaSuffix(eta)))
		pushPartial(false)
	}
	return exitCode(cmd.Wait()), lastLines(stderr.String(), 3)
}

func exitCode(err error) int {
	if err == nil {
		return 0
	}
	if ee, ok := err.(*exec.ExitError); ok {
		return ee.ExitCode()
	}
	return -1
}

func buildArgs(cfg Config, modeID int, hashFile, outFile string) []string {
	args := []string{"-m", strconv.Itoa(modeID), hashFile}
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
		"--potfile-disable", "--status", "--status-json", "--status-timer", "1", "--force")
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

func humanCount(n int) string {
	switch {
	case n < 0:
		return "?"
	case n >= 1e6:
		return fmt.Sprintf("%.1fM", float64(n)/1e6)
	case n >= 1e3:
		return fmt.Sprintf("%.0fk", float64(n)/1e3)
	default:
		return strconv.Itoa(n)
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
// Hash-type auto-detection (hashid)
// ---------------------------------------------------------------------------

var hashidRe = regexp.MustCompile(`\[\+\]\s*(.+?)\s*\[Hashcat Mode:\s*(\d+)\]`)

// DetectModes shells out to `hashid -m <hash>` and returns candidate hashcat
// modes in hashid's preference order (deduped). Empty if hashid is missing or
// finds nothing with a hashcat mode.
func DetectModes(hash string) []HashMode {
	hash = strings.TrimSpace(hash)
	if hash == "" {
		return nil
	}
	out, err := shared.Command(context.Background(), "hashid", "-m", hash).Output()
	if err != nil || len(out) == 0 {
		return nil
	}
	var modes []HashMode
	seen := map[int]bool{}
	for _, line := range strings.Split(string(out), "\n") {
		m := hashidRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		id, err := strconv.Atoi(m[2])
		if err != nil || seen[id] {
			continue
		}
		seen[id] = true
		name := ModeName(id)
		if name == "" {
			name = strings.TrimSpace(m[1])
		}
		modes = append(modes, HashMode{ID: id, Name: name})
	}
	return modes
}

// ---------------------------------------------------------------------------
// Environment enumeration — consumed by the handler to build the launch form.
// ---------------------------------------------------------------------------

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

// HashModes parses hashcat's hash-mode table once and caches it.
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
				break
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
				continue
			}
			modesCache = append(modesCache, HashMode{ID: id, Name: name, Category: strings.TrimSpace(m[3])})
		}
	})
	return modesCache
}

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
	Path     string `json:"path"`
	Label    string `json:"label"`
	Group    string `json:"group"` // "General", "Language-specific", …
	Size     int64  `json:"size"`
	Words    int    `json:"words"`   // line count (exact, or estimated for huge files)
	WordsH   string `json:"words_h"` // humanized: "15.5M", "92k", "512"
	Approx   bool   `json:"approx"`  // Words is an estimate
	Gz       bool   `json:"gz"`
}

// wordlistSources maps a glob to a display group. Order matters (first match
// wins for the group label; dedupe on path).
var wordlistSources = []struct {
	glob, group string
}{
	{"/usr/share/wordlists/*.txt", "General"},
	{"/usr/share/wordlists/*.txt.gz", "General"},
	{"/usr/share/seclists/Passwords/Common-Credentials/Language-Specific/*.txt", "Language-specific"},
	{"/usr/share/seclists/Passwords/turk303k.txt", "Language-specific"},
	{"/usr/share/seclists/Passwords/*.txt", "SecLists / Passwords"},
	{"/usr/share/seclists/Passwords/Common-Credentials/*.txt", "SecLists / Common"},
	{"/usr/share/seclists/Passwords/Leaked-Databases/*.txt", "SecLists / Leaked DBs"},
}

// Wordlists enumerates common + language-specific wordlists on the host with
// their word (line) counts. Big files get a size-based estimate to keep the
// page snappy; results are cached per process.
func Wordlists() []WordlistOption {
	seen := map[string]bool{}
	var out []WordlistOption
	for _, src := range wordlistSources {
		matches, _ := filepath.Glob(src.glob)
		for _, p := range matches {
			if seen[p] {
				continue
			}
			seen[p] = true
			fi, err := os.Stat(p)
			if err != nil || fi.IsDir() {
				continue
			}
			words, approx := wordCount(p, fi.Size())
			wh := humanCount(words)
			if approx {
				wh = "~" + wh
			}
			out = append(out, WordlistOption{
				Path: p, Label: filepath.Base(p), Group: src.group,
				Size: fi.Size(), Words: words, WordsH: wh, Approx: approx, Gz: strings.HasSuffix(p, ".gz"),
			})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		ri, rj := strings.HasPrefix(out[i].Label, "rockyou"), strings.HasPrefix(out[j].Label, "rockyou")
		if ri != rj {
			return ri
		}
		if out[i].Group != out[j].Group {
			return out[i].Group < out[j].Group
		}
		return out[i].Label < out[j].Label
	})
	return out
}

var wcCache sync.Map // path -> [2]int{words, approxFlag}

// wordCount returns a wordlist's line count. Exact for files up to 25 MB
// (streamed, gzip-aware); larger plain files are estimated from size (~9
// bytes/line) to avoid multi-hundred-MB reads on page load. Cached per path.
func wordCount(path string, size int64) (int, bool) {
	if v, ok := wcCache.Load(path); ok {
		p := v.([2]int)
		return p[0], p[1] == 1
	}
	var words int
	var approx bool
	if size > 25<<20 {
		div := int64(9)
		if strings.HasSuffix(path, ".gz") {
			div = 3 // compressed → assume ~3x ratio then ~9 bytes/line
		}
		words = int(size / div)
		approx = true
	} else {
		words = countLinesExact(path)
		if words < 0 {
			words, approx = int(size/9), true
		}
	}
	flag := 0
	if approx {
		flag = 1
	}
	wcCache.Store(path, [2]int{words, flag})
	return words, approx
}

func countLinesExact(path string) int {
	f, err := os.Open(path)
	if err != nil {
		return -1
	}
	defer f.Close()
	var r = bufio.NewReaderSize(f, 256*1024)
	if strings.HasSuffix(path, ".gz") {
		gz, err := gzip.NewReader(f)
		if err != nil {
			return -1
		}
		defer gz.Close()
		r = bufio.NewReaderSize(gz, 256*1024)
	}
	buf := make([]byte, 256*1024)
	count := 0
	for {
		n, err := r.Read(buf)
		count += bytes.Count(buf[:n], []byte{'\n'})
		if err != nil {
			break
		}
	}
	return count
}

// RuleOption is a selectable hashcat rule file.
type RuleOption struct {
	Path   string `json:"path"`
	Label  string `json:"label"`
	Size   int64  `json:"size"`
	Famous bool   `json:"famous"`
}

// famousRules are surfaced first in the picker (whichever are present).
var famousRules = map[string]bool{
	"OneRuleToRuleThemAll.rule": true, "best64.rule": true, "best66.rule": true,
	"rockyou-30000.rule": true, "dive.rule": true, "d3ad0ne.rule": true,
	"T0XlC.rule": true, "T0XlCv2.rule": true, "generated2.rule": true,
	"leetspeak.rule": true, "combinator.rule": true, "toggles1.rule": true,
	"toggles3.rule": true, "toggles5.rule": true, "top10_2025.rule": true,
	"Incisive-leetspeak.rule": true,
}

// ruleSources are searched in order; the bundled dir ships famous community
// rules (OneRuleToRuleThemAll) that Kali's hashcat package omits.
var ruleSources = []string{
	"data/hashcat-rules/*.rule", // bundled with scaNNer (relative to the working dir)
	"/usr/share/hashcat/rules/*.rule",
}

// Rules enumerates rule files from the bundled dir + the system dir, famous first.
func Rules() []RuleOption {
	seen := map[string]bool{}
	var out []RuleOption
	for _, glob := range ruleSources {
		matches, _ := filepath.Glob(glob)
		for _, p := range matches {
			base := filepath.Base(p)
			if seen[base] {
				continue // same rule name from two dirs → first wins (bundled)
			}
			fi, err := os.Stat(p)
			if err != nil || fi.IsDir() {
				continue
			}
			seen[base] = true
			if abs, err := filepath.Abs(p); err == nil {
				p = abs // bundled rules are glob-relative; abs-resolve so -r works from any cwd
			}
			out = append(out, RuleOption{Path: p, Label: base, Size: fi.Size(), Famous: famousRules[base]})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Famous != out[j].Famous {
			return out[i].Famous
		}
		return out[i].Label < out[j].Label
	})
	return out
}
