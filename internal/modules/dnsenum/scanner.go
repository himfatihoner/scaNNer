package dnsenum

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"scanner/internal/modules/shared"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// dnsenumHTTPClient is the bounded client used for all external API calls
// (crt.sh, hackertarget, others). Audit S1: the previous package-level
// client used the stdlib default dialer, so killswitch L2 source-IP
// binding never applied to passive-DNS API calls. shared.BoundDialer
// reads SetGlobalLocalAddr at dial time so the pinned outbound iface is
// honored. Bounded transport keeps idle conn counts in check (audit B47).
var dnsenumHTTPClient = &http.Client{
	Timeout: 30 * time.Second,
	Transport: &http.Transport{
		MaxIdleConns:        20,
		MaxIdleConnsPerHost: 5,
		IdleConnTimeout:     60 * time.Second,
		DialContext:         shared.BoundDialer(nil, 10*time.Second).DialContext,
	},
}

// Options holds optional dnsenum extras the user can toggle from the form.
type Options struct {
	AXFR        bool   // attempt zone transfer against each authoritative NS
	ReverseDNS  bool   // reverse-DNS sweep across resolved IPs
	CrtSh       bool   // scrape crt.sh certificate-transparency logs
	ReverseCIDR string // newline/space/comma-separated IPs and/or CIDRs to sweep
	// Passive-source API keys — fetched from settings by the handler.
	// Each source contributes a subdomain list when its key is non-empty.
	// VirusTotal: domains/<d>/subdomains endpoint.
	// Shodan:     hostname:<d> facet enumeration.
	// Censys:     hosts search with auto-pagination.
	VirusTotalKey string
	ShodanKey     string
	CensysID      string
	CensysSecret  string
	// MaxDepth limits the discovered-subdomain depth relative to the
	// apex. depth=1 → only foo.example.com; depth=2 → foo.bar.example.com
	// also allowed; depth=0 → no limit (default).
	// Filter is applied AFTER enumeration so brute/passive sources still
	// have the full hit list internally — we just exclude rows that
	// exceed the user's depth preference from the output.
	MaxDepth int

	// Audit fix: surface concurrency knobs so operators can dial down
	// the DNS load on small / monitored / corporate resolvers. All three
	// fall back to sane defaults when 0 / unset.
	//   ResolveConcurrency caps the goroutine fan-out of the final
	//   per-subdomain resolve pass (default 50).
	//   BruteRateLimit overrides puredns' --rate-limit (qps). When 0,
	//   the legacy per-speed defaults are used.
	//   PTRConcurrency caps the reverse-DNS sweep fan-out (default 16).
	ResolveConcurrency int
	BruteRateLimit     int
	PTRConcurrency     int

	// WordlistPath, when non-empty, overrides the hard-coded seclists
	// path for the current speed profile. Audit fix: lets operators point
	// at a custom wordlist on non-Kali hosts, air-gapped systems, or
	// engagements with a bespoke wordlist. Empty falls back to the
	// per-speed WordlistFast/Normal/Deep defaults.
	WordlistPath string
}

// Speed profile
type Speed string

const (
	SpeedFast   Speed = "fast"   // small wordlist, all passive (subfinder+amass+crt.sh) + quick brute
	SpeedNormal Speed = "normal" // medium wordlist, all passive + recon-ng + brute + permutations
	SpeedDeep   Speed = "deep"   // large wordlist, all sources, NS brute, permutations
)

// PhaseCount is the number of sub-progress slots reserved per domain.
// The handler multiplies len(domains) by this when calling CreateScan so
// the progress bar can advance during a single-domain scan (passive →
// brute → NS-brute → permutation → resolve). Audit fix: without this the
// bar sat at 0/1 for an entire 30+ minute run.
const PhaseCount = 5

// Paths
var (
	ToolsDir     = "tools"
	DataDir      = "data"
	ResolverFile = "data/resolvers.txt"

	WordlistFast   = "/usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt"
	WordlistNormal = "/usr/share/seclists/Discovery/DNS/namelist.txt"
	WordlistDeep   = "/usr/share/seclists/Discovery/DNS/dns-Jhaddix.txt"
)

type SubdomainRecord struct {
	Subdomain string   `json:"subdomain"`
	IPs       []string `json:"ips,omitempty"`
	Source    string   `json:"source"`
	IsWild    bool     `json:"is_wild,omitempty"`
}

type DomainResult struct {
	Domain      string            `json:"domain"`
	Nameservers []string          `json:"nameservers"`
	Subdomains  []SubdomainRecord `json:"subdomains"`
	TotalFound  int               `json:"total_found"`
	Sources     map[string]int    `json:"sources"` // source -> count
	// SourceStates is the per-tool status board the UI renders: which
	// discovery sources ran, which are still running, which found how
	// many, and which failed/were skipped (and why). Kept in launch
	// order so the panel is stable across partial re-renders.
	SourceStates []SourceStatus `json:"source_states,omitempty"`
	Error        string         `json:"error,omitempty"`

	// Optional add-ons (populated only when the user enables the matching
	// checkbox in the form).
	AXFRRecords []AXFRRecord  `json:"axfr_records,omitempty"`
	ReverseDNS  []PTRRecord   `json:"reverse_dns,omitempty"`
	CrtShCerts  []CrtShRecord `json:"crtsh_certs,omitempty"`
}

// SourceStatus is one row in the per-tool status board. State is one of
// "running", "ok", "failed", or "skipped". Count is how many raw hits the
// source returned (before cross-source dedup); Message carries the failure
// reason or skip reason ("not installed", "no API key", "wordlist missing").
type SourceStatus struct {
	Name    string `json:"name"`
	State   string `json:"state"`
	Count   int    `json:"count"`
	Message string `json:"message,omitempty"`
}

// AXFRRecord captures a single record returned by a successful zone transfer.
type AXFRRecord struct {
	NS    string `json:"ns"`
	Name  string `json:"name"`
	Type  string `json:"type"`
	Value string `json:"value"`
}

// PTRRecord is one IP→hostname mapping from the reverse-DNS sweep.
type PTRRecord struct {
	IP       string `json:"ip"`
	Hostname string `json:"hostname"`
}

// CrtShRecord is one entry from crt.sh's CT log search.
type CrtShRecord struct {
	NameValue string `json:"name_value"`
	Issuer    string `json:"issuer,omitempty"`
	NotBefore string `json:"not_before,omitempty"`
	NotAfter  string `json:"not_after,omitempty"`
}

type ScanResult struct {
	Results []DomainResult `json:"results"`
}

type ProgressFunc func(done int, msg string)

// PartialFunc fires when each phase completes for live UI updates
type PartialFunc func(partial *ScanResult)

func Scan(ctx context.Context, domains []string, speed Speed, onPartial PartialFunc, progress ProgressFunc) *ScanResult {
	return ScanWithOpts(ctx, domains, speed, Options{}, onPartial, progress)
}

func ScanWithOpts(ctx context.Context, domains []string, speed Speed, opts Options, onPartial PartialFunc, progress ProgressFunc) *ScanResult {
	if ctx == nil {
		ctx = context.Background()
	}
	result := &ScanResult{}
	var mu sync.Mutex

	partialReport := func(currentDR *DomainResult) {
		if onPartial == nil {
			return
		}
		mu.Lock()
		snap := &ScanResult{Results: append([]DomainResult(nil), result.Results...)}
		if currentDR != nil {
			snap.Results = append(snap.Results, *currentDR)
		}
		mu.Unlock()
		onPartial(snap)
	}

	for i, domain := range domains {
		if ctx.Err() != nil {
			break
		}
		base := i * PhaseCount
		if progress != nil {
			progress(base, fmt.Sprintf("Enumerating %s (%s mode)", domain, speed))
		}
		// enumerateDomain reports finer-grained phase progress via the
		// closure: each major phase calls phaseProgress(step, msg) so the
		// scan bar advances within a single-domain run.
		phaseProgress := func(step int, msg string) {
			if progress == nil {
				return
			}
			if step < 0 {
				step = 0
			}
			if step > PhaseCount {
				step = PhaseCount
			}
			progress(base+step, msg)
		}
		dr := enumerateDomain(ctx, domain, speed, opts, func(msg string) {
			if progress != nil {
				progress(base, msg)
			}
		}, partialReport, phaseProgress)

		// Optional add-on phases (run after the main enum)
		logExtra := func(msg string) {
			if progress != nil {
				progress(base, msg)
			}
		}
		// crt.sh is now always queried in the passive phase (single
		// source of truth — see scrapeCrtSh call above). The CrtSh
		// checkbox now decides whether the cert metadata table is
		// rendered on the results page. When unchecked we drop the
		// CrtShCerts slice so the JSON payload stays compact.
		if !opts.CrtSh {
			dr.CrtShCerts = nil
		} else {
			partialReport(dr)
		}
		if opts.AXFR {
			logExtra("AXFR zone-transfer attempts...")
			dr.AXFRRecords = tryAXFR(ctx, domain, dr.Nameservers, logExtra)
			mergeAXFRAsSubdomains(dr)
			partialReport(dr)
		}
		if opts.ReverseDNS {
			logExtra("reverse DNS sweep...")
			dr.ReverseDNS = sweepReverseDNS(ctx, dr, opts.ReverseCIDR, opts.PTRConcurrency)
			partialReport(dr)
		}

		// Apply max-depth filter LAST so all sources have run unrestricted
		// (we want the brute/passive cache to see everything) but the user
		// only sees rows at-or-below their requested depth.
		if opts.MaxDepth > 0 {
			before := len(dr.Subdomains)
			filtered := make([]SubdomainRecord, 0, before)
			for _, s := range dr.Subdomains {
				if subdomainDepth(s.Subdomain, domain) <= opts.MaxDepth {
					filtered = append(filtered, s)
				}
			}
			dr.Subdomains = filtered
			dr.TotalFound = len(filtered)
			if progress != nil && before != len(filtered) {
				progress(base, fmt.Sprintf("Depth filter (≤%d): %d → %d subdomains", opts.MaxDepth, before, len(filtered)))
			}
		}

		mu.Lock()
		result.Results = append(result.Results, *dr)
		mu.Unlock()
		if progress != nil {
			progress((i+1)*PhaseCount, fmt.Sprintf("[%d/%d] %s — %d subdomains found", i+1, len(domains), domain, dr.TotalFound))
		}
		partialReport(nil)
	}
	return result
}

func enumerateDomain(ctx context.Context, domain string, speed Speed, scanOpts Options, logFn func(string), partialFn func(*DomainResult), phaseFn func(int, string)) *DomainResult {
	// phaseFn advances the progress bar between major phases. nil-safe
	// for backward compat with any internal caller; the Scan loop always
	// supplies it.
	if phaseFn == nil {
		phaseFn = func(int, string) {}
	}
	dr := &DomainResult{
		Domain:  domain,
		Sources: map[string]int{},
	}

	tmpDir, _ := os.MkdirTemp("", "dnsenum-*")
	defer os.RemoveAll(tmpDir)

	// ---- Phase 1: Discover authoritative nameservers ----
	logFn(fmt.Sprintf("[%s] Discovering nameservers...", domain))
	dr.Nameservers = getNameservers(ctx, domain)

	allSubs := map[string]string{} // subdomain -> first source
	var mu sync.Mutex

	collect := func(subs []string, source string) {
		mu.Lock()
		defer mu.Unlock()
		// Audit fix: Sources[source]++ was previously incremented on every
		// input line, which (a) double-counted duplicates within one
		// source's output, and (b) counted subs that an earlier source
		// already discovered. The Sources histogram in the UI showed raw
		// emitted lines, not unique first-sighting attribution. Increment
		// only when the sub is newly inserted into allSubs.
		seenLocal := map[string]bool{}
		for _, s := range subs {
			s = strings.TrimSpace(strings.ToLower(s))
			if s == "" || !strings.HasSuffix(s, "."+domain) && s != domain {
				continue
			}
			if seenLocal[s] {
				continue
			}
			seenLocal[s] = true
			if _, exists := allSubs[s]; !exists {
				allSubs[s] = source
				dr.Sources[source]++
			}
		}
	}

	// firePhase reports an intermediate snapshot after each major phase
	firePhase := func() {
		if partialFn == nil {
			return
		}
		snap := &DomainResult{
			Domain:      dr.Domain,
			Nameservers: append([]string(nil), dr.Nameservers...),
			Sources:     map[string]int{},
		}
		mu.Lock()
		for k, v := range dr.Sources {
			snap.Sources[k] = v
		}
		snap.SourceStates = append([]SourceStatus(nil), dr.SourceStates...)
		// Flatten all discovered subs so the UI can show progress during the passive phase
		for s, source := range allSubs {
			snap.Subdomains = append(snap.Subdomains, SubdomainRecord{Subdomain: s, Source: source})
		}
		mu.Unlock()
		snap.TotalFound = len(snap.Subdomains)
		sort.Slice(snap.Subdomains, func(i, j int) bool { return snap.Subdomains[i].Subdomain < snap.Subdomains[j].Subdomain })
		partialFn(snap)
	}

	// setSrc records/updates the status of one discovery source on dr in
	// launch order, then pushes a partial so the UI's status board updates
	// live. count < 0 leaves the previous count untouched (used for the
	// initial "running" mark before the tally is known). It fires a partial
	// itself, so callers don't need a separate firePhase() afterwards.
	srcIdx := map[string]int{}
	setSrc := func(name, state string, count int, msg string) {
		mu.Lock()
		i, ok := srcIdx[name]
		if !ok {
			i = len(dr.SourceStates)
			srcIdx[name] = i
			dr.SourceStates = append(dr.SourceStates, SourceStatus{Name: name})
		}
		dr.SourceStates[i].State = state
		if count >= 0 {
			dr.SourceStates[i].Count = count
		}
		dr.SourceStates[i].Message = msg
		mu.Unlock()
		firePhase()
	}
	// runSource is the standard wrapper for a discovery source: mark it
	// running, run fn, collect its hits, then mark ok/failed. When
	// subprocess is true and the tool binary is absent it short-circuits to
	// "skipped: not installed" without spawning anything. A tool that
	// errored but still returned some hits is treated as ok (partial).
	runSource := func(name string, subprocess bool, fn func() ([]string, error)) {
		if subprocess && !toolInstalled(name) {
			setSrc(name, "skipped", 0, "kurulu değil (not installed)")
			collect(nil, name)
			logFn(fmt.Sprintf("[%s] %s: skipped (kurulu değil)", domain, name))
			return
		}
		setSrc(name, "running", -1, "")
		subs, err := fn()
		collect(subs, name)
		n := len(subs)
		if err != nil && n == 0 {
			reason := err.Error()
			setSrc(name, "failed", 0, reason)
			logFn(fmt.Sprintf("[%s] %s: FAILED — %s", domain, name, reason))
		} else {
			setSrc(name, "ok", n, "")
			logFn(fmt.Sprintf("[%s] %s: %d results", domain, name, n))
		}
	}

	// ---- Phase 2: Passive sources (concurrent) ----
	var wg sync.WaitGroup

	// Subfinder
	wg.Add(1)
	go func() {
		defer wg.Done()
		logFn(fmt.Sprintf("[%s] Running subfinder...", domain))
		runSource("subfinder", true, func() ([]string, error) {
			return runSubfinder(ctx, domain, tmpDir, logFn)
		})
	}()

	// Amass passive — runs in ALL modes. On large targets (e.g. example.com)
	// amass + crt.sh + brute together are what produce the full result set
	// (~1800 subdomains). It's bounded by its own -timeout (see runAmass) and a
	// tight context cap so it can't run away; removing it just to shave time
	// gutted the results, which was the wrong trade.
	wg.Add(1)
	go func() {
		defer wg.Done()
		logFn(fmt.Sprintf("[%s] Running amass (passive)...", domain))
		runSource("amass", true, func() ([]string, error) {
			return runAmass(ctx, domain, tmpDir, speed, logFn)
		})
	}()

	// Certificate Transparency (via crt.sh).
	// Audit fix: previously fired queryCrtSh (shell-out curl, fragile
	// JSON-by-string-split) here AND scrapeCrtSh (Go HTTP, real JSON
	// unmarshal) again in the post-enum extras when opts.CrtSh was on.
	// That double-hit crt.sh per domain and made killswitch coverage
	// asymmetric. Single source of truth now: scrapeCrtSh runs once,
	// populates dr.CrtShCerts, and feeds the subdomain list via
	// mergeCrtShAsSubdomains. The opt-in CrtSh checkbox now controls
	// only whether the CrtShCerts metadata table is preserved on dr.
	wg.Add(1)
	go func() {
		defer wg.Done()
		logFn(fmt.Sprintf("[%s] Querying certificate transparency...", domain))
		setSrc("crt.sh", "running", -1, "")
		certs := scrapeCrtSh(ctx, domain)
		// Extract unique hostnames from the cert records.
		seen := map[string]bool{}
		var subs []string
		for _, c := range certs {
			name := strings.ToLower(strings.TrimSpace(c.NameValue))
			if name == "" || seen[name] {
				continue
			}
			seen[name] = true
			subs = append(subs, name)
		}
		collect(subs, "crt.sh")
		// Stash certs on dr — Scan() at the call site will keep or drop
		// CrtShCerts based on the opts.CrtSh toggle.
		mu.Lock()
		dr.CrtShCerts = certs
		mu.Unlock()
		// crt.sh is HTTP, not a subprocess: no "not installed" case. A zero
		// return usually means the API rate-limited or timed out rather than
		// a genuine empty set, so flag that instead of a bare "0".
		if len(subs) == 0 && ctx.Err() == nil {
			setSrc("crt.sh", "failed", 0, "yanıt yok / rate-limit (crt.sh)")
		} else {
			setSrc("crt.sh", "ok", len(subs), "")
		}
		logFn(fmt.Sprintf("[%s] crt.sh: %d results", domain, len(subs)))
	}()

	// Recon-ng
	if speed != SpeedFast {
		wg.Add(1)
		go func() {
			defer wg.Done()
			logFn(fmt.Sprintf("[%s] Running recon-ng...", domain))
			runSource("recon-ng", true, func() ([]string, error) {
				return runReconNG(ctx, domain, tmpDir, logFn)
			})
		}()
	}

	// External API passive sources — only fire when the user has
	// supplied credentials in Settings. Three independent goroutines
	// so a slow API doesn't block the rest of discovery.
	if scanOpts.VirusTotalKey != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			logFn(fmt.Sprintf("[%s] Querying VirusTotal...", domain))
			runSource("virustotal", false, func() ([]string, error) {
				return queryVirusTotal(ctx, domain, scanOpts.VirusTotalKey), nil
			})
		}()
	}
	if scanOpts.ShodanKey != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			logFn(fmt.Sprintf("[%s] Querying Shodan...", domain))
			runSource("shodan", false, func() ([]string, error) {
				return queryShodan(ctx, domain, scanOpts.ShodanKey), nil
			})
		}()
	}
	if scanOpts.CensysID != "" && scanOpts.CensysSecret != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			logFn(fmt.Sprintf("[%s] Querying Censys...", domain))
			runSource("censys", false, func() ([]string, error) {
				return queryCensys(ctx, domain, scanOpts.CensysID, scanOpts.CensysSecret), nil
			})
		}()
	}

	wg.Wait()
	logFn(fmt.Sprintf("[%s] Passive phase done: %d unique subdomains", domain, len(allSubs)))
	firePhase()
	phaseFn(1, fmt.Sprintf("[%s] Passive phase done — %d subs", domain, len(allSubs)))

	if ctx.Err() != nil {
		return dr
	}

	// ---- Phase 3: Active brute-force with puredns + massdns ----
	wordlist := WordlistFast
	switch speed {
	case SpeedNormal:
		wordlist = WordlistNormal
	case SpeedDeep:
		wordlist = WordlistDeep
	}
	// Audit fix: honour operator-supplied wordlist override. Skips the
	// per-speed default entirely so a custom list works even off-Kali.
	if strings.TrimSpace(scanOpts.WordlistPath) != "" {
		wordlist = strings.TrimSpace(scanOpts.WordlistPath)
	}

	// Audit fix: warn loudly if the seclists wordlist is missing.
	// puredns silently exits with zero hits when the wordlist file is
	// absent — the operator just sees "0 subdomains from puredns" with
	// no indication that the brute phase never actually ran. Common on
	// non-Kali hosts / fresh Docker / scope where `seclists` wasn't
	// installed.
	var bruteSubs []string
	if _, err := os.Stat(wordlist); err != nil {
		logFn(fmt.Sprintf("[%s] $ # wordlist missing: %s — skipping brute-force phase (install seclists to enable)", domain, wordlist))
		setSrc("puredns", "skipped", 0, "wordlist yok: "+wordlist)
	} else if !toolInstalled("puredns") {
		setSrc("puredns", "skipped", 0, "kurulu değil (not installed)")
	} else if !toolInstalled("massdns") {
		setSrc("puredns", "skipped", 0, "massdns kurulu değil (puredns onu çağırır)")
	} else {
		logFn(fmt.Sprintf("[%s] Brute-forcing with global resolvers...", domain))
		setSrc("puredns", "running", -1, "")
		var bErr error
		bruteSubs, bErr = runPureDNS(ctx, domain, wordlist, ResolverFile, tmpDir, speed, scanOpts.BruteRateLimit, logFn)
		if bErr != nil && len(bruteSubs) == 0 && ctx.Err() == nil {
			setSrc("puredns", "failed", 0, bErr.Error())
		} else {
			setSrc("puredns", "ok", len(bruteSubs), "")
		}
	}
	collect(bruteSubs, "puredns")
	logFn(fmt.Sprintf("[%s] puredns brute: %d results", domain, len(bruteSubs)))
	firePhase()
	phaseFn(2, fmt.Sprintf("[%s] Brute-force done — %d new subs", domain, len(bruteSubs)))

	if ctx.Err() != nil {
		return dr
	}

	// ---- Phase 4: NS-specific brute-force (query each authoritative NS separately) ----
	if speed != SpeedFast && len(dr.Nameservers) > 0 {
		logFn(fmt.Sprintf("[%s] Brute-forcing via %d authoritative nameservers...", domain, len(dr.Nameservers)))

		// Build a focused wordlist from passive results (extract prefixes) + small static list
		nsWordlist := buildNSWordlist(allSubs, domain, tmpDir)

		for _, ns := range dr.Nameservers {
			if ctx.Err() != nil {
				break
			}
			nsIP := resolveNS(ctx, ns)
			if nsIP == "" {
				continue
			}
			logFn(fmt.Sprintf("[%s] Querying NS %s (%s)...", domain, ns, nsIP))
			nsSubs := bruteWithNS(ctx, domain, nsIP, nsWordlist, speed)
			collect(nsSubs, "ns:"+ns)
			logFn(fmt.Sprintf("[%s] NS %s: %d results", domain, ns, len(nsSubs)))
			firePhase()
		}
	}
	phaseFn(3, fmt.Sprintf("[%s] NS-brute done", domain))

	if ctx.Err() != nil {
		return dr
	}

	// ---- Phase 4b: altdns-style permutations on discovered subdomains ----
	// Take everything passive+brute already found and mutate it with
	// common SaaS/staging suffixes & prefixes (api-staging, dev-www,
	// www2, www-old, etc.). Often resurfaces forgotten environments
	// that the wordlist alone missed. Only runs on normal+deep —
	// fast mode would slow down too much for the extra value.
	if speed != SpeedFast && len(allSubs) > 0 {
		baseSet := make([]string, 0, len(allSubs))
		mu.Lock()
		for s := range allSubs {
			baseSet = append(baseSet, s)
		}
		mu.Unlock()
		permList := generatePermutations(baseSet, domain)
		logFn(fmt.Sprintf("[%s] Generating %d permutations (altdns-style)...", domain, len(permList)))
		if len(permList) > 0 {
			permFile := filepath.Join(tmpDir, "permutations.txt")
			_ = os.WriteFile(permFile, []byte(strings.Join(permList, "\n")), 0644)
			setSrc("permutation", "running", -1, "")
			permSubs, permErr := runPureDNS(ctx, domain, permFile, ResolverFile, tmpDir, speed, scanOpts.BruteRateLimit, logFn)
			collect(permSubs, "permutation")
			if permErr != nil && len(permSubs) == 0 && ctx.Err() == nil {
				setSrc("permutation", "failed", 0, permErr.Error())
			} else {
				setSrc("permutation", "ok", len(permSubs), "")
			}
			logFn(fmt.Sprintf("[%s] permutations: %d new live subdomains", domain, len(permSubs)))
			firePhase()
		}
	}
	phaseFn(4, fmt.Sprintf("[%s] Permutations done", domain))

	if ctx.Err() != nil {
		return dr
	}

	// ---- Phase 5: Resolve all found subdomains ----
	logFn(fmt.Sprintf("[%s] Resolving %d subdomains...", domain, len(allSubs)))
	wildcard := detectWildcard(ctx, domain)

	var records []SubdomainRecord
	subList := make([]string, 0, len(allSubs))
	for s := range allSubs {
		subList = append(subList, s)
	}
	sort.Strings(subList)

	resolveConc := scanOpts.ResolveConcurrency
	if resolveConc <= 0 {
		resolveConc = 50
	}
	sem := make(chan struct{}, resolveConc)
	var recMu sync.Mutex
	var wg2 sync.WaitGroup

	for _, sub := range subList {
		if ctx.Err() != nil {
			break
		}
		wg2.Add(1)
		sem <- struct{}{}
		go func(s, source string) {
			defer wg2.Done()
			defer func() { <-sem }()
			if ctx.Err() != nil {
				return
			}
			ips := resolveHost(ctx, s)
			isWild := false
			if wildcard != "" && len(ips) == 1 && ips[0] == wildcard {
				isWild = true
			}
			recMu.Lock()
			records = append(records, SubdomainRecord{
				Subdomain: s,
				IPs:       ips,
				Source:    source,
				IsWild:    isWild,
			})
			recMu.Unlock()
		}(sub, allSubs[sub])
	}
	wg2.Wait()

	sort.Slice(records, func(i, j int) bool {
		return records[i].Subdomain < records[j].Subdomain
	})

	dr.Subdomains = records
	dr.TotalFound = len(records)
	return dr
}

// --- Tool runners ---

func runSubfinder(parent context.Context, domain, tmpDir string, log func(string)) ([]string, error) {
	// Bail before spawning if parent already cancelled (audit B59).
	if parent.Err() != nil {
		return nil, parent.Err()
	}
	out := filepath.Join(tmpDir, "subfinder.txt")
	ctx, cancel := context.WithTimeout(parent, 3*time.Minute)
	defer cancel()
	// -all enables every data source (not just the fast default set) — this is
	// the single biggest lever on subfinder's yield and what restores the old
	// ~1800-result runs. Sources that need an API key are skipped gracefully
	// when no key is configured, so -all is safe with an empty config.
	args := []string{"-d", domain, "-o", out, "-silent", "-all"}
	if log != nil {
		log("$ " + shared.FormatCommand("subfinder", args))
	}
	cmd := shared.Command(ctx, toolPath("subfinder"), args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	err := cmd.Run()
	subs := readLines(out)
	return subs, toolErr(err, stderr.String())
}

// amassBinary resolves the amass executable, preferring the real Go binary
// over Kali/Debian's /usr/bin/amass wrapper script. That wrapper front-runs
// amass with:
//
//	if [ ! -e /usr/share/libpostal/transliteration ]; then
//	    sudo libpostal_data download all /var/lib/libpostal
//	fi
//
// Under a non-interactive service (systemd, no tty, no NOPASSWD) that sudo
// can't be answered, so `set -e` aborts the wrapper with "sudo: a password is
// required" BEFORE the real amass ever runs — silently zeroing amass's
// contribution to the enum (the ~350-subdomain regression this fixes). The
// libpostal model data is only used for name-alteration, which passive enum
// doesn't touch, so calling the binary directly is safe. Non-Debian hosts
// where amass is a plain binary fall through to the PATH lookup unchanged.
func amassBinary() string {
	if _, err := os.Stat("/usr/lib/amass/amass"); err == nil {
		return "/usr/lib/amass/amass"
	}
	return toolPath("amass")
}

var (
	amassMajorOnce sync.Once
	amassMajorVal  int // 0 = undetermined → treat as modern (v4+)
)

// amassMajor returns amass's major version (5 for v5.1.1), cached for the
// process. 0 means it couldn't be parsed — callers treat that as "modern"
// (v4+ CLI) since v3 is effectively extinct. Probed via `amass -version`,
// which prints e.g. "v5.1.1" and makes no network calls.
func amassMajor(parent context.Context) int {
	amassMajorOnce.Do(func() {
		ctx, cancel := context.WithTimeout(parent, 5*time.Second)
		defer cancel()
		out, _ := shared.Command(ctx, amassBinary(), "-version").CombinedOutput()
		if m := regexp.MustCompile(`v(\d+)\.`).FindSubmatch(out); m != nil {
			amassMajorVal, _ = strconv.Atoi(string(m[1]))
		}
	})
	return amassMajorVal
}

// harvestAmass scoops every hostname under the target domain out of whatever
// amass produced — each file in its output dir (v4+ -oA writes .txt and .json;
// the exact suffix has drifted across versions) plus its stdout. Regex + dedup
// makes it robust to format and to which channel the names actually land in.
func harvestAmass(dir string, stdout []byte, domain string) []string {
	re := regexp.MustCompile(`(?i)(?:[a-z0-9_*-]+\.)+` + regexp.QuoteMeta(domain))
	seen := map[string]bool{}
	var subs []string
	scan := func(b []byte) {
		for _, m := range re.FindAll(b, -1) {
			s := strings.ToLower(strings.Trim(string(m), ". "))
			if s == "" || seen[s] {
				continue
			}
			seen[s] = true
			subs = append(subs, s)
		}
	}
	scan(stdout)
	if entries, err := os.ReadDir(dir); err == nil {
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			if b, err := os.ReadFile(filepath.Join(dir, e.Name())); err == nil {
				scan(b)
			}
		}
	}
	return subs
}

func runAmass(parent context.Context, domain, tmpDir string, speed Speed, log func(string)) ([]string, error) {
	if parent.Err() != nil {
		return nil, parent.Err()
	}
	timeout := "2"
	hardCap := 5 * time.Minute
	if speed == SpeedDeep {
		timeout = "6"
		hardCap = 12 * time.Minute
	}
	// amass v4+ dropped -o in favour of -oA <prefix> and — unlike v3 — flushes
	// its output files only on a clean exit (its own -timeout firing, not our
	// SIGKILL). So: give it its own dir, budget enough headroom above -timeout
	// for the graceful exit to land, and harvest whatever it wrote. -passive is
	// the default in v5 (still accepted, a no-op) and required by v3, so keep
	// it. The hardCap is a touch higher than v3's since v5 also DNS-resolves
	// the names it discovers, which takes longer.
	ctx, cancel := context.WithTimeout(parent, hardCap)
	defer cancel()

	outDir := filepath.Join(tmpDir, "amassout")
	_ = os.MkdirAll(outDir, 0o755)
	outFlag, outVal := "-oA", filepath.Join(outDir, "amass")
	if v := amassMajor(parent); v >= 1 && v < 4 {
		outFlag, outVal = "-o", filepath.Join(outDir, "amass.txt")
	}
	args := []string{"enum", "-passive", "-d", domain, outFlag, outVal, "-timeout", timeout, "-nocolor"}
	if log != nil {
		log("$ " + shared.FormatCommand("amass", args))
	}
	cmd := shared.Command(ctx, amassBinary(), args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()

	subs := harvestAmass(outDir, stdout.Bytes(), domain)
	// Only surface an error when amass gave us nothing — a non-zero exit with
	// results (e.g. it hit our hardCap after already writing files) is still a
	// win, and the status board should show ok, not failed.
	if len(subs) == 0 && err != nil {
		return nil, fmt.Errorf("%s", amassFailReason(ctx, stderr.String()))
	}
	return subs, nil
}

// amassFailReason produces a clean status-board message when amass yielded
// nothing. amass v5 redraws a progress bar on stderr with carriage returns, so
// the raw last line is meaningless noise ("0 / 1 [___] 0.00% ? p/s"); strip it.
// A hard-cap kill is the common failure since amass v5 flushes output only on a
// clean exit — a kill means it never wrote anything — so name that explicitly.
func amassFailReason(ctx context.Context, stderr string) string {
	if ctx.Err() == context.DeadlineExceeded {
		return "zaman aşımı — amass v5 süre dolmadan sonuç yazamadı (yavaş: bulduğu isimleri DNS ile çözüyor)"
	}
	msg := ""
	for _, ln := range strings.Split(strings.ReplaceAll(stderr, "\r", "\n"), "\n") {
		ln = strings.TrimSpace(ln)
		if ln == "" || strings.Contains(ln, "p/s") || (strings.Contains(ln, "%") && strings.Contains(ln, "[")) {
			continue // progress-bar redraw noise, not a real message
		}
		msg = ln
	}
	if msg == "" {
		msg = "sonuç yok"
	}
	if len(msg) > 180 {
		msg = msg[:180] + "…"
	}
	return msg
}

// validDomainLabel returns true only for strings that look like a DNS
// domain (labels separated by dots, each label LDH per RFC 1123). Used
// as an injection guard before interpolating user-supplied domains into
// recon-ng resource files / subprocess argv.
func validDomainLabel(s string) bool {
	if s == "" || len(s) > 253 {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if label == "" || len(label) > 63 {
			return false
		}
		for i, r := range label {
			ok := (r >= 'a' && r <= 'z') ||
				(r >= 'A' && r <= 'Z') ||
				(r >= '0' && r <= '9') ||
				(r == '-' && i > 0 && i < len(label)-1)
			if !ok {
				return false
			}
		}
	}
	return true
}

// reconNGBootstrapOnce guards the marketplace install for the entire
// process lifetime. Audit fix: previously every scan re-ran
// `marketplace install ...` which hit GitHub (fails on air-gapped hosts)
// and slowed down every recon-ng phase by 3-15 seconds. Now the install
// runs once per process; subsequent scans skip straight to the query.
var reconNGBootstrapOnce sync.Once

func runReconNG(parent context.Context, domain, tmpDir string, log func(string)) ([]string, error) {
	out := filepath.Join(tmpDir, "reconng.txt")

	// Audit fix: domain flowed straight into the recon-ng resource-file
	// without validation. A submitted domain containing a newline could
	// inject extra recon-ng commands (e.g. `\nexec sh -c '...' \n`).
	// Reject anything that isn't a plain DNS-safe label sequence.
	if !validDomainLabel(domain) {
		return nil, fmt.Errorf("geçersiz alan adı: %q", domain)
	}

	// One-time marketplace bootstrap. Best-effort; if it fails (offline,
	// GitHub rate-limit, etc.) recon-ng will just error on `use ...`
	// downstream and the scan continues with the other passive sources.
	reconNGBootstrapOnce.Do(func() {
		bootstrapRC := filepath.Join(tmpDir, "reconng_bootstrap.rc")
		_ = os.WriteFile(bootstrapRC, []byte(
			"marketplace install recon/domains-hosts/hackertarget\n"+
				"marketplace install recon/domains-hosts/threatminer\n"+
				"exit\n"), 0644)
		bctx, bcancel := context.WithTimeout(parent, 60*time.Second)
		defer bcancel()
		if log != nil {
			log("$ " + shared.FormatCommand("recon-ng", []string{"-r", bootstrapRC}))
		}
		_ = shared.Command(bctx, "recon-ng", "-r", bootstrapRC).Run()
	})

	// Build recon-ng commands.
	// Audit fix: append `workspaces remove tmp_<domain>` at the end so
	// the temporary workspace doesn't accumulate on disk under
	// ~/.recon-ng/workspaces/ across runs. Marketplace install is now
	// bootstrapped once per process (see reconNGBootstrapOnce above), so
	// the per-scan resource file only contains the query pipeline.
	wsName := strings.ReplaceAll(domain, ".", "_")
	commands := fmt.Sprintf(`
workspaces create tmp_%s
db insert domains domain=%s
use recon/domains-hosts/hackertarget
run
use recon/domains-hosts/threatminer
run
show hosts
workspaces remove tmp_%s
exit
`, wsName, domain, wsName)

	cmdFile := filepath.Join(tmpDir, "reconng_cmds.rc")
	os.WriteFile(cmdFile, []byte(commands), 0644)

	ctx, cancel := context.WithTimeout(parent, 3*time.Minute)
	defer cancel()
	if log != nil {
		log("$ " + shared.FormatCommand("recon-ng", []string{"-r", cmdFile}))
	}
	cmd := shared.Command(ctx, "recon-ng", "-r", cmdFile)
	output, runErr := cmd.CombinedOutput()

	// Parse "show hosts" output for hostnames
	var subs []string
	for _, line := range strings.Split(string(output), "\n") {
		line = strings.TrimSpace(line)
		if strings.Contains(line, domain) && !strings.HasPrefix(line, "-") && !strings.HasPrefix(line, "+") {
			parts := strings.Fields(line)
			for _, p := range parts {
				p = strings.TrimSpace(p)
				if strings.HasSuffix(p, "."+domain) || p == domain {
					subs = append(subs, p)
				}
			}
		}
	}

	os.WriteFile(out, []byte(strings.Join(subs, "\n")), 0644)
	if len(subs) == 0 && runErr != nil {
		return subs, toolErr(runErr, string(output))
	}
	return subs, nil
}

func runPureDNS(parent context.Context, domain, wordlist, resolverFile, tmpDir string, speed Speed, rateOverride int, log func(string)) ([]string, error) {
	// Audit B59: skip the (very slow) puredns brute if cancel already
	// fired. Without the guard a cancelled scan was forced to wait up
	// to 20 minutes for the puredns subprocess timeout to elapse.
	if parent.Err() != nil {
		return nil, parent.Err()
	}
	out := filepath.Join(tmpDir, "puredns.txt")
	massdnsPath := toolPath("massdns")
	purednsBin := toolPath("puredns")
	// puredns delegates the actual resolution to massdns; if massdns is
	// absent the brute silently yields nothing. Surface that as a clear
	// failure instead of a mysterious "0 results".
	if !toolInstalled("massdns") {
		return nil, fmt.Errorf("massdns kurulu değil (puredns onu çağırır)")
	}

	// Audit fix: caller can override the per-speed default via Options
	// (rateOverride > 0). Honors the operator's "go gentle on this
	// resolver" preference set in the form/Settings.
	rateLimit := "300"
	if speed == SpeedFast {
		rateLimit = "500"
	} else if speed == SpeedDeep {
		rateLimit = "200"
	}
	if rateOverride > 0 {
		rateLimit = fmt.Sprintf("%d", rateOverride)
	}

	ctx, cancel := context.WithTimeout(parent, 20*time.Minute)
	defer cancel()
	args := []string{
		"bruteforce", wordlist, domain,
		"--resolvers", resolverFile,
		"--bin", massdnsPath,
		"--rate-limit", rateLimit,
		"--wildcard-tests", "15",
		"-w", out,
		"--quiet",
	}
	if log != nil {
		log("$ " + shared.FormatCommand("puredns", args))
	}
	cmd := shared.Command(ctx, purednsBin, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	err := cmd.Run()
	subs := readLines(out)
	return subs, toolErr(err, stderr.String())
}

// bruteWithNS brute-forces subdomains using a specific nameserver
func bruteWithNS(parent context.Context, domain, nsIP, wordlistPath string, speed Speed) []string {
	words := readLines(wordlistPath)
	var found []string
	var mu sync.Mutex

	conc := 20
	if speed == SpeedDeep {
		conc = 10 // slower but more thorough against auth NS
	}
	sem := make(chan struct{}, conc)
	var wg sync.WaitGroup

	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			// Custom resolver dialer — must obey the killswitch too,
			// otherwise DNS brute traffic would route via system default
			// even when -e tun0 is set everywhere else.
			// Audit fix: use net.JoinHostPort so an IPv6 NS address (e.g.
			// "2606:4700::1") gets bracketed correctly. Previously
			// nsIP+":53" produced an unparseable address for IPv6 NS,
			// silently failing every brute lookup.
			d := shared.BoundDialer(nil, 3*time.Second)
			return d.DialContext(ctx, "udp", net.JoinHostPort(nsIP, "53"))
		},
	}

	for _, w := range words {
		if parent.Err() != nil {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(word string) {
			defer wg.Done()
			defer func() { <-sem }()
			if parent.Err() != nil {
				return
			}
			fqdn := word + "." + domain
			ctx, cancel := context.WithTimeout(parent, 5*time.Second)
			defer cancel()
			ips, err := resolver.LookupHost(ctx, fqdn)
			if err == nil && len(ips) > 0 {
				mu.Lock()
				found = append(found, fqdn)
				mu.Unlock()
			}
		}(w)
	}
	wg.Wait()
	return found
}

// buildNSWordlist creates a focused wordlist from discovered subdomains + top words
func buildNSWordlist(allSubs map[string]string, domain string, tmpDir string) string {
	words := map[string]bool{}

	// Extract prefixes from passive results
	suffix := "." + domain
	for sub := range allSubs {
		if strings.HasSuffix(sub, suffix) {
			prefix := strings.TrimSuffix(sub, suffix)
			parts := strings.Split(prefix, ".")
			for _, p := range parts {
				if p != "" {
					words[p] = true
				}
			}
		}
	}

	// Add common short list
	common := []string{"www", "mail", "ftp", "cpanel", "webmail", "admin", "api", "dev", "staging", "test",
		"beta", "app", "m", "ns1", "ns2", "ns3", "dns", "mx", "smtp", "pop", "imap", "vpn", "remote",
		"portal", "shop", "store", "blog", "news", "support", "help", "docs", "cdn", "static", "media",
		"img", "images", "assets", "git", "svn", "jenkins", "ci", "jira", "wiki", "confluence",
		"grafana", "monitor", "status", "sso", "auth", "login", "secure", "gateway", "proxy",
		"internal", "intranet", "extranet", "staging2", "uat", "qa", "prod", "backup", "db",
		"mysql", "postgres", "redis", "elastic", "kibana", "prometheus", "k8s", "kube",
	}
	for _, w := range common {
		words[w] = true
	}

	path := filepath.Join(tmpDir, "ns_wordlist.txt")
	var lines []string
	for w := range words {
		lines = append(lines, w)
	}
	sort.Strings(lines)
	os.WriteFile(path, []byte(strings.Join(lines, "\n")), 0644)
	return path
}

// --- Helpers ---

// boundResolver is a Go-native resolver whose UDP/TCP dialer obeys the
// killswitch source-IP binding. Used by getNameservers / resolveNS /
// detectWildcard so DNS lookups (a) honor context cancellation and (b)
// stay on the pinned outbound iface. Audit fix: the previous helpers
// called net.LookupNS / net.LookupHost (no ctx, system resolver) — a
// cancelled scan blocked until each system query timed out (up to 30s),
// and cgo system-resolver bypassed shared.SetGlobalLocalAddr entirely.
var boundResolver = &net.Resolver{
	PreferGo: true,
	Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
		d := shared.BoundDialer(nil, 3*time.Second)
		return d.DialContext(ctx, network, address)
	},
}

func getNameservers(parent context.Context, domain string) []string {
	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
	defer cancel()
	nss, err := boundResolver.LookupNS(ctx, domain)
	if err != nil {
		return nil
	}
	var result []string
	for _, ns := range nss {
		result = append(result, strings.TrimSuffix(ns.Host, "."))
	}
	return result
}

func resolveNS(parent context.Context, ns string) string {
	ctx, cancel := context.WithTimeout(parent, 3*time.Second)
	defer cancel()
	ips, err := boundResolver.LookupHost(ctx, ns)
	if err != nil || len(ips) == 0 {
		return ""
	}
	// Prefer the first IPv4 entry — bruteWithNS uses the result as a
	// dial target, and an IPv6-only NS would just fail the lookup.
	for _, ip := range ips {
		if parsed := net.ParseIP(ip); parsed != nil && parsed.To4() != nil {
			return ip
		}
	}
	return ips[0]
}

func resolveHost(parent context.Context, host string) []string {
	ctx, cancel := context.WithTimeout(parent, 3*time.Second)
	defer cancel()
	ips, err := boundResolver.LookupHost(ctx, host)
	if err != nil {
		return nil
	}
	return ips
}

func detectWildcard(parent context.Context, domain string) string {
	ctx, cancel := context.WithTimeout(parent, 3*time.Second)
	defer cancel()
	random := "xz9q7k3m2p." + domain
	ips, err := boundResolver.LookupHost(ctx, random)
	if err != nil || len(ips) == 0 {
		return ""
	}
	return ips[0]
}

func toolPath(name string) string {
	// Check project tools dir first
	p := filepath.Join(ToolsDir, name)
	if _, err := os.Stat(p); err == nil {
		return p
	}
	// Fall back to PATH
	if path, err := exec.LookPath(name); err == nil {
		return path
	}
	return name
}

// Audit B79: cache resolved tool paths per process. exec.LookPath stat's
// every PATH entry on every call — for a 4-tool dnsenum (subfinder,
// amass, puredns, massdns) running per-domain in a 1000-target scan
// that's 4000 redundant syscalls. The cache also lets us log the
// resolved path once at startup so the operator can verify which
// version is in use.
var (
	toolPathCache   = map[string]string{}
	toolPathCacheMu sync.Mutex
)

// CachedToolPath returns the resolved path for `name`, looking it up in
// ToolsDir then PATH the first time and reusing the result thereafter.
// Safe under concurrency.
func CachedToolPath(name string) string {
	toolPathCacheMu.Lock()
	defer toolPathCacheMu.Unlock()
	if p, ok := toolPathCache[name]; ok {
		return p
	}
	p := toolPath(name)
	toolPathCache[name] = p
	return p
}

// toolInstalled reports whether `name` resolves to a real binary — either in
// the repo-local tools/ dir or somewhere on $PATH. toolPath returns the bare
// name (unchanged) only when neither lookup succeeded, so a resolved path that
// differs from the input means the tool is present. This is what lets the
// status board distinguish "skipped: not installed" from "ran, found 0".
func toolInstalled(name string) bool {
	return CachedToolPath(name) != name
}

// toolErr condenses a subprocess failure into a short, user-facing reason for
// the status board. Returns "" when err is nil (success). Prefers the last
// non-empty line of stderr (where CLIs put the actual message) over the
// generic "exit status N", and normalises the common "not found" case.
func toolErr(err error, stderr string) error {
	if err == nil {
		return nil
	}
	if strings.Contains(err.Error(), "executable file not found") {
		return fmt.Errorf("kurulu değil (not installed)")
	}
	msg := ""
	for _, ln := range strings.Split(stderr, "\n") {
		if ln = strings.TrimSpace(ln); ln != "" {
			msg = ln
		}
	}
	if msg == "" {
		msg = err.Error()
	}
	if len(msg) > 180 {
		msg = msg[:180] + "…"
	}
	return fmt.Errorf("%s", msg)
}

func readLines(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var lines []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line != "" {
			lines = append(lines, line)
		}
	}
	return lines
}

// --- Optional add-on phases ---

// tryAXFR attempts a zone transfer via `dig axfr` against each authoritative NS.
// Most providers refuse (REFUSED), but it's quick and occasionally hits gold.
func tryAXFR(ctx context.Context, domain string, nameservers []string, log func(string)) []AXFRRecord {
	var out []AXFRRecord
	if _, err := exec.LookPath("dig"); err != nil {
		return out
	}
	if len(nameservers) == 0 {
		nsCtx, nsCancel := context.WithTimeout(ctx, 5*time.Second)
		nss, _ := boundResolver.LookupNS(nsCtx, domain)
		nsCancel()
		for _, ns := range nss {
			nameservers = append(nameservers, strings.TrimSuffix(ns.Host, "."))
		}
	}
	for _, ns := range nameservers {
		ns = strings.TrimSuffix(strings.TrimSpace(ns), ".")
		if ns == "" {
			continue
		}
		digArgs := []string{"+nocmd", "+noall", "+answer", "+time=4", "+tries=1", "@" + ns, "axfr", domain}
		if log != nil {
			log("$ " + shared.FormatCommand("dig", digArgs))
		}
		cmd := shared.Command(ctx, "dig", digArgs...)
		raw, _ := cmd.Output()
		text := strings.TrimSpace(string(raw))
		if text == "" || strings.Contains(strings.ToLower(text), "transfer failed") || strings.Contains(strings.ToLower(text), "refused") {
			continue
		}
		// Each answer line looks like: name TTL IN TYPE value
		for _, line := range strings.Split(text, "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, ";") {
				continue
			}
			fields := strings.Fields(line)
			if len(fields) < 5 {
				continue
			}
			out = append(out, AXFRRecord{
				NS:    ns,
				Name:  fields[0],
				Type:  fields[3],
				Value: strings.Join(fields[4:], " "),
			})
		}
	}
	return out
}

// mergeAXFRAsSubdomains promotes any A/AAAA/CNAME entries from a successful
// AXFR into the main subdomain list so they appear in summaries and exports.
func mergeAXFRAsSubdomains(dr *DomainResult) {
	if dr.Sources == nil {
		dr.Sources = map[string]int{}
	}
	seen := map[string]bool{}
	for _, s := range dr.Subdomains {
		seen[strings.ToLower(s.Subdomain)] = true
	}
	for _, r := range dr.AXFRRecords {
		t := strings.ToUpper(r.Type)
		if t != "A" && t != "AAAA" && t != "CNAME" {
			continue
		}
		name := strings.TrimSuffix(strings.ToLower(r.Name), ".")
		if name == "" || seen[name] {
			continue
		}
		seen[name] = true
		rec := SubdomainRecord{Subdomain: name, Source: "axfr"}
		if t == "A" || t == "AAAA" {
			rec.IPs = []string{r.Value}
		}
		dr.Subdomains = append(dr.Subdomains, rec)
		dr.Sources["axfr"]++
		dr.TotalFound++
	}
}

// sweepReverseDNS does a PTR lookup for every IP we already know about (or
// every IP in the user-supplied CIDR override) and returns the hits.
// subdomainDepth returns how many labels the subdomain has BEYOND the apex.
// example: subdomainDepth("foo.example.com", "example.com") = 1
//
//	subdomainDepth("a.b.c.example.com", "example.com") = 3
//	subdomainDepth("example.com", "example.com") = 0
//
// Comparison is case-insensitive; leading/trailing dots are stripped.
func subdomainDepth(sub, apex string) int {
	s := strings.ToLower(strings.Trim(sub, "."))
	a := strings.ToLower(strings.Trim(apex, "."))
	if s == a {
		return 0
	}
	if !strings.HasSuffix(s, "."+a) {
		// Unrelated subdomain (shouldn't normally happen) — return a
		// sentinel high value so a strict filter excludes it.
		return 999
	}
	prefix := strings.TrimSuffix(s, "."+a)
	if prefix == "" {
		return 0
	}
	return strings.Count(prefix, ".") + 1
}

func sweepReverseDNS(ctx context.Context, dr *DomainResult, cidrOverride string, concurrency int) []PTRRecord {
	var ips []string
	if strings.TrimSpace(cidrOverride) != "" {
		ips = parseReverseTargets(cidrOverride)
	} else {
		seen := map[string]bool{}
		for _, sub := range dr.Subdomains {
			for _, ip := range sub.IPs {
				if ip != "" && !seen[ip] {
					seen[ip] = true
					ips = append(ips, ip)
				}
			}
		}
	}
	out := []PTRRecord{}
	resolver := net.Resolver{}
	if concurrency <= 0 {
		concurrency = 16
	}
	sem := make(chan struct{}, concurrency)
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, ip := range ips {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(ip string) {
			defer wg.Done()
			defer func() { <-sem }()
			lookupCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
			defer cancel()
			names, err := resolver.LookupAddr(lookupCtx, ip)
			if err != nil {
				return
			}
			mu.Lock()
			for _, n := range names {
				out = append(out, PTRRecord{IP: ip, Hostname: strings.TrimSuffix(n, ".")})
			}
			mu.Unlock()
		}(ip)
	}
	wg.Wait()
	return out
}

// parseReverseTargets turns the multi-line / multi-token ReverseCIDR field
// into a flat list of IPs. Accepts (whitespace, comma OR newline)-separated
// entries; each entry may be a single IPv4 ("10.0.0.1") OR a CIDR
// ("10.0.0.0/24"). Invalid entries are silently dropped.
var (
	ipv4Re = regexp.MustCompile(`^(?:\d{1,3}\.){3}\d{1,3}$`)
	cidrRe = regexp.MustCompile(`^(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}$`)
)

func parseReverseTargets(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	// Split on newlines OR commas OR whitespace runs.
	for _, tok := range strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == ';' || r == '\n' || r == '\r' || r == ' ' || r == '\t'
	}) {
		tok = strings.TrimSpace(tok)
		if tok == "" {
			continue
		}
		switch {
		case ipv4Re.MatchString(tok):
			if ip := net.ParseIP(tok); ip != nil && ip.To4() != nil && !seen[ip.String()] {
				seen[ip.String()] = true
				out = append(out, ip.String())
			}
		case cidrRe.MatchString(tok):
			for _, ip := range expandCIDR(tok) {
				if !seen[ip] {
					seen[ip] = true
					out = append(out, ip)
				}
			}
		}
		// Else: silently skip — not a valid IP or CIDR.
	}
	return out
}

// expandCIDR returns every IP in a /16-or-smaller IPv4 CIDR. Bigger blocks
// are silently skipped to avoid runaway sweeps.
func expandCIDR(cidr string) []string {
	_, ipnet, err := net.ParseCIDR(strings.TrimSpace(cidr))
	if err != nil {
		return nil
	}
	ones, bits := ipnet.Mask.Size()
	if bits != 32 || ones < 16 {
		return nil
	}
	ip := ipnet.IP.To4()
	if ip == nil {
		return nil
	}
	count := 1 << uint(bits-ones)
	out := make([]string, 0, count)
	cur := make(net.IP, 4)
	copy(cur, ip)
	for i := 0; i < count; i++ {
		out = append(out, cur.String())
		// increment
		for j := 3; j >= 0; j-- {
			cur[j]++
			if cur[j] != 0 {
				break
			}
		}
	}
	return out
}

// scrapeCrtSh queries crt.sh's JSON API for certificates issued for any
// subdomain of the target.
func scrapeCrtSh(ctx context.Context, domain string) []CrtShRecord {
	url := "https://crt.sh/?q=%25." + domain + "&output=json"
	// crt.sh is frequently overloaded (502/503/timeout). The old code gave up
	// on the very first hiccup and returned nothing — so a flaky crt.sh looked
	// like "crt.sh does nothing". Retry a few times with backoff; usually one
	// of the attempts lands.
	var body []byte
	for attempt := 0; attempt < 3; attempt++ {
		if ctx.Err() != nil {
			return nil
		}
		if attempt > 0 {
			time.Sleep(time.Duration(attempt) * 2 * time.Second)
		}
		httpCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
		req, _ := http.NewRequestWithContext(httpCtx, "GET", url, nil)
		req.Header.Set("User-Agent", "scaNNer-DNSEnum/1.0")
		resp, err := dnsenumHTTPClient.Do(req)
		if err != nil {
			cancel()
			continue
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			cancel()
			continue
		}
		body, _ = io.ReadAll(io.LimitReader(resp.Body, 16*1024*1024))
		resp.Body.Close()
		cancel()
		if len(body) > 0 {
			break
		}
	}
	if len(body) == 0 {
		return nil
	}
	var raw []struct {
		NameValue string `json:"name_value"`
		Issuer    string `json:"issuer_name"`
		NotBefore string `json:"not_before"`
		NotAfter  string `json:"not_after"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil
	}
	out := make([]CrtShRecord, 0, len(raw))
	seen := map[string]bool{}
	for _, r := range raw {
		// name_value may be a multi-line list of SANs
		for _, n := range strings.Split(r.NameValue, "\n") {
			n = strings.ToLower(strings.TrimSpace(n))
			if n == "" || strings.HasPrefix(n, "*") {
				continue
			}
			key := n + "::" + r.NotBefore
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, CrtShRecord{
				NameValue: n,
				Issuer:    r.Issuer,
				NotBefore: r.NotBefore,
				NotAfter:  r.NotAfter,
			})
		}
	}
	return out
}

// mergeCrtShAsSubdomains promotes hostnames from CT logs into the main list.
func mergeCrtShAsSubdomains(dr *DomainResult) {
	if dr.Sources == nil {
		dr.Sources = map[string]int{}
	}
	seen := map[string]bool{}
	for _, s := range dr.Subdomains {
		seen[strings.ToLower(s.Subdomain)] = true
	}
	for _, c := range dr.CrtShCerts {
		name := strings.ToLower(strings.TrimSpace(c.NameValue))
		if name == "" || seen[name] {
			continue
		}
		seen[name] = true
		dr.Subdomains = append(dr.Subdomains, SubdomainRecord{
			Subdomain: name,
			Source:    "crt.sh",
		})
		dr.Sources["crt.sh"]++
		dr.TotalFound++
	}
}

// generatePermutations builds an altdns-style mutation set from a seed
// list of already-discovered subdomains. For each "<sub>.example.com"
// we emit variants like "<sub>-staging.example.com", "<sub>-dev",
// "dev-<sub>", "<sub>2", etc. Deduped + capped at 20 000 to keep the
// puredns sweep bounded; large seed lists need a tighter mutation
// alphabet to stay practical.
func generatePermutations(seeds []string, domain string) []string {
	suffixes := []string{"staging", "dev", "test", "qa", "uat", "preprod", "prod", "beta", "old", "new", "internal", "backup", "admin"}
	numericSuffix := []string{"1", "2", "3", "01", "02", "v2", "v3"}
	out := make(map[string]struct{}, len(seeds)*10)
	add := func(s string) {
		s = strings.ToLower(strings.TrimSpace(s))
		if s == "" || len(s) > 253 {
			return
		}
		out[s] = struct{}{}
	}
	for _, s := range seeds {
		// Strip the apex so we mutate only the label portion.
		if !strings.HasSuffix(s, "."+domain) {
			continue
		}
		label := strings.TrimSuffix(s, "."+domain)
		// Whole-label suffix/prefix combos.
		for _, suf := range suffixes {
			add(label + "-" + suf + "." + domain)
			add(label + "." + suf + "." + domain)
			add(suf + "-" + label + "." + domain)
			add(suf + "." + label + "." + domain)
		}
		// Numeric increments.
		for _, n := range numericSuffix {
			add(label + n + "." + domain)
			add(label + "-" + n + "." + domain)
		}
		if len(out) >= 20000 {
			break
		}
	}
	res := make([]string, 0, len(out))
	for s := range out {
		res = append(res, s)
	}
	return res
}

// queryVirusTotal hits the public domains API. VT serves the subdomain
// list paginated up to ~1000 entries; we stop after one page since
// the deeper-than-thousand cases are rare for legit pentest scope.
// Reference: https://docs.virustotal.com/reference/domains-relationships-subdomains
func queryVirusTotal(ctx context.Context, domain, apiKey string) []string {
	if apiKey == "" {
		return nil
	}
	url := "https://www.virustotal.com/api/v3/domains/" + domain + "/subdomains?limit=1000"
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("x-apikey", apiKey)
	resp, err := dnsenumHTTPClient.Do(req)
	if err != nil || resp.StatusCode != 200 {
		if resp != nil {
			resp.Body.Close()
		}
		return nil
	}
	defer resp.Body.Close()
	var payload struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil
	}
	out := make([]string, 0, len(payload.Data))
	for _, d := range payload.Data {
		out = append(out, d.ID)
	}
	return out
}

// queryShodan uses the host search endpoint with the hostname facet.
// API key required, but the facet query consumes very little quota.
// Returns up to ~100 unique subdomains from facet histogram.
func queryShodan(ctx context.Context, domain, apiKey string) []string {
	if apiKey == "" {
		return nil
	}
	url := "https://api.shodan.io/dns/domain/" + domain + "?key=" + apiKey
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil
	}
	resp, err := dnsenumHTTPClient.Do(req)
	if err != nil || resp.StatusCode != 200 {
		if resp != nil {
			resp.Body.Close()
		}
		return nil
	}
	defer resp.Body.Close()
	var payload struct {
		Subdomains []string `json:"subdomains"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil
	}
	out := make([]string, 0, len(payload.Subdomains))
	for _, s := range payload.Subdomains {
		if s != "" {
			out = append(out, s+"."+domain)
		}
	}
	return out
}

// queryCensys uses the v2 hosts search API with Basic auth (API ID +
// secret from Settings). One request, pulls the first 100 results —
// enough for typical recon scope.
func queryCensys(ctx context.Context, domain, apiID, apiSecret string) []string {
	if apiID == "" || apiSecret == "" {
		return nil
	}
	url := "https://search.censys.io/api/v2/hosts/search?per_page=100&q=" + domain
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil
	}
	req.SetBasicAuth(apiID, apiSecret)
	resp, err := dnsenumHTTPClient.Do(req)
	if err != nil || resp.StatusCode != 200 {
		if resp != nil {
			resp.Body.Close()
		}
		return nil
	}
	defer resp.Body.Close()
	var payload struct {
		Result struct {
			Hits []struct {
				DNS struct {
					Names []string `json:"names"`
				} `json:"dns"`
			} `json:"hits"`
		} `json:"result"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil
	}
	seen := map[string]bool{}
	out := []string{}
	for _, h := range payload.Result.Hits {
		for _, n := range h.DNS.Names {
			if strings.HasSuffix(n, "."+domain) || n == domain {
				if !seen[n] {
					seen[n] = true
					out = append(out, n)
				}
			}
		}
	}
	return out
}
