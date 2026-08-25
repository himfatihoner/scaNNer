package handlers

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"scanner/internal/database"
	"scanner/internal/modules/cvematch"
)

// cveRefreshState tracks the singleton CVE-DB sync job. The Settings UI
// polls /settings/cvedb/status every 2s for the live progress bar.
type cveRefreshState struct {
	mu sync.Mutex

	running    bool
	startedAt  time.Time
	finishedAt time.Time
	err        string

	// Feed-level progress: how many NVD feeds total + how many done.
	feedsTotal  int
	feedsDone   int    // stages COMPLETED (monotonic — never decreases)
	stageName   string // current stage label e.g. "NVD modified" or "NVD 2024"
	subPhase    string // "download" | "parse" | "insert"

	// Within the current sub-phase: progress in native units.
	// Download: bytes_done/bytes_total are real byte counts.
	// Parse:    bytes_done/bytes_total are parsed-advisory counts.
	// Insert:   bytes_done/bytes_total are inserted-row counts.
	bytesDone  int64
	bytesTotal int64

	// Total rows UPSERTED across all stages so far (this run). Note:
	// because we INSERT OR REPLACE, this can exceed the net cache size
	// when sources overlap (e.g. an OSV row for the same CVE as NVD).
	rowsUpserted int
	// Net rows added to the cache (cache_count after - cache_count before).
	// Always <= rowsUpserted; the gap is dedup (intra-batch or cross-source).
	rowsNetAdded int

	// Cancel hook — when the user clicks "Cancel sync", we trigger this
	// context cancel which propagates into the downloader's HTTP call
	// and aborts cleanly.
	cancel context.CancelFunc
}

var cveRefresh = &cveRefreshState{}

// Per-feed download resilience: retry a transient failure (network blip / VPN
// tunnel drop) this many times, spacing attempts by attempt×backoff so the VPN
// watchdog can reconnect between tries.
const (
	cveFeedMaxAttempts  = 3
	cveFeedRetryBackoff = 5 * time.Second
	// Auto-refresh gap-fill: a recent year with fewer than cveYearMinRows NVD
	// rows is treated as missing (a real recent year has 10k+), and up to
	// cveGapPerRun of them are backfilled per daily run (so coverage self-heals
	// over a few days rather than in one huge download), looking back
	// cveGapLookbackYears from the current year.
	cveYearMinRows      = 2000
	cveGapLookbackYears = 11
	cveGapPerRun        = 3

	// CNA enrichment (CVE.org) for NVD-unanalyzed CVEs: bound the per-refresh
	// work so a daily sync stays quick, and only chase RECENT unanalyzed CVEs
	// (the analysis-lag window) — older ones without CPE are usually rejected/
	// disputed and never get analyzed. A backlog self-heals across daily runs.
	cveCNAConcurrency  = 16
	cveCNAPerRun       = 1500
	cveCNALookbackDays = 120
)

// CVEDBRefresh kicks off a background CVE database sync against NVD.
// Accepts:
//   - years=2|5|10|all   (NVD year span)
//   - modified=on        (NVD modified-only feed; takes precedence over years)
//   - clear=on           (wipe NVD rows before sync; builtin seed preserved)
func (h *Handler) CVEDBRefresh(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	cveRefresh.mu.Lock()
	if cveRefresh.running {
		cveRefresh.mu.Unlock()
		http.Error(w, "refresh already in progress", http.StatusConflict)
		return
	}
	cveRefresh.running = true
	cveRefresh.startedAt = time.Now()
	cveRefresh.finishedAt = time.Time{}
	cveRefresh.feedsDone = 0
	cveRefresh.feedsTotal = 0
	cveRefresh.bytesDone = 0
	cveRefresh.bytesTotal = 0
	cveRefresh.rowsUpserted = 0
	cveRefresh.rowsNetAdded = 0
	cveRefresh.err = ""
	cveRefresh.stageName = "starting"
	cveRefresh.subPhase = ""
	cveRefresh.mu.Unlock()

	r.ParseForm()
	years := r.FormValue("years")
	modifiedOnly := r.FormValue("modified") == "on"
	clear := r.FormValue("clear") == "on"

	go h.runCVERefresh(years, modifiedOnly, clear)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"started": true})
}

// StartCVEAutoRefresh runs a daily check (audit B71): if the cache is
// older than 7 days, kick off a modified-only NVD refresh in the
// background. Without this, scaNNer's CVE matcher silently drifted out
// of date — operators only noticed when a known-recent CVE failed to
// match. The refresh respects the same lock as the manual button, so
// a user-triggered refresh is never preempted.
func (h *Handler) StartCVEAutoRefresh() {
	go func() {
		// Brief startup delay so we don't race the rest of init.
		time.Sleep(30 * time.Second)
		t := time.NewTicker(24 * time.Hour)
		defer t.Stop()
		check := func() {
			cveRefresh.mu.Lock()
			alreadyRunning := cveRefresh.running
			cveRefresh.mu.Unlock()
			if alreadyRunning {
				return // a manual (or prior auto) refresh is in flight
			}

			// 1. Modified delta when the cache is stale (last 8 days of changes).
			if lr := h.db.CVECacheLastRefresh(); !lr.IsZero() && time.Since(lr) >= 7*24*time.Hour {
				log.Printf("CVE auto-refresh: cache is %d days old, kicking off modified-only NVD sync",
					int(time.Since(lr)/(24*time.Hour)))
				h.runCVERefresh("", true, false)
				// Prune NVD entries not seen upstream for 2 years (audit B17):
				// without this the table only grew — retracted CVEs lived on
				// forever, slowly inflating matcher false-positive rate.
				if removed, err := h.db.CVECachePruneStale(2 * 365 * 24 * time.Hour); err == nil && removed > 0 {
					log.Printf("CVE auto-refresh: pruned %d stale NVD rows (modified_at > 2y ago)", removed)
				}
			}

			// 2. Gap-fill. The modified feed never backfills a whole year that a
			// full sync missed (never run, or interrupted by a VPN drop) — so
			// recent years silently drift toward empty. Detect the sparse ones
			// and backfill a few per run so coverage self-heals over a few days.
			counts := h.db.CVEYearRowCounts()
			nowY := time.Now().Year()
			var gaps []string
			for y := nowY - cveGapLookbackYears; y <= nowY; y++ {
				if counts[y] < cveYearMinRows {
					gaps = append(gaps, strconv.Itoa(y))
					if len(gaps) >= cveGapPerRun {
						break
					}
				}
			}
			if len(gaps) > 0 {
				cveRefresh.mu.Lock()
				busy := cveRefresh.running
				cveRefresh.mu.Unlock()
				if !busy {
					log.Printf("CVE auto-refresh: backfilling %d sparse year(s): %v", len(gaps), gaps)
					h.runCVERefresh(strings.Join(gaps, ","), false, false)
				}
			}
		}
		check() // first check immediately after warmup
		for range t.C {
			check()
		}
	}()
}

// parseExplicitYears interprets a refresh "years" value as an explicit set of
// NVD feed years. It returns the years when spec is a comma-separated list
// ("2019,2020") or a single 4-digit year ("2020"), and nil for the "last-N"
// forms ("2","5","10") or "all" — so the caller falls through to those paths.
// Years are clamped to [2002, maxYear] and de-duplicated.
func parseExplicitYears(spec string, maxYear int) []string {
	spec = strings.TrimSpace(spec)
	if spec == "" || spec == "all" {
		return nil
	}
	// A bare number that isn't a 4-digit year is a "last-N-years" count.
	if !strings.Contains(spec, ",") {
		if n, err := strconv.Atoi(spec); err != nil || n < 2002 || n > maxYear {
			return nil
		}
	}
	var out []string
	seen := map[string]bool{}
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if y, err := strconv.Atoi(part); err == nil && y >= 2002 && y <= maxYear && !seen[part] {
			seen[part] = true
			out = append(out, strconv.Itoa(y))
		}
	}
	return out
}

func (h *Handler) runCVERefresh(years string, modifiedOnly, clear bool) {
	// Mark running for the whole duration. The manual button (CVEDBRefresh)
	// already sets this before spawning us, but the auto-refresh path calls us
	// directly — without this its gap-fill/modified passes wouldn't guard
	// against a concurrent manual refresh.
	cveRefresh.mu.Lock()
	cveRefresh.running = true
	cveRefresh.mu.Unlock()
	defer func() {
		// Snapshot `now` once (audit B75). Previously time.Now() was
		// called twice — once for the in-memory `finishedAt` and once
		// for the DB-persisted `last_refresh`. Calls a few ms apart
		// produced different timestamps; UI sometimes displayed
		// "finished 2 seconds ago" while the freshness check still
		// considered the data older. One timestamp = consistent.
		now := time.Now()
		cveRefresh.mu.Lock()
		cveRefresh.running = false
		cveRefresh.finishedAt = now
		cveRefresh.cancel = nil
		cveRefresh.mu.Unlock()
		h.db.CVECacheSetLastRefresh(now)
	}()

	// Clear requested? Wipe NVD rows (preserve builtin seed —
	// builtin re-seeds at startup if missing).
	if clear {
		h.db.CVECacheClearSource("nvd")
	}

	// Build the NVD feed list.
	var nvdFeeds []string
	now := time.Now()
	if modifiedOnly {
		nvdFeeds = []string{"modified"}
	} else if years == "all" {
		for y := 2002; y <= now.Year(); y++ {
			nvdFeeds = append(nvdFeeds, strconv.Itoa(y))
		}
	} else if ys := parseExplicitYears(years, now.Year()); len(ys) > 0 {
		// Explicit year list (e.g. "2019,2020,2021" or a single "2020") — used
		// by the auto-refresh gap-fill to backfill specific missing years.
		nvdFeeds = ys
	} else {
		n, err := strconv.Atoi(years)
		if err != nil || n <= 0 {
			n = 2
		}
		if n > 25 {
			n = 25
		}
		for y := now.Year() - n + 1; y <= now.Year(); y++ {
			nvdFeeds = append(nvdFeeds, strconv.Itoa(y))
		}
	}

	total := len(nvdFeeds)
	cveRefresh.mu.Lock()
	cveRefresh.feedsTotal = total
	cveRefresh.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Hour)
	defer cancel()
	// Publish the cancel hook so /settings/cvedb/cancel can abort us.
	cveRefresh.mu.Lock()
	cveRefresh.cancel = cancel
	cveRefresh.mu.Unlock()

	totalRows := 0
	netAddedAcc := 0
	var allUnanalyzed []cvematch.UnanalyzedCVE // NVD-received CVEs w/o CPE → CNA-enrich after
	// Snapshot the cache count to compute net delta after each insert
	// (so we can show "upserted vs net-added" to the user honestly).
	stageDelta := func(beforeCount int) int {
		after := h.db.CVECacheCount()
		delta := after - beforeCount
		if delta < 0 {
			delta = 0
		}
		return delta
	}

	// setStage resets the per-stage progress fields when entering a new
	// stage or sub-phase. Ensures bytes_done/total reflect the CURRENT
	// sub-phase only — the UI weights by sub-phase to keep the bar monotonic.
	setStage := func(name, phase string) {
		cveRefresh.mu.Lock()
		cveRefresh.stageName = name
		cveRefresh.subPhase = phase
		cveRefresh.bytesDone = 0
		cveRefresh.bytesTotal = 0
		cveRefresh.mu.Unlock()
	}
	setStageProgress := func(name, phase string, done, total int64) {
		cveRefresh.mu.Lock()
		cveRefresh.stageName = name
		cveRefresh.subPhase = phase
		cveRefresh.bytesDone = done
		cveRefresh.bytesTotal = total
		cveRefresh.mu.Unlock()
	}

	// ----- NVD feeds -----
	for _, f := range nvdFeeds {
		stageLabel := "NVD " + f
		if f == "modified" {
			stageLabel = "NVD incremental"
		}
		setStage(stageLabel, "download")

		// Retry a transient download failure a few times before giving up.
		// Without this, a brief network blip mid-sync — most importantly a VPN
		// tunnel drop, which BoundDialer routes through — permanently skips that
		// year's feed (the daily "modified"-only auto-refresh never backfills
		// it), leaving exactly the kind of multi-year hole we found here. The
		// backoff gives the VPN watchdog time to reconnect before the next try.
		var rows []cvematch.CVERow
		var unan []cvematch.UnanalyzedCVE
		var err error
		for attempt := 1; attempt <= cveFeedMaxAttempts; attempt++ {
			if f == "modified" {
				// Quick refresh: pull the exact delta since our newest record via
				// the REST API (closes any gap since the last refresh, however
				// long) instead of the fixed 8-day "modified" gz feed.
				since := h.db.CVEMaxModifiedAt()
				rows, unan, err = cvematch.FetchModifiedSince(ctx, since, func(stage string, cur, tot int64) {
					setStageProgress(stageLabel, stage, cur, tot)
				})
				if err == nil || ctx.Err() != nil {
					break
				}
				log.Printf("[cvedb] NVD incremental attempt %d/%d failed: %v — retrying", attempt, cveFeedMaxAttempts, err)
				select {
				case <-ctx.Done():
				case <-time.After(time.Duration(attempt) * cveFeedRetryBackoff):
				}
				continue
			}
			rows, unan, err = cvematch.DownloadFeedWithProgress(ctx, f, func(stage string, cur, tot int64) {
				setStageProgress(stageLabel, stage, cur, tot)
			})
			if err == nil || ctx.Err() != nil {
				break // success, or the whole refresh was cancelled/timed out
			}
			log.Printf("[cvedb] NVD feed %s attempt %d/%d failed: %v — retrying", f, attempt, cveFeedMaxAttempts, err)
			select {
			case <-ctx.Done():
			case <-time.After(time.Duration(attempt) * cveFeedRetryBackoff):
			}
		}
		if err != nil {
			log.Printf("[cvedb] NVD feed %s failed after %d attempts: %v", f, cveFeedMaxAttempts, err)
			cveRefresh.mu.Lock()
			cveRefresh.feedsDone++
			cveRefresh.mu.Unlock()
			continue
		}
		log.Printf("[cvedb] NVD feed %s: %d rows downloaded (%d unanalyzed), inserting…", f, len(rows), len(unan))
		allUnanalyzed = append(allUnanalyzed, unan...)
		bulk := make([]database.CVEBulkRow, 0, len(rows))
		for _, row := range rows {
			fixedIn := ""
			if row.VersionHi != "" && !row.HiInc {
				fixedIn = row.VersionHi
			}
			bulk = append(bulk, database.CVEBulkRow{
				CVEID: row.CVEID, Source: "nvd",
				ProductKey: row.ProductKey, ProductName: row.ProductName,
				VersionLo: row.VersionLo, VersionHi: row.VersionHi,
				LoInc: row.LoInc, HiInc: row.HiInc,
				FixedIn: fixedIn, Severity: row.Severity, CVSS: row.CVSS,
				Description: row.Description, Reference: row.Reference,
				PublishedAt: row.PublishedAt, ModifiedAt: row.ModifiedAt,
			})
		}
		setStage(stageLabel, "insert")
		insertStart := totalRows
		preCount := h.db.CVECacheCount()
		err = h.db.CVEBulkUpsert(bulk, func(done int) {
			setStageProgress(stageLabel, "insert", int64(done), int64(len(bulk)))
			cveRefresh.mu.Lock()
			cveRefresh.rowsUpserted = insertStart + done
			cveRefresh.mu.Unlock()
		})
		if err != nil {
			log.Printf("[cvedb] NVD feed %s bulk insert: %v", f, err)
		} else {
			totalRows = insertStart + len(bulk)
		}
		stageNet := stageDelta(preCount)
		netAddedAcc += stageNet
		log.Printf("[cvedb] NVD feed %s: upserted=%d net=%d (dedup=%d)",
			f, len(bulk), stageNet, len(bulk)-stageNet)
		cveRefresh.mu.Lock()
		cveRefresh.feedsDone++
		cveRefresh.rowsUpserted = totalRows
		cveRefresh.rowsNetAdded = netAddedAcc
		cveRefresh.mu.Unlock()
	}

	// ----- CNA enrichment (CVE.org) -----
	// The NVD feed carried these CVEs with no CPE data (still "Received"/awaiting
	// analysis). Pull the CNA-supplied affected product+version from CVE.org so
	// the newest CVEs become matchable now instead of after NVD's days-to-weeks
	// analysis lag. Bounded + recent-first so a daily refresh stays quick.
	if len(allUnanalyzed) > 0 && ctx.Err() == nil {
		added, net := h.enrichFromCNA(ctx, allUnanalyzed, &totalRows)
		netAddedAcc += net
		cveRefresh.mu.Lock()
		cveRefresh.rowsNetAdded = netAddedAcc
		cveRefresh.mu.Unlock()
		log.Printf("[cvedb] CNA enrichment: %d unanalyzed CVEs → %d rows upserted (net %d)", len(allUnanalyzed), added, net)
	}

	cveRefresh.mu.Lock()
	cveRefresh.stageName = ""
	cveRefresh.subPhase = ""
	cveRefresh.mu.Unlock()

	log.Printf("[cvedb] refresh complete: %d stages, %d upserted, %d net new",
		total, totalRows, netAddedAcc)
}

// CVEDBCancel aborts the in-flight refresh. Idempotent — calling it
// when nothing is running is a no-op. Returns JSON {cancelled: bool}.
func (h *Handler) CVEDBCancel(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	cveRefresh.mu.Lock()
	wasRunning := cveRefresh.running
	if cveRefresh.cancel != nil {
		cveRefresh.cancel()
	}
	cveRefresh.err = "cancelled by user"
	cveRefresh.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"cancelled": wasRunning})
}

// enrichFromCNA fetches CVE.org/MITRE CNA `affected` data for NVD-unanalyzed
// CVEs (no CPE) and upserts version-bounded rows (source="cna"), so the newest
// CVEs are matchable before NVD's analysis lag. Recent-first and capped per run;
// a backlog self-heals across daily refreshes. Updates *totalRows and returns
// (rowsUpserted, netAdded).
func (h *Handler) enrichFromCNA(ctx context.Context, unanalyzed []cvematch.UnanalyzedCVE, totalRows *int) (rowsUpserted, netAdded int) {
	cutoff := time.Now().AddDate(0, 0, -cveCNALookbackDays)
	// Skip CVEs we already enriched on a previous refresh so daily runs only hit
	// CVE.org for newly-appeared unanalyzed CVEs (the modified feed re-lists the
	// same recent CVEs every day until they age out or NVD analyzes them).
	already := h.db.CVEIDsBySource("cna")
	cands := make([]cvematch.UnanalyzedCVE, 0, len(unanalyzed))
	for _, u := range unanalyzed {
		if already[u.CVEID] {
			continue
		}
		if u.PublishedAt.IsZero() || u.PublishedAt.After(cutoff) {
			cands = append(cands, u)
		}
	}
	sort.Slice(cands, func(i, j int) bool { return cands[i].PublishedAt.After(cands[j].PublishedAt) })
	if len(cands) > cveCNAPerRun {
		cands = cands[:cveCNAPerRun]
	}
	if len(cands) == 0 {
		return 0, 0
	}

	cveRefresh.mu.Lock()
	cveRefresh.stageName = "CNA enrich"
	cveRefresh.subPhase = "fetch"
	cveRefresh.bytesTotal = int64(len(cands))
	cveRefresh.bytesDone = 0
	cveRefresh.mu.Unlock()

	sem := make(chan struct{}, cveCNAConcurrency)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var rows []cvematch.CVERow
	done := 0
	for _, u := range cands {
		if ctx.Err() != nil {
			break
		}
		sem <- struct{}{}
		wg.Add(1)
		go func(u cvematch.UnanalyzedCVE) {
			defer wg.Done()
			defer func() { <-sem }()
			r, err := cvematch.FetchCNARows(ctx, u)
			mu.Lock()
			if err == nil {
				rows = append(rows, r...)
			}
			done++
			d := done
			mu.Unlock()
			cveRefresh.mu.Lock()
			cveRefresh.bytesDone = int64(d)
			cveRefresh.mu.Unlock()
		}(u)
	}
	wg.Wait()
	if len(rows) == 0 {
		return 0, 0
	}

	bulk := make([]database.CVEBulkRow, 0, len(rows))
	for _, row := range rows {
		fixedIn := ""
		if row.VersionHi != "" && !row.HiInc {
			fixedIn = row.VersionHi
		}
		bulk = append(bulk, database.CVEBulkRow{
			CVEID: row.CVEID, Source: "cna",
			ProductKey: row.ProductKey, ProductName: row.ProductName,
			VersionLo: row.VersionLo, VersionHi: row.VersionHi,
			LoInc: row.LoInc, HiInc: row.HiInc,
			FixedIn: fixedIn, Severity: row.Severity, CVSS: row.CVSS,
			Description: row.Description, Reference: row.Reference,
			PublishedAt: row.PublishedAt, ModifiedAt: row.ModifiedAt,
		})
	}
	cveRefresh.mu.Lock()
	cveRefresh.subPhase = "insert"
	cveRefresh.mu.Unlock()
	pre := h.db.CVECacheCount()
	if err := h.db.CVEBulkUpsert(bulk, nil); err != nil {
		log.Printf("[cvedb] CNA bulk insert: %v", err)
		return 0, 0
	}
	*totalRows += len(bulk)
	cveRefresh.mu.Lock()
	cveRefresh.rowsUpserted = *totalRows
	cveRefresh.mu.Unlock()
	return len(bulk), h.db.CVECacheCount() - pre
}

// CVEDBStatus is polled by the Settings UI to render the live progress.
func (h *Handler) CVEDBStatus(w http.ResponseWriter, r *http.Request) {
	cveRefresh.mu.Lock()
	// Compose current_feed string for backwards-compat readers, plus
	// expose structured (stage_name, sub_phase) for the smart UI.
	cf := cveRefresh.stageName
	if cveRefresh.subPhase != "" {
		cf = cveRefresh.stageName + " · " + cveRefresh.subPhase
	}
	resp := map[string]any{
		"running":         cveRefresh.running,
		"feeds_total":     cveRefresh.feedsTotal,
		"feeds_done":      cveRefresh.feedsDone,
		"rows_upserted":   cveRefresh.rowsUpserted,
		"rows_net_added":  cveRefresh.rowsNetAdded,
		"stage_name":      cveRefresh.stageName,
		"sub_phase":       cveRefresh.subPhase,
		"current_feed":    cf,
		"bytes_done":      cveRefresh.bytesDone,
		"bytes_total":     cveRefresh.bytesTotal,
		"error":           cveRefresh.err,
	}
	if !cveRefresh.startedAt.IsZero() {
		resp["started_at"] = cveRefresh.startedAt.Format(time.RFC3339)
		if !cveRefresh.finishedAt.IsZero() {
			resp["finished_at"] = cveRefresh.finishedAt.Format(time.RFC3339)
			resp["duration_sec"] = int(cveRefresh.finishedAt.Sub(cveRefresh.startedAt).Seconds())
		}
	}
	cveRefresh.mu.Unlock()

	// Cache stats — row count, distinct CVE count, per-source breakdown,
	// real last-refresh timestamp.
	resp["cache_count"] = h.db.CVECacheCount()
	resp["cache_counts_by_source"] = h.db.CVECacheCountsBySource()
	resp["distinct_cves"] = h.db.CVECacheDistinctCVEs()
	resp["distinct_cves_by_source"] = h.db.CVECacheDistinctCVEsBySource()
	if lr := h.db.CVECacheLastRefresh(); !lr.IsZero() {
		resp["last_refresh"] = lr.Format(time.RFC3339)
		// Integer Duration arithmetic (audit B77). The previous
		// float-Hours()/24 rounded inconsistently — across DST
		// transitions a 30-day cache occasionally reported 29 or 31
		// because the float division accumulated 0.04167-per-hour
		// rounding errors. Integer Duration division has no DST or
		// rounding hazards.
		resp["age_days"] = int(time.Since(lr) / (24 * time.Hour))
	}
	// Coverage summary so the operator can see the DB's state at a glance and
	// decide whether a wider sync is needed: the year span with real data, how
	// many recent years, and the newest CVE modification we hold.
	yc := h.db.CVEYearRowCounts()
	minY, maxY := 0, 0
	years := 0
	for y, n := range yc {
		if n < cveYearMinRows {
			continue // ignore trace/placeholder years
		}
		years++
		if minY == 0 || y < minY {
			minY = y
		}
		if y > maxY {
			maxY = y
		}
	}
	if minY > 0 {
		resp["coverage_years"] = strconv.Itoa(minY) + "–" + strconv.Itoa(maxY)
		resp["coverage_year_count"] = years
	}
	if nm := h.db.CVEMaxModifiedAt(); !nm.IsZero() {
		resp["newest_cve"] = nm.Format("2006-01-02")
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}
