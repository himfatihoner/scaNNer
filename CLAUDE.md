# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

**scaNNer** is a Go-based, web-UI pentest scanning toolkit. A single binary serves a Tailwind/htmx frontend on `:9090` and orchestrates ~34 internal modules that shell out to standard pentest tooling (nmap, nuclei, wpscan, hydra, impacket suite, netexec/nxc, bloodhound-python, certipy, responder, etc.) and parse the output into structured findings persisted in SQLite. Every scan is async, cancellable, and re-renderable from its stored config (Restart action). All outbound traffic can be confined to a Linux network namespace bridged to a chosen interface so a VPN drop drops the scan instead of leaking via the default route.

## Build, run, restart

```
go build -o ./scanner ./cmd/scanner            # build
./scanner                                       # run on :9090 (default)
PORT=8080 DATA_DIR=/tmp/scan ./scanner          # overrideable env
docker compose up -d --build                    # containerised (Kali base image)
```

There are no tests in the tree right now — `go test ./...` runs nothing meaningful. `go vet ./...` and `go build` are the truth-source for "code is healthy."

**Hot-restart workflow** while developing: the process is single-binary, no migrations, no daemon manager — `go build && pkill -TERM scanner && ./scanner &` is the loop. State lives in `data/scanner.db` (SQLite WAL) so a restart does not lose scan history; orphaned `running`/`pending` rows from the prior process are auto-marked `error` at startup via `DB.MarkOrphanedScans` (see `cmd/scanner/main.go:130`).

**Killswitch privilege model — TEMPORARY**: the network namespace path (`internal/network/netns_linux.go::RequiresPrivilege`) needs `CAP_NET_ADMIN`. Right now the dev workflow is `sudo setcap cap_net_admin,cap_net_raw+ep ./scanner` after each rebuild. The agreed long-term install path is a systemd system unit with `AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW` so capabilities re-attach on every restart without touching the binary. The full design + rationale + the unit/sudoers files are saved at `~/.claude/projects/-home-user-my-tools-scaNNer/memory/project_install_systemd.md` — **load that memory whenever the install/setup script is being designed**. Do NOT default new design discussions to setcap; that's the pain we're escaping.

## High-level architecture

```
                       ┌─────────────────────────────────────────────┐
                       │  cmd/scanner/main.go (registry + routes)    │
                       └─────────────────────────────────────────────┘
                                          │
                  ┌───────────────────────┼───────────────────────┐
                  ▼                       ▼                       ▼
        internal/modules.Registry   net/http routes      handlers.Handler
        (Name→Module struct)        (4 per module)       (page/run/results/status)
                  │                                              │
                  │                                              ▼
                  ▼                                       ScanManager + DB
        internal/modules/<name>/                          (cancel ctxs, sqlite WAL)
        ├─ module.go     ←  Module interface              │
        ├─ scanner.go    ←  Scan(ctx, cfg, progress, partial) *ScanResult
        ├─ phase_*.go    ←  (optional sub-stages, see adpentest)
        └─ helpers       ←  parse_<tool>.go, etc.
                  │
                  └─ subprocess → internal/modules/shared.Command(ctx, name, args...)
                                                                      │
                                       ┌──────────────────────────────┤
                                       ▼                              ▼
                              killswitch ARMED →            killswitch DORMANT →
                              `ip netns exec scanner-ns`    plain exec.CommandContext
```

**Single source of truth for subprocess spawning is `shared.Command`** (`internal/modules/shared/subprocess.go`). It returns a `*exec.Cmd` with the same stdlib API; namespace wrapping is invisible to callers. Never call `exec.CommandContext` directly from module code — that bypasses the killswitch and the kill flag in the previous iteration is gone for good. Module authors should also use `shared.RunNmap` for nmap (parses XML), `shared.FormatCommand` for command-line crumbs in progress messages, and `shared.BoundDialer` / `shared.HTTPOptions` for Go-side HTTP so traffic stays on the pinned interface.

### The Module pattern (mirror this for every new module)

Each module is one directory under `internal/modules/<name>/` with exactly this contract:

1. **`module.go`** — implements `modules.Module` (`Name() / DisplayName() / Description() / Category() / Icon()`). Category is free-form but the UI filter buttons recognise `web`, `network`, `recon`, `vuln`. Anything else still appears under "All" but won't be reachable via a single click.

2. **`scanner.go`** — declares `Config`, the result types (whatever `ScanResult` looks like for this module), and:
   ```go
   type ProgressFunc func(done int, msg string)
   type PartialFunc  func(*ScanResult)
   func Scan(ctx context.Context, cfg Config, progress ProgressFunc, partial PartialFunc) *ScanResult
   ```
   `progress` messages that start with `"$ "` are auto-extracted into the scan's `Commands` log column (so the live UI shows the exact shell command). `partial` is called with snapshots of the in-progress result — the handler buffers and flushes the latest snapshot every 2 s.

3. **`internal/handlers/<name>.go`** — five funcs in the canonical shape (use `smbenum.go` or `adpentest.go` as the template):
   - `<Name>Page` — GET form, lists historical scans
   - `<Name>Run` — POST, parses form into a JSON config, `db.CreateScan` + `go h.run<Name>(...)`, 303 to results page
   - `<Name>Results` — GET, loads scan row + unmarshal result JSON, calls `renderResults(w, r, "<name>_results_inner", data)` which honours `?partial=1` for htmx polling
   - `<Name>Status` — GET, calls `h.writeScanStatus(w, scan)` returning the progress JSON
   - `run<Name>` — the goroutine that calls `db.MarkRunning` → `h.scanMgr.Register` → invokes the module → has the 2-second partial-flush ticker that pushes the latest snapshot to `db.UpdateScanResult`. `defer h.FinishScan(scanID)` is mandatory (closes transports + DB cleanup).

4. **`web/templates/<name>.html`** — defines `{{define "page_<name>"}}` (form + history sidebar)

5. **`web/templates/<name>_results.html`** — defines `{{define "page_<name>_results"}}` (full page) AND `{{define "<name>_results_inner"}}` (the htmx-swappable fragment). The full-page wrapper composes `scan_actions` + `scan_progress` + the inner fragment; the inner fragment is what `renderResults` serves on `?partial=1`. See `adpentest_results.html` for the cleanest example.

6. **Wire-up in `cmd/scanner/main.go`** — three sites, all easy to forget:
   - Import: `"scanner/internal/modules/<name>"`
   - Registry: `registry.Register(&<name>.Module{})`
   - Routes: 4 `http.HandleFunc("/modules/<name>{,/run,/results/,/status/}", ...)`

7. **Wire-up in `web/templates/layout.html`** — the page dispatch is a hand-maintained `{{else if eq .Page "..."}}` chain. **Adding a new module without adding two entries here (one for the form page, one for the results page) causes the page to render the layout shell with an empty body — HTTP 200, ~57 KB of head/scripts, zero content.** Symptom is "page is blank but URL works". Search for `smbenum` in `layout.html` to find the pattern.

8. **Wire-up the URL helper in `internal/handlers/handlers.go::scanResultsURL` FuncMap** if the module should be linkable from the Scans listing / Dashboard.

### Killswitch (outbound interface pinning)

Two-layer defense, both gated by Settings → "Outbound Network Interface":

- **Layer 1 — Linux network namespace** (`internal/network/netns_linux.go`):
  - `scanner-ns` netns with a veth pair `scanner0 ↔ scanner1` (IPs `10.200.0.1/24 ↔ 10.200.0.2/24`).
  - iptables FORWARD rules tagged `--comment scaNNer-killswitch` only allow egress through the chosen interface; everything else DROPs.
  - NAT POSTROUTING masquerade so the namespace's `10.200.0.0/24` source NATs out the chosen iface.
  - `/etc/netns/scanner-ns/resolv.conf` is copied from the host so VPN-pushed DNS works inside the namespace.
  - `netns.IsActive()` is an atomic bool that `shared.Command` consults on every spawn.

- **Layer 2 — Go HTTP source-IP binding** (`internal/modules/shared/httpopt.go`):
  - `shared.SetGlobalLocalAddr` plus per-`HTTPOptions.LocalAddr` propagate through `BoundDialer` so every Go-side dialer pins to the iface's primary IPv4.
  - Catches modules that use `net/http` directly without spawning a subprocess.

- **Runtime monitor** (`internal/network/iface_monitor.go::loop`): 2-second tick that runs `CheckInterfaceUp` AND, when the killswitch is armed, `HealthCheck` (namespace exists + veth UP + iptables rules intact). On failure: `cancelAll` + `markErr` on every running scan, then stops polling until Settings is re-saved.

**Subprocess code only needs to use `shared.Command`** — namespace wrapping is transparent. If a phase needs to listen on the killswitch veth (Responder, mitm6), use `scanner1` as the interface name (`defaultHarvestIface` in `adpentest/phase_harvest.go` handles the detection).

### ScanManager lifecycle

`internal/handlers/scanmgr.go` tracks three things per active scan:

- `context.CancelFunc` — `Cancel(scanID)` aborts the scan and propagates to subprocesses (because their context is the ScanManager's).
- `*shared.HTTPOptions` — registered via `RegisterOpts` so cancel can flush every transport's idle TCP pool (otherwise sockets stay parked until GC, minutes later).
- Sticky `warnings[scanID]` — surfaced via `writeScanStatus` so the UI shows the killswitch's "interface went down" message even after the cancel goroutine returns.

`CancelAll(reason)` is what the killswitch monitor calls when the pinned iface drops. The killswitch dependency-injects this function in `cmd/scanner/main.go:212` to avoid a `network → handlers` import cycle.

### Database

`internal/database/database.go` — `modernc.org/sqlite` (pure-Go, no CGO) wrapped in `sqlx`. Single file at `data/scanner.db`, opened with `journal_mode=wal`, `foreign_keys=1`, `busy_timeout=5000`. Connection pool capped (audit B3 — see header docstring).

Critical methods:

- `CreateScan(workspaceID, module, config, totalTargets)` — config is the JSON-encoded launch form; used by the Restart action to replay the scan
- `MarkRunning(id)` → bool — handler's first call inside its goroutine; returns false if the row was deleted / already finished, in which case the goroutine returns early
- `UpdateScanProgress(id, done, msg)` — high-frequency; `msg` starting with `"$ "` is appended to the `commands` column
- `UpdateScanResult(id, jsonString)` — called both periodically (the 2s flush) and finally (full marshal). Result column is a TEXT blob containing the module's own `ScanResult` JSON.
- `MarkScanError(id, message)` — used by the killswitch monitor and by handlers on terminal errors
- `MarkOrphanedScans()` — startup-only sweep that flips `running`/`pending` rows from the previous process to `error`

`internal/models/scan.go::Scan.Status` is a tiny string enum: `pending|running|done|error|cancelled`.

### Workspaces

Most pages live inside an active workspace (selected via dropdown, persisted in a cookie). `h.activeWorkspace(r)` reads the cookie; `h.baseData(r, title, page)` builds the standard layout context map (including `Page` for the dispatch chain). Handlers that mutate state always scope queries to the workspace. Workspaces own: targets, target lists, scans, assets.

### CVE database

`internal/database/database.go::CVEUpsert` plus `internal/handlers/cvedb.go` manage three CVE sources: `builtin` (curated, seeded on every startup from `cvematch.SeedBuiltin`), `nvd` (NIST feed, daily auto-refresh via `h.StartCVEAutoRefresh`), and `osv`. The Settings page has refresh / cancel buttons that drive the same locked refresh path as the auto job.

## Frontend conventions

- **Templates are not embedded** — `web/templates/*.html` is read from disk at startup (`handlers.New(... "web/templates")`). Editing a template requires a restart for changes to be visible.
- **The layout dispatch is a hand-maintained switch** — see the "Wire-up in `layout.html`" note above. There is no auto-discovery.
- **htmx + Tailwind** — Tailwind via CDN, htmx for the live progress polling and the partial result re-renders. No bundler, no SPA framework.
- **Shared partials** live in templates prefixed with `_` (`_form_helpers.html`, `_empty_toggle.html`). The `field_label` and `info_icon` partials are used in nearly every form.
- **`scan_actions.html` + `scan_progress.html`** are the common header strip and progress bar every results page composes via `{{template "scan_actions" .}}` and `{{template "scan_progress" .}}`.
- **Template FuncMap** is defined inline in `handlers.New` (start of `handlers.go`). Notable helpers: `dict` (for nested partial args), `scanResultsURL` (module → URL switch), `formatDuration`, `moduleDisplayName`, `isVulnEmitter`.

## External tool dependencies

The startup banner (`cmd/scanner/main.go:75`) probes a fixed list and warns about missing ones. Modules call out to (non-exhaustive):

| Module | Tools |
|---|---|
| `portservice`, `smbenum`, many | nmap (+ NSE scripts) |
| `nuclei` | nuclei |
| `wpscan` | wpscan |
| `brutef` | hydra |
| `smbenum` | smbclient, enum4linux, enum4linux-ng |
| `dnsenum` | subfinder, amass, puredns, dig, recon-ng |
| `whoisinfo` | whois |
| `snmpenum` | onesixtyone, snmpget, snmpwalk |
| `techdetect` | whatweb |
| `emailharvest` | theHarvester |
| `adpentest` | ldapsearch, ldapdomaindump, nxc/netexec, impacket-{GetUserSPNs,GetNPUsers,lookupsid,samrdump,secretsdump,GetTGT,GetST,...}, bloodhound-python, certipy-ad, responder, mitm6, kerbrute, coercer, hashcat |

`adpentest` runs its own `preflight()` per scan and surfaces missing-tool warnings on the results page (`internal/modules/adpentest/preflight.go`). Other modules just silently degrade; the startup banner is the only warning.

For `kerbrute` (Go binary at `~/go/bin/kerbrute`) and `mitm6` (pipx-installed at `~/.local/bin/mitm6`), make sure both directories are on `$PATH`. If `~/go/bin` is not on `$PATH`, symlink: `ln -sf ~/go/bin/kerbrute ~/.local/bin/`.

## Things that bite

- **A new module that doesn't render** is almost always a missing `{{else if eq .Page "..."}}` entry in `layout.html`. The page returns 200 with the layout shell and no content. The dispatch is hand-maintained; there's no fallback like "if no page_X template matches, fall back to .Page name."
- **`exec.CommandContext` directly in module code** bypasses the killswitch. Use `shared.Command`. (The previous flag-injection-based killswitch was reverted specifically because some tools didn't support a flag for it; the namespace approach was chosen so callers don't have to think about it. Don't reintroduce that thinking.)
- **A scan that "hangs at 0%"** with `total > 0` is usually a module that returns before its final `progress(total, ...)` call — `writeScanStatus` clamps to 100% when `Status == done`, so the visible bar is fine; the issue is your `partial` callback never fired with a non-nil result. Fix the module to push at least one snapshot before returning.
- **Templates aren't embedded**. A `go build && ./scanner` cycle is required after template edits, but only because the new process re-reads them — the binary doesn't include them. If you'd rather edit-reload, that's a refactor target (Go 1.16+ `embed.FS`).
- **The Restart action replays the original config JSON**. Adding fields to a module's launch form means handling `restart_helpers.go` for any module that has a `restart<Name>` handler (not all do — search before assuming).
- **`go vet` lies** about unused fields in JSON-tagged structs (it's permissive there). Use the build output as the final word.
- **SQLite WAL files** (`scanner.db-shm`, `scanner.db-wal`) sit next to the DB. Don't delete them while the scanner is running — corrupts the DB. To fully reset state: stop the scanner, delete `data/scanner.db*` (all three).

## Repo layout (the parts worth knowing)

- `cmd/scanner/main.go` — entry point: tool preflight, /tmp sweep, DB open + orphan sweep, registry, killswitch arm, routes, signal handler with `srv.Shutdown` + `netns.Teardown`
- `internal/database/database.go` — single 1.4k-line file, all schema + queries
- `internal/handlers/handlers.go` — handler struct + base, template FuncMap, settings page, workspace + target CRUD, helpers used across all modules
- `internal/handlers/scanmgr.go` — cancel registry + transport flush
- `internal/handlers/scan_control.go` — per-scan cancel/delete/restart/archive endpoints
- `internal/handlers/restart_helpers.go` — module-specific config-replay glue for Restart
- `internal/modules/module.go` — `Module` interface + `Registry`
- `internal/modules/moduleinfo.go` — `ModuleDoc` rich descriptions surfaced in the UI's per-module help
- `internal/modules/shared/` — `subprocess.go` (the wrap), `httpopt.go` (HTTPOptions + BoundDialer + RegisterTransport), `nmap.go` (RunNmap XML parse), `progress.go`, `rawcapture.go`, `target.go` (ExpandTargets CIDR/range)
- `internal/network/netns_linux.go` + `netns_other.go` — the Linux-specific namespace ops vs. the cross-platform stub
- `internal/network/iface.go` — interface enumeration for the Settings dropdown
- `web/templates/layout.html` — every page's outer shell + the dispatch chain
- `web/static/` — Tailwind + any client-side JS (htmx is CDN-served)
- `PENTEST_PLAN.txt` — historical scope plan; pentest module groupings (A/B/C) come from here

## When changing things

- **Adding a module**: copy `smbenum/` as the closest "average" template; mirror the 8 wire-up sites listed above. The `adpentest/` module is a richer example of multi-phase scanners with risk-tier toggles and BloodHound-style result panels.
- **Changing the killswitch's interface name / IPs / iptables comment**: edit `internal/network/netns.go` constants. `IptablesComment` is the lookup key the teardown logic uses to clean up only our rules, so it must stay unique to scaNNer.
- **Adding a CLI tool dependency**: append it to the `tools` slice in `cmd/scanner/main.go:80` so the startup banner warns when it's missing. Then call it via `shared.Command(ctx, "newtool", args...)`.
- **Touching HTTP from a module**: build an `HTTPOptions` via `shared.ParseHTTPOptions(r)` in the handler, call `opts.NewHTTPClient()` for the client, `opts.RegisterTransport(t)` if you build your own transport so cancellation can flush its idle pool, and use `opts.BindContext(req)` so the request inherits the scan's cancellable context.
