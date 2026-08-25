package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Software self-update. An admin can pull the latest code from the app's git
// remote, rebuild the binary, and re-exec into it — all from the web UI.
//
// Safety model (this must be robust — it replaces the running program):
//   - Refuse unless it's a clean git checkout with an 'origin' remote and both
//     git + the Go toolchain are present.
//   - Refuse if the working tree has local changes (never discard user edits).
//   - Build to ./scanner.new FIRST; a failed build never touches the running
//     binary. Smoke-test the new binary (`-version`) before committing.
//   - Atomically rename ./scanner.new → ./scanner, then re-exec (same argv+env).
//     Re-exec keeps the PID and works with or without a supervisor (systemd).
//
// git and go run on the HOST network via plain exec — deliberately NOT
// shared.Command — because these are management operations that must reach
// GitHub / the module proxy even while the killswitch confines scan traffic to
// a VPN interface.

var updateMu sync.Mutex // serializes update operations (and stays held across re-exec)

// updateInfo is the status surfaced to the UI.
type updateInfo struct {
	Available    bool     `json:"available"`
	Reason       string   `json:"reason,omitempty"`
	Branch       string   `json:"branch,omitempty"`
	Current      string   `json:"current,omitempty"`
	CurrentSubj  string   `json:"current_subject,omitempty"`
	Latest       string   `json:"latest,omitempty"`
	Behind       int      `json:"behind"`
	UpToDate     bool     `json:"up_to_date"`
	Clean        bool     `json:"clean"`
	Changelog    []string `json:"changelog,omitempty"`
	ScansRunning bool     `json:"scans_running"`
}

func runCmd(dir string, timeout time.Duration, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = dir
	var buf bytes.Buffer
	cmd.Stdout, cmd.Stderr = &buf, &buf
	err := cmd.Run()
	return buf.String(), err
}

func runGit(dir string, timeout time.Duration, args ...string) (string, error) {
	return runCmd(dir, timeout, "git", args...)
}

// repoRoot resolves the git working tree the app runs from (cwd is the repo root
// because templates load from ./web/templates).
func repoRoot() (string, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	out, err := runGit(cwd, 5*time.Second, "rev-parse", "--show-toplevel")
	if err != nil {
		return "", fmt.Errorf("not a git checkout")
	}
	return strings.TrimSpace(out), nil
}

// gatherUpdateInfo inspects the checkout (optionally fetching first).
func (h *Handler) gatherUpdateInfo(fetch bool) updateInfo {
	var ui updateInfo
	ui.ScansRunning = h.db.HasRunningScans()
	root, err := repoRoot()
	if err != nil {
		ui.Reason = "This deployment is not a git checkout, so in-app updates aren't available."
		return ui
	}
	if _, err := exec.LookPath("git"); err != nil {
		ui.Reason = "git is not installed on this machine."
		return ui
	}
	if _, err := exec.LookPath("go"); err != nil {
		ui.Reason = "the Go toolchain is not installed (needed to rebuild the app)."
		return ui
	}
	if remote, err := runGit(root, 5*time.Second, "remote", "get-url", "origin"); err != nil || strings.TrimSpace(remote) == "" {
		ui.Reason = "no 'origin' git remote is configured to update from."
		return ui
	}
	ui.Available = true
	ui.Branch = firstLine(gitOut(root, "rev-parse", "--abbrev-ref", "HEAD"))
	ui.Current = firstLine(gitOut(root, "rev-parse", "--short", "HEAD"))
	ui.CurrentSubj = firstLine(gitOut(root, "log", "-1", "--pretty=%s"))
	ui.Clean = strings.TrimSpace(gitOut(root, "status", "--porcelain")) == ""

	if fetch && ui.Branch != "" {
		runGit(root, 60*time.Second, "fetch", "--quiet", "origin", ui.Branch)
	}
	upstream := "origin/" + ui.Branch
	ui.Latest = firstLine(gitOut(root, "rev-parse", "--short", upstream))
	ui.Behind, _ = strconv.Atoi(firstLine(gitOut(root, "rev-list", "--count", "HEAD.."+upstream)))
	ui.UpToDate = ui.Behind == 0
	if ui.Behind > 0 {
		for _, l := range strings.Split(strings.TrimSpace(gitOut(root, "log", "--pretty=%h %s", "HEAD.."+upstream)), "\n") {
			if l = strings.TrimSpace(l); l != "" {
				ui.Changelog = append(ui.Changelog, l)
			}
		}
	}
	return ui
}

func gitOut(dir string, args ...string) string {
	out, _ := runGit(dir, 10*time.Second, args...)
	return out
}
func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}
func lastLines(s string) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) > 8 {
		lines = lines[len(lines)-8:]
	}
	return strings.Join(lines, "\n")
}

func writeJSON(w http.ResponseWriter, code int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

// UpdatePage renders the admin Software Update page.
func (h *Handler) UpdatePage(w http.ResponseWriter, r *http.Request) {
	data := h.baseData(r, "Software Update - scaNNer", "update")
	data["Update"] = h.gatherUpdateInfo(false) // no network fetch on page load
	h.render(w, "layout", data)
}

// UpdateCheck fetches and reports whether an update is available (JSON).
func (h *Handler) UpdateCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/update", http.StatusSeeOther)
		return
	}
	writeJSON(w, http.StatusOK, h.gatherUpdateInfo(true))
}

// UpdateApply pulls, rebuilds, and re-execs into the new binary.
func (h *Handler) UpdateApply(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/update", http.StatusSeeOther)
		return
	}
	if !updateMu.TryLock() {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "An update is already in progress."})
		return
	}
	// Unlock only on the early-return (failure) paths; on success we re-exec so
	// the lock intentionally dies with the process.
	locked := true
	unlock := func() {
		if locked {
			updateMu.Unlock()
			locked = false
		}
	}
	fail := func(msg string) { unlock(); writeJSON(w, http.StatusBadGateway, map[string]string{"error": msg}) }

	ui := h.gatherUpdateInfo(true)
	if !ui.Available {
		fail(ui.Reason)
		return
	}
	if !ui.Clean {
		fail("The working tree has local changes — refusing to update so nothing is lost. Commit, stash, or reset them first.")
		return
	}
	if ui.UpToDate {
		unlock()
		writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true, "message": "Already up to date — nothing to apply."})
		return
	}
	root, err := repoRoot()
	if err != nil {
		fail("could not locate the git checkout")
		return
	}

	// Remember the pre-update commit so any post-pull failure can restore the
	// checkout to exactly its last-good state (source AND running binary).
	oldCommit := firstLine(gitOut(root, "rev-parse", "HEAD"))
	rollback := func() {
		if oldCommit != "" {
			runGit(root, 30*time.Second, "reset", "--hard", oldCommit)
		}
	}

	// 1. Sync the checkout to exactly origin's tip. A plain `pull --ff-only`
	//    ABORTS the moment local history has diverged from the remote — which
	//    happens whenever the upstream is force-pushed or rebased (a curated
	//    public mirror commonly rewrites its release history). Since a deployed
	//    checkout only ever TRACKS the remote (any local edit was already
	//    refused above via the clean-tree guard), fetch then hard-reset to the
	//    upstream tip: a normal update is a fast-forward, and a diverged one is
	//    realigned instead of dead-ending the whole update feature.
	if out, err := runGit(root, 120*time.Second, "fetch", "origin", ui.Branch); err != nil {
		fail("git fetch failed:\n" + lastLines(out))
		return
	}
	upstream := "origin/" + ui.Branch
	if out, err := runGit(root, 60*time.Second, "reset", "--hard", upstream); err != nil {
		rollback()
		fail("git update failed (could not sync to " + upstream + "):\n" + lastLines(out))
		return
	}
	// 2. Build to a temp binary so a broken build never replaces the running one.
	if out, err := runCmd(root, 5*time.Minute, "go", "build", "-o", "./scanner.new", "./cmd/scanner"); err != nil {
		rollback()
		fail("Build failed — rolled back, keeping the current version running:\n" + lastLines(out))
		return
	}
	newBin := filepath.Join(root, "scanner.new")
	// 3. Smoke-test: the new binary must at least execute (catches link/init panics).
	if out, err := runCmd(root, 20*time.Second, newBin, "-version"); err != nil {
		os.Remove(newBin)
		rollback()
		fail("The rebuilt binary failed its smoke test — rolled back, keeping the current version:\n" + lastLines(out))
		return
	}
	// 4. Atomically swap it in.
	finalBin := filepath.Join(root, "scanner")
	if err := os.Rename(newBin, finalBin); err != nil {
		os.Remove(newBin)
		rollback()
		fail("Could not install the new binary (rolled back): " + err.Error())
		return
	}

	// Success: tell the client we're restarting, then re-exec (keep the lock).
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"ok": true, "restarting": true,
		"message": "Update applied (now at " + ui.Latest + "). Restarting into the new version…",
	})
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
	go h.reexecAfterUpdate(finalBin)
}

// reexecAfterUpdate stops in-flight scans, then replaces this process with the
// freshly-built binary via execve (same argv + env).
func (h *Handler) reexecAfterUpdate(binPath string) {
	time.Sleep(800 * time.Millisecond) // let the HTTP response flush to the client
	if ids := h.scanMgr.CancelAll("Restarting to apply a software update"); len(ids) > 0 {
		for _, id := range ids {
			h.db.MarkScanError(id, "Scan stopped — applying software update")
		}
		time.Sleep(1 * time.Second) // let the subprocess SIGKILLs land
	}
	log.Printf("update: re-exec into %s", binPath)
	argv := append([]string{binPath}, os.Args[1:]...)
	if err := syscall.Exec(binPath, argv, os.Environ()); err != nil {
		// Exec should not return; if it does the update didn't take effect.
		log.Printf("update: re-exec failed: %v (the new binary is installed; a manual restart will pick it up)", err)
		updateMu.Unlock()
	}
}
