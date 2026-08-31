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

	"scanner/internal/models"
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
	// NeedsInstaller is true when the pending update changes scripts/install.sh
	// (systemd unit / capabilities / sudoers / tmpfiles / sysctl / apt deps) — an
	// in-place re-exec can't apply those, so applying needs a one-time sudo
	// password to re-run the installer. See UpdateApplyPrivileged.
	NeedsInstaller bool `json:"needs_installer"`
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
		// Does the pending update touch the installer? If so it changes system
		// integration a re-exec can't apply, so applying needs the privileged path.
		ui.NeedsInstaller = strings.TrimSpace(gitOut(root, "diff", "--name-only", "HEAD", upstream, "--", "scripts/install.sh")) != ""
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

	finalBin, errMsg := h.pullBuildSwap(root, ui)
	if errMsg != "" {
		fail(errMsg)
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

// pullBuildSwap syncs the checkout to origin's tip, builds + smoke-tests the new
// binary, and atomically swaps it in. On any failure it rolls the checkout back
// to the pre-update commit and returns a non-empty error message; on success it
// returns the installed binary path and "".
func (h *Handler) pullBuildSwap(root string, ui updateInfo) (string, string) {
	oldCommit := firstLine(gitOut(root, "rev-parse", "HEAD"))
	rollback := func() {
		if oldCommit != "" {
			runGit(root, 30*time.Second, "reset", "--hard", oldCommit)
		}
	}
	// fetch + hard-reset to the upstream tip (a diverged/force-pushed mirror is
	// realigned rather than dead-ending; the clean-tree guard already ran).
	if out, err := runGit(root, 120*time.Second, "fetch", "origin", ui.Branch); err != nil {
		return "", "git fetch failed:\n" + lastLines(out)
	}
	upstream := "origin/" + ui.Branch
	if out, err := runGit(root, 60*time.Second, "reset", "--hard", upstream); err != nil {
		rollback()
		return "", "git update failed (could not sync to " + upstream + "):\n" + lastLines(out)
	}
	if out, err := runCmd(root, 5*time.Minute, "go", "build", "-o", "./scanner.new", "./cmd/scanner"); err != nil {
		rollback()
		return "", "Build failed — rolled back, keeping the current version running:\n" + lastLines(out)
	}
	newBin := filepath.Join(root, "scanner.new")
	if out, err := runCmd(root, 20*time.Second, newBin, "-version"); err != nil {
		os.Remove(newBin)
		rollback()
		return "", "The rebuilt binary failed its smoke test — rolled back, keeping the current version:\n" + lastLines(out)
	}
	finalBin := filepath.Join(root, "scanner")
	if err := os.Rename(newBin, finalBin); err != nil {
		os.Remove(newBin)
		rollback()
		return "", "Could not install the new binary (rolled back): " + err.Error()
	}
	return finalBin, ""
}

// zeroBytes wipes a byte slice — used to erase the sudo password from memory the
// instant it has been handed to sudo's stdin.
func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// UpdateApplyPrivileged applies an update that changes system integration
// (scripts/install.sh). It does the ordinary git+build+swap as the normal user,
// then re-runs the installer as root using a sudo password the operator supplies
// for this one action.
//
// SECURITY (the operator's hard requirement): the password is read into a single
// []byte, fed ONLY to sudo's stdin (never argv/env/logs/DB/audit/commands),
// zeroed immediately after, and `sudo -k` leaves no cached session. Admin-only,
// HTTPS-only, POST + SameSite (CSRF-safe). The executed argv is fully fixed
// (trusted absolute paths) — no shell, no user-controlled command.
func (h *Handler) UpdateApplyPrivileged(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/update", http.StatusSeeOther)
		return
	}
	user := h.currentUser(r) // /update* is already admin-gated; re-check defensively
	if user == nil || !user.IsAdmin() {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "Administrator access required."})
		return
	}
	if !h.secureCookies { // never accept a sudo password over cleartext HTTP
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "For safety the sudo password is only accepted over HTTPS. This deployment is on plain HTTP — apply the system update from a terminal instead."})
		return
	}
	if !updateMu.TryLock() {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "An update is already in progress."})
		return
	}
	locked := true
	unlock := func() {
		if locked {
			updateMu.Unlock()
			locked = false
		}
	}

	pw := []byte(r.FormValue("sudo_password"))
	// Drop the parsed-form references so the password string becomes GC-eligible
	// (Go strings can't be wiped in place; our []byte copy is zeroed below).
	if r.PostForm != nil {
		r.PostForm.Del("sudo_password")
	}
	if r.Form != nil {
		r.Form.Del("sudo_password")
	}
	defer zeroBytes(pw) // erased whichever path we leave on
	if len(pw) == 0 {
		unlock()
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Your sudo password is required to apply a system update."})
		return
	}

	ui := h.gatherUpdateInfo(true)
	if !ui.Available {
		unlock()
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": ui.Reason})
		return
	}
	if !ui.Clean {
		unlock()
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "The working tree has local changes — refusing to update so nothing is lost."})
		return
	}
	root, err := repoRoot()
	if err != nil {
		unlock()
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "could not locate the git checkout"})
		return
	}
	if !ui.UpToDate { // pull+build as the normal user; if already current this is a forced installer re-run
		if _, errMsg := h.pullBuildSwap(root, ui); errMsg != "" {
			unlock()
			writeJSON(w, http.StatusBadGateway, map[string]string{"error": errMsg})
			return
		}
	}

	out, err := runInstallerWithSudo(pw, root)
	zeroBytes(pw)
	if err != nil {
		unlock()
		msg := "Could not apply the system update."
		lo := strings.ToLower(out)
		if strings.Contains(lo, "incorrect password") || strings.Contains(lo, "sorry, try again") || strings.Contains(lo, "authentication failure") {
			msg = "sudo authentication failed — the password was rejected. Nothing was changed."
		} else if out != "" {
			msg = "Could not launch the privileged installer:\n" + out
		}
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": msg})
		return
	}
	h.audit(r, user, models.AuditAdmin, "update.privileged", "re-ran installer for system update ("+ui.Latest+")")

	// Success: the transient unit is now running install.sh, which restarts the
	// service. Respond, then let the restart replace us (keep the lock — the
	// process is about to die).
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"ok": true, "restarting": true,
		"message": "Applying the system update in the background (unit scanner-selfupdate). The service will restart — reconnect in ~30 seconds.",
	})
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
}

// runInstallerWithSudo launches scripts/install.sh as root inside a transient
// systemd unit (its own cgroup, so it survives the `systemctl restart scanner`
// the installer runs at its end). The password reaches ONLY sudo's stdin; every
// argv element is a trusted absolute path, so there is no shell/argv injection.
func runInstallerWithSudo(pw []byte, root string) (string, error) {
	script := filepath.Join(root, "scripts", "install.sh")
	// -k: drop any cached sudo timestamp; -S: read the password from stdin;
	// -p '': no prompt text. systemd-run --collect: GC the unit after it exits.
	cmd := exec.Command("sudo", "-k", "-S", "-p", "",
		"systemd-run", "--unit=scanner-selfupdate", "--collect",
		"--working-directory="+root,
		"/bin/bash", script, "--yes")
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return "", err
	}
	if err := cmd.Start(); err != nil {
		return "", err
	}
	stdin.Write(pw)
	stdin.Write([]byte("\n"))
	stdin.Close()
	err = cmd.Wait()
	return lastLines(out.String()), err
}
