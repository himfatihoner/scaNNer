package handlers

import (
	"context"
	"net/http"
	"net/url"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"scanner/internal/sysmon"
)

// The install script drops the sudoers-allowlisted helper here (root:root 0755).
const scannerTunePath = "/usr/local/sbin/scanner-tune"

// netTuneRec is the recommended sysctl target set surfaced in the Settings
// "Network Tuning" panel — matches scripts/install.sh defaults.
type netTuneRec struct {
	PortLo, PortHi, FinTimeout, TWReuse, ConntrackMax, TWBuckets int
}

func recommendedTuning() netTuneRec {
	return netTuneRec{PortLo: 10000, PortHi: 65535, FinTimeout: 15, TWReuse: 1, ConntrackMax: 262144, TWBuckets: 262144}
}

// netTuneAvailable reports whether the helper is installed AND sudo can invoke
// it without a password (i.e. the install script's sudoers drop-in is present).
func netTuneAvailable() bool {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	// `sudo -n -l <path>` lists the rule without running it; succeeds only when a
	// NOPASSWD rule for exactly this command exists.
	return exec.CommandContext(ctx, "sudo", "-n", "-l", scannerTunePath).Run() == nil
}

// SettingsNetworkTune applies operator-edited sysctl network-tuning values via
// the sudoers-allowlisted scanner-tune helper, then redirects back to Settings.
// Per-module capacity recommendations recompute automatically on the next scan
// launch (capacity.Recommend reads live sysmon.Limits each call), so no explicit
// recompute step is needed.
func (h *Handler) SettingsNetworkTune(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/settings", http.StatusSeeOther)
		return
	}
	args := []string{scannerTunePath}
	for _, k := range []string{"port_lo", "port_hi", "fin_timeout", "tw_reuse", "conntrack_max", "tw_buckets"} {
		v := strings.TrimSpace(r.FormValue(k))
		if v == "" {
			continue
		}
		if _, err := strconv.Atoi(v); err != nil { // client-side numeric guard; helper re-validates
			continue
		}
		args = append(args, k+"="+v)
	}
	if len(args) == 1 {
		http.Redirect(w, r, "/settings?error=nettune_no_values#nettune", http.StatusSeeOther)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	// Local privileged helper (not scan traffic) → direct exec, not shared.Command.
	out, err := exec.CommandContext(ctx, "sudo", append([]string{"-n"}, args...)...).CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg == "" {
			msg = err.Error()
		}
		if len(msg) > 200 {
			msg = msg[:200]
		}
		http.Redirect(w, r, "/settings?error=nettune_failed&msg="+url.QueryEscape(msg)+"#nettune", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/settings?success=nettune_applied#nettune", http.StatusSeeOther)
}

// netTuneData builds the template context for the Settings "Network Tuning"
// panel: current live limits, the recommended targets, helper availability, and
// the apply-result flash from the redirect.
func netTuneData(r *http.Request) map[string]any {
	l := sysmon.ReadLimits()
	m := map[string]any{
		"Current":   l,
		"Rec":       recommendedTuning(),
		"Available": netTuneAvailable(),
		"Tuned":     l.UsablePorts() >= 50000 && l.FinTimeout <= 30,
	}
	if r.URL.Query().Get("success") == "nettune_applied" {
		m["OK"] = true
	}
	if e := r.URL.Query().Get("error"); strings.HasPrefix(e, "nettune") {
		msg := r.URL.Query().Get("msg")
		if msg == "" {
			msg = e
		}
		m["Err"] = msg
	}
	return m
}
