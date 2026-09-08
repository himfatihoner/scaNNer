package handlers

import (
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	scannet "scanner/internal/network"
)

// LeakReportPage renders an admin-only, one-click "paste this to Claude" leak
// report. It gathers the LIVE state the operator would otherwise have to run by
// hand — killswitch mode, the scaNNer iptables OUTPUT rules, /etc/resolv.conf,
// the routing table, and the tail of leakwatch.log — and assembles them with an
// instruction preamble into a single copy-paste block, so a DNS-leak can be
// reported to Claude without remembering any commands. Admin-only (gated in
// authorizePath: prefix "/leak-report").
func (h *Handler) LeakReportPage(w http.ResponseWriter, r *http.Request) {
	data := h.baseData(r, "Leak Report - scaNNer", "leakreport")
	data["Report"] = h.buildLeakReport()
	data["GeneratedAt"] = time.Now().Format("2006-01-02 15:04:05")
	h.render(w, "layout", data)
}

func lrDataDir() string {
	d := os.Getenv("DATA_DIR")
	if d == "" {
		d = "data"
	}
	return d
}

// lrCmd runs a fixed (no user input) local diagnostic command and returns its
// combined output, folding any error into the text so the report is always
// informative (e.g. "iptables: permission denied" tells us caps are missing).
func lrCmd(name string, args ...string) string {
	out, err := exec.Command(name, args...).CombinedOutput()
	s := strings.TrimRight(string(out), "\n")
	if err != nil {
		if s != "" {
			s += "\n"
		}
		s += "(" + name + ": " + err.Error() + ")"
	}
	if strings.TrimSpace(s) == "" {
		s = "(no output)"
	}
	return s
}

func lrTail(path string, n int) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return "(" + path + " okunamadı: " + err.Error() +
			" — leakwatch servisi kurulu/çalışıyor mu? scripts/LEAKWATCH.md)"
	}
	body := strings.TrimRight(string(b), "\n")
	if body == "" {
		return "(leakwatch.log boş — henüz kayıt yok)"
	}
	lines := strings.Split(body, "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}

// buildLeakReport assembles the paste-ready prompt.
func (h *Handler) buildLeakReport() string {
	armed := scannet.IsActive()
	scope := scannet.KillswitchScope()
	vpn := h.db.GetSettings().NetworkInterface
	if vpn == "" {
		vpn = "(default routing / none)"
	}

	// Only our own OUTPUT rules — keep the block short + relevant.
	var ks []string
	for _, l := range strings.Split(lrCmd("iptables", "-S", "OUTPUT"), "\n") {
		if strings.Contains(l, scannet.IptablesComment) {
			ks = append(ks, l)
		}
	}
	ksText := strings.Join(ks, "\n")
	if strings.TrimSpace(ksText) == "" {
		ksText = "(no " + scannet.IptablesComment + " OUTPUT rules — killswitch not armed, or iptables unreadable)"
	}

	logPath := filepath.Join(lrDataDir(), "leakwatch.log")

	var b strings.Builder
	b.WriteString("scaNNer DNS-leak follow-up. leakwatch bir sızıntı tespit etti (ya da şüpheleniyorum).\n")
	b.WriteString("Aşağıdaki CANLI çıktıları oku; memory'lerini yükle (project_dns_killswitch + project_leak_detector);\n")
	b.WriteString("sızıntının kökenini bul ve düzelt. Triyaj sırası project_leak_detector memory'sinde.\n\n")
	fmt.Fprintf(&b, "## Killswitch state (app)\narmed=%v  scope=%s  vpn_iface=%s\n\n", armed, scope, vpn)
	fmt.Fprintf(&b, "## iptables -S OUTPUT | grep scaNNer\n%s\n\n", ksText)
	fmt.Fprintf(&b, "## cat /etc/resolv.conf\n%s\n\n", lrTail("/etc/resolv.conf", 30))
	fmt.Fprintf(&b, "## ip route\n%s\n\n", lrCmd("ip", "route"))
	fmt.Fprintf(&b, "## tail -50 %s\n%s\n", logPath, lrTail(logPath, 50))
	return b.String()
}
