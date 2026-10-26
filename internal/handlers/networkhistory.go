package handlers

import (
	"net/http"
	"time"

	"scanner/internal/database"
	"scanner/internal/models"
	scannet "scanner/internal/network"
)

// netEventRow decorates a NetworkEvent with a human-readable label for the UI,
// keeping the page self-contained (no FuncMap change). The embedded event's
// fields (.TS, .Severity, .Detail, …) stay accessible in the template.
type netEventRow struct {
	models.NetworkEvent
	Label string
}

// netEventLabel maps an event type to a short human label. The returned string
// is also an i18n key — the template runs it through T and tr.json carries the
// Turkish.
func netEventLabel(eventType string) string {
	switch eventType {
	case models.NetEvtVPNDown:
		return "VPN down"
	case models.NetEvtVPNReconnecting:
		return "VPN reconnecting"
	case models.NetEvtVPNReconnectFailed:
		return "VPN reconnect failed"
	case models.NetEvtVPNUp:
		return "VPN back up"
	case models.NetEvtInterfaceDown:
		return "Interface down"
	case models.NetEvtInterfaceIPChanged:
		return "Interface IP changed"
	case models.NetEvtKillswitchIntegrity:
		return "Killswitch integrity failed"
	case models.NetEvtKillswitchRecovered:
		return "Killswitch recovered"
	case models.NetEvtKillswitchArmed:
		return "Killswitch armed"
	case models.NetEvtKillswitchDisarmed:
		return "Killswitch disarmed"
	case models.NetEvtKillswitchArmFailed:
		return "Killswitch arm failed"
	case models.NetEvtInternetDown:
		return "Internet lost"
	case models.NetEvtInternetDegraded:
		return "Internet degraded"
	case models.NetEvtInternetRestored:
		return "Internet restored"
	case models.NetEvtDNSLeak:
		return "DNS leak detected"
	case models.NetEvtUnprotectedTraffic:
		return "Unprotected traffic"
	default:
		return eventType
	}
}

// netRangeSince maps a time-range filter token to a lower-bound time; "" / "all"
// returns nil (no bound).
func netRangeSince(rng string) *time.Time {
	var d time.Duration
	switch rng {
	case "1h":
		d = time.Hour
	case "24h":
		d = 24 * time.Hour
	case "7d":
		d = 7 * 24 * time.Hour
	case "30d":
		d = 30 * 24 * time.Hour
	default:
		return nil
	}
	t := time.Now().Add(-d)
	return &t
}

// NetworkHistoryPage renders the admin-only Network History screen: a
// filterable, retrospective timeline of every network event scaNNer detected or
// caused (VPN drops, killswitch trips, connectivity loss, DNS leaks). Read-only
// — rows are written by the background monitors, never from here.
func (h *Handler) NetworkHistoryPage(w http.ResponseWriter, r *http.Request) {
	rng := r.URL.Query().Get("range")
	filter := database.NetworkEventFilter{
		Category:      r.URL.Query().Get("category"),
		Severity:      r.URL.Query().Get("severity"),
		ScanAffecting: r.URL.Query().Get("scan_affecting") == "1",
		Since:         netRangeSince(rng),
		Limit:         1000,
	}
	events, _ := h.db.ListNetworkEvents(filter)
	rows := make([]netEventRow, 0, len(events))
	for _, e := range events {
		rows = append(rows, netEventRow{NetworkEvent: e, Label: netEventLabel(e.EventType)})
	}

	st := h.db.GetSettings()
	leakActive, _, _, leakCount := leakAlert.snapshot()

	data := h.baseData(r, "Network History - scaNNer", "networkhistory")
	data["Events"] = rows
	data["Count"] = len(rows)
	data["FilterCategory"] = filter.Category
	data["FilterSeverity"] = filter.Severity
	data["FilterRange"] = rng
	data["FilterScanAffecting"] = filter.ScanAffecting
	// Live current-state strip (reuses existing getters — no new probing).
	data["KSArmed"] = scannet.IsActive()
	data["KSMonitoring"] = scannet.IsMonitoring()
	data["NetIface"] = st.NetworkInterface
	data["NetScope"] = st.KillswitchScope
	data["NetHealth"] = netHealthLabel()
	data["LeakActive"] = leakActive
	data["LeakCount"] = leakCount
	h.render(w, "layout", data)
}
