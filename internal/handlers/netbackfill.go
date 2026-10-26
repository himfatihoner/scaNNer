package handlers

import (
	"bufio"
	"os"
	"strings"
	"time"

	"scanner/internal/database"
	"scanner/internal/models"
)

// BackfillNetworkEvents seeds the Network History log — once, idempotently —
// from sources that predate it, so the retrospective screen is not empty on
// first run: finished scan rows whose reason was a network event, plus the
// external leakwatch.log if one exists. Every row carries a deterministic id,
// so re-running on each startup inserts nothing new. The historical egress path
// is unknown, so iface/scope are left blank rather than stamped with the current
// settings. Lossy by design: an event that killed zero scans leaves no scan row
// (the leakwatch.log pass recovers some; live capture covers the rest forward).
func (h *Handler) BackfillNetworkEvents() {
	h.backfillNetFromScans()
	h.backfillNetFromLeakLog()
}

func (h *Handler) backfillNetFromScans() {
	scans, err := h.db.ListScansForNetBackfill()
	if err != nil {
		return
	}
	for _, s := range scans {
		evtType, sev := classifyScanNetReason(s.ProgressMsg)
		if evtType == "" {
			continue
		}
		ts := s.CreatedAt
		switch {
		case s.FinishedAt != nil:
			ts = *s.FinishedAt
		case s.StartedAt != nil:
			ts = *s.StartedAt
		}
		h.db.AddNetworkEvent(models.NetworkEvent{
			ID:            database.NetEventBackfillID("scan:" + s.ID),
			TS:            ts,
			EventType:     evtType,
			Severity:      sev,
			ScansAffected: 1,
			Detail:        s.ProgressMsg,
		})
	}
}

// classifyScanNetReason maps a scan's stored reason (progress_msg) to a network
// event type. Mirrors the reason strings written by the killswitch monitor
// (markErr "killswitch: …"), the connectivity/VPN pause (PauseAll "Paused — …")
// and the leak detector (MarkScanError "DNS leak detected …").
func classifyScanNetReason(msg string) (eventType, severity string) {
	switch {
	case strings.HasPrefix(msg, "DNS leak detected"):
		return models.NetEvtDNSLeak, models.NetSevCritical
	case strings.HasPrefix(msg, "Paused — VPN"):
		return models.NetEvtVPNDown, models.NetSevCritical
	case strings.HasPrefix(msg, "Paused — internet"):
		return models.NetEvtInternetDown, models.NetSevCritical
	case strings.HasPrefix(msg, "killswitch:"):
		switch {
		case strings.Contains(msg, "IP changed"):
			return models.NetEvtInterfaceIPChanged, models.NetSevCritical
		case strings.Contains(msg, "namespace health"):
			return models.NetEvtKillswitchIntegrity, models.NetSevCritical
		default:
			return models.NetEvtInterfaceDown, models.NetSevCritical
		}
	}
	return "", ""
}

func (h *Handler) backfillNetFromLeakLog() {
	f, err := os.Open(leakLogPath())
	if err != nil {
		return // no external leakwatch log on this box → nothing to seed
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		var evtType, sev string
		switch {
		case strings.Contains(line, " LEAK "):
			evtType, sev = models.NetEvtDNSLeak, models.NetSevCritical
		case strings.Contains(line, " UNPROTECTED "):
			evtType, sev = models.NetEvtUnprotectedTraffic, models.NetSevWarning
		default:
			continue
		}
		tsStr, detail := parseLeakLine(line)
		e := models.NetworkEvent{
			ID:        database.NetEventBackfillID("leak:" + line),
			EventType: evtType,
			Severity:  sev,
			Detail:    detail,
		}
		// leakwatch.py stamps each line with an RFC3339 timestamp; parse it so
		// the backfilled row keeps the real time. If it won't parse, leave TS
		// zero and AddNetworkEvent stamps now (better present than dropped).
		if ts, perr := time.Parse(time.RFC3339, tsStr); perr == nil {
			e.TS = ts
		}
		h.db.AddNetworkEvent(e)
	}
}
