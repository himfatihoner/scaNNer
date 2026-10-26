package handlers

import "scanner/internal/models"

// recordNetEvent is the single handler-side sink for Network History events. It
// snapshots the active interface / killswitch scope / VPN connection from
// Settings (so each row preserves the egress path in force at the time) unless
// the caller already set those fields, then appends the event. Safe from any
// goroutine; AddNetworkEvent prunes rows past the retention window on write.
func (h *Handler) recordNetEvent(e models.NetworkEvent) {
	st := h.db.GetSettings()
	if e.Interface == "" {
		e.Interface = st.NetworkInterface
	}
	if e.InterfaceIP == "" {
		e.InterfaceIP = st.NetworkInterfaceIP
	}
	if e.KillswitchScope == "" {
		e.KillswitchScope = st.KillswitchScope
	}
	if e.VPNConnection == "" {
		e.VPNConnection = st.VPNConnection
	}
	h.db.AddNetworkEvent(e)
}

// RecordKillswitchEvent adapts recordNetEvent to network.RecordEventFn so the
// killswitch interface monitor — which must not import this package (import
// cycle) — can log its trips and auto-re-arms through the injected callback.
// Exported because cmd/scanner wires it into StartMonitor at startup too.
func (h *Handler) RecordKillswitchEvent(eventType, severity, iface, detail string, scansAffected int) {
	h.recordNetEvent(models.NetworkEvent{
		EventType:     eventType,
		Severity:      severity,
		Interface:     iface,
		Detail:        detail,
		ScansAffected: scansAffected,
	})
}

// netBool converts a bool to the 0/1 integer the network_events columns store.
func netBool(b bool) int {
	if b {
		return 1
	}
	return 0
}
