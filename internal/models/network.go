package models

import "time"

// Network event categories — the top-level filter dimension on the Network
// History screen.
const (
	NetCatVPN          = "vpn"          // VPN tunnel up/down/reconnect
	NetCatInterface    = "interface"    // pinned outbound interface link/IP
	NetCatIntegrity    = "integrity"    // killswitch namespace/iptables integrity
	NetCatConfig       = "config"       // killswitch armed/disarmed/arm-failed
	NetCatConnectivity = "connectivity" // internet reachability (pause/throttle/resume)
	NetCatLeak         = "leak"         // DNS/traffic leak detector
)

// Network event severities (drive UI colouring + a filter).
const (
	NetSevInfo     = "info"
	NetSevWarning  = "warning"
	NetSevCritical = "critical"
)

// Network event types — the pre-defined scenarios surfaced on the Network
// History screen. Each maps to a fixed category via NetworkEventCategory.
const (
	NetEvtVPNDown             = "vpn_down"
	NetEvtVPNReconnecting     = "vpn_reconnecting"
	NetEvtVPNReconnectFailed  = "vpn_reconnect_failed"
	NetEvtVPNUp               = "vpn_up"
	NetEvtInterfaceDown       = "interface_down"
	NetEvtInterfaceIPChanged  = "interface_ip_changed"
	NetEvtKillswitchIntegrity = "killswitch_integrity_failed"
	NetEvtKillswitchRecovered = "killswitch_recovered"
	NetEvtKillswitchArmed     = "killswitch_armed"
	NetEvtKillswitchDisarmed  = "killswitch_disarmed"
	NetEvtKillswitchArmFailed = "killswitch_arm_failed"
	NetEvtInternetDown        = "internet_down"
	NetEvtInternetDegraded    = "internet_degraded"
	NetEvtInternetRestored    = "internet_restored"
	NetEvtDNSLeak             = "dns_leak"
	NetEvtUnprotectedTraffic  = "unprotected_traffic"
)

// NetworkEvent is one network-telemetry record (a VPN drop, killswitch trip,
// connectivity loss, DNS leak, etc.) with a denormalized snapshot of the active
// interface/scope at the moment it happened. It is GLOBAL (machine-level, no
// workspace_id and no foreign keys) and — unlike the immutable audit log —
// prunable: it is operational troubleshooting telemetry, not a compliance trail.
type NetworkEvent struct {
	ID              string    `db:"id"               json:"id"`
	TS              time.Time `db:"ts"               json:"ts"`
	EventType       string    `db:"event_type"       json:"event_type"`
	Category        string    `db:"category"         json:"category"`
	Severity        string    `db:"severity"         json:"severity"`
	Interface       string    `db:"interface"        json:"interface"`
	InterfaceIP     string    `db:"interface_ip"     json:"interface_ip"`
	KillswitchScope string    `db:"killswitch_scope" json:"killswitch_scope"`
	VPNConnection   string    `db:"vpn_connection"   json:"vpn_connection"`
	Reachable       int       `db:"reachable"        json:"reachable"`      // 0..3 probe hosts answering (connectivity events)
	DNSOK           int       `db:"dns_ok"           json:"dns_ok"`         // 1 = system resolver healthy
	ScansAffected   int       `db:"scans_affected"   json:"scans_affected"` // scans this event paused/cancelled/resumed
	Detail          string    `db:"detail"           json:"detail"`
}

// NetworkEventCategory returns the fixed filter category for an event type, so
// every emit site and the UI agree without each carrying the category.
func NetworkEventCategory(eventType string) string {
	switch eventType {
	case NetEvtVPNDown, NetEvtVPNReconnecting, NetEvtVPNReconnectFailed, NetEvtVPNUp:
		return NetCatVPN
	case NetEvtInterfaceDown, NetEvtInterfaceIPChanged:
		return NetCatInterface
	case NetEvtKillswitchIntegrity, NetEvtKillswitchRecovered:
		return NetCatIntegrity
	case NetEvtKillswitchArmed, NetEvtKillswitchDisarmed, NetEvtKillswitchArmFailed:
		return NetCatConfig
	case NetEvtInternetDown, NetEvtInternetDegraded, NetEvtInternetRestored:
		return NetCatConnectivity
	case NetEvtDNSLeak, NetEvtUnprotectedTraffic:
		return NetCatLeak
	default:
		return ""
	}
}
