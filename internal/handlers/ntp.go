package handlers

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"scanner/internal/auth"
)

// TOTP verification depends on the server clock, and it only tolerates ~90s of
// skew — a drifting host clock silently breaks authenticator logins. The proper
// fix is host-level NTP (chrony / systemd-timesyncd), but as a self-contained
// fallback the operator can point scaNNer at an NTP server here: we query it,
// measure the (ntp - local) offset, and feed that into TOTP time. We NEVER set
// the system clock (that needs root and fights the OS time daemon) — the offset
// is applied only when computing TOTP steps (see auth.SetClockOffset).

// queryNTP performs one SNTP (RFC 4330) round-trip and returns the offset to
// add to the local clock to match the server. UDP/123, host routing (a plain
// net.Dialer, like the mailer) so it works regardless of the killswitch.
func queryNTP(server string, timeout time.Duration) (time.Duration, error) {
	host := strings.TrimSpace(server)
	if host == "" {
		return 0, fmt.Errorf("no NTP server configured")
	}
	if !strings.Contains(host, ":") {
		host += ":123"
	}
	conn, err := net.DialTimeout("udp", host, timeout)
	if err != nil {
		return 0, fmt.Errorf("ntp dial: %w", err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return 0, err
	}
	req := make([]byte, 48)
	req[0] = 0x1B // LI = 0, VN = 3, Mode = 3 (client)
	t1 := time.Now()
	if _, err := conn.Write(req); err != nil {
		return 0, fmt.Errorf("ntp write: %w", err)
	}
	resp := make([]byte, 48)
	if _, err := conn.Read(resp); err != nil {
		return 0, fmt.Errorf("ntp read: %w", err)
	}
	t4 := time.Now()
	// Transmit timestamp: seconds (bytes 40-43) + fraction (44-47), NTP epoch 1900.
	secs := binary.BigEndian.Uint32(resp[40:44])
	frac := binary.BigEndian.Uint32(resp[44:48])
	if secs == 0 {
		return 0, fmt.Errorf("ntp: empty/kiss-o'-death response")
	}
	const ntpUnixEpochOffset = 2208988800 // seconds between 1900 and 1970
	nsec := (int64(frac) * 1_000_000_000) >> 32
	serverTime := time.Unix(int64(secs)-ntpUnixEpochOffset, nsec)
	// Offset relative to the midpoint of our send/receive removes ~half the RTT.
	mid := t1.Add(t4.Sub(t1) / 2)
	return serverTime.Sub(mid), nil
}

type ntpStatus struct {
	Server  string
	Offset  time.Duration
	Checked time.Time
	Err     string
	OK      bool
}

var (
	ntpMu   sync.RWMutex
	ntpLast ntpStatus
)

// refreshNTP re-measures the offset against the currently-saved NTP server and
// applies it to TOTP. On failure it keeps the last good offset (no flapping);
// with no server configured it clears the correction (trust the local clock).
func (h *Handler) refreshNTP() {
	server := strings.TrimSpace(h.db.GetSettings().NTPServer)
	st := ntpStatus{Server: server, Checked: time.Now()}
	if server == "" {
		auth.SetClockOffset(0)
		st.OK = true
	} else if off, err := queryNTP(server, 5*time.Second); err != nil {
		st.Err = err.Error()
	} else {
		auth.SetClockOffset(off)
		st.OK = true
	}
	st.Offset = auth.ClockOffset()
	ntpMu.Lock()
	ntpLast = st
	ntpMu.Unlock()
}

// StartNTPRefresh does an initial check then re-checks every 30 minutes.
func (h *Handler) StartNTPRefresh() {
	h.refreshNTP()
	go func() {
		for {
			time.Sleep(30 * time.Minute)
			h.refreshNTP()
		}
	}()
}

// SettingsNTPCheck is the "Check now" button — re-measures against the saved
// server and flashes the result back to the Settings clock panel.
func (h *Handler) SettingsNTPCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/settings", http.StatusSeeOther)
		return
	}
	h.refreshNTP()
	ntpMu.RLock()
	st := ntpLast
	ntpMu.RUnlock()
	if st.Err != "" {
		http.Redirect(w, r, "/settings?error=ntp&msg="+url.QueryEscape(st.Err)+"#ntp", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/settings?success=ntp#ntp", http.StatusSeeOther)
}

// ntpData builds the Settings "Server Clock" panel context.
func ntpData() map[string]any {
	ntpMu.RLock()
	st := ntpLast
	ntpMu.RUnlock()
	now := time.Now()
	offMS := st.Offset.Milliseconds()
	m := map[string]any{
		"Server":        st.Server,
		"Configured":    st.Server != "",
		"OffsetMS":      offMS,
		"OffsetHuman":   st.Offset.Round(time.Millisecond).String(),
		"Err":           st.Err,
		"LocalTime":     now.Format("2006-01-02 15:04:05 MST"),
		"CorrectedTime": now.Add(st.Offset).Format("2006-01-02 15:04:05"),
		// TOTP tolerates ~90s; warn well before that so 2FA never silently fails.
		"Skewed": offMS > 30000 || offMS < -30000,
	}
	if !st.Checked.IsZero() {
		m["Checked"] = st.Checked.Format("2006-01-02 15:04:05")
	}
	return m
}
