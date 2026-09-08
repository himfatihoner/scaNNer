#!/usr/bin/env python3
"""
scaNNer leakwatch — long-running DNS-leak detector for the scaNNer killswitch.

WHAT IT DOES
  Watches the box's NON-VPN interface(s) for DNS queries that belong to a
  currently-active scaNNer scan target. If such a query appears off the VPN
  while the killswitch is armed, that is a real DNS leak — the killswitch should
  have kept scan DNS on the VPN. Management probes (the connectivity health
  check to cloudflare.com, NVD/GitHub/NTP, etc.) legitimately use the normal
  route in scan_only mode and are allow-listed, so false positives are low.

WHY IT'S "SMART" ABOUT MODE
  It reads the killswitch state from the LIVE iptables rules — no coupling to
  scaNNer internals:
    - armed?      -> an OUTPUT rule tagged "scaNNer-killswitch" exists
    - scope       -> the DROP rule carrying "--mark 0x5343" => scan_only,
                     otherwise all_traffic
    - VPN iface   -> the "! -o <iface>" in that DROP rule
  and it reads the active scan targets from scaNNer's SQLite DB (read-only).

OUTPUT
  Appends greppable lines to LEAKWATCH_LOG (default <repo>/data/leakwatch.log)
  and prints them (so `journalctl -u scanner-leakwatch` shows them too):
    <ts> LEAK        iface=eth0 query=sub.t.com target=t.com dst=1.0.0.1 killswitch=armed/scan_only vpn=tun0
    <ts> UNPROTECTED iface=eth0 query=... target=...   (a scan-target query off-VPN while killswitch is OFF)
    <ts> STATE       killswitch=armed/scan_only vpn=tun0 nonvpn=eth0 active_targets=3 leaks_total=0
    <ts> KILLSWITCH  changed armed/scan_only -> off        (integrity: silent disarm = everything would leak)

RUN
  sudo python3 leakwatch.py            (needs root: tcpdump raw socket + iptables read)
  env: SCANNER_DB, LEAKWATCH_LOG, LEAKWATCH_HEARTBEAT_SEC (default 600),
       LEAKWATCH_REFRESH_SEC (default 15)

No third-party deps — Python 3 stdlib only.
"""
import os, re, sys, json, time, signal, sqlite3, subprocess, threading
from datetime import datetime, timezone

KS_COMMENT = "scaNNer-killswitch"
SCAN_MARK = "0x5343"

# Management destinations that legitimately use the normal route in scan_only.
# A query whose name ends in one of these is never treated as a leak.
ALLOWLIST = (
    "cloudflare.com", "nist.gov", "mitre.org", "github.com", "githubusercontent.com",
    "githubassets.com", "debian.org", "kali.org", "ubuntu.com", "ntp.org",
    "pool.ntp.org", "ubuntu.pool.ntp.org", "archive.ubuntu.com", "in-addr.arpa",
    "ip6.arpa", "local", "localdomain",
)

def _repo_default_db():
    for p in ("~/scaNNer/data/scanner.db", "./data/scanner.db",
              os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "data", "scanner.db"),
              "/home/user/scaNNer/data/scanner.db"):
        p = os.path.abspath(os.path.expanduser(p))
        if os.path.exists(p):
            return p
    return os.path.abspath(os.path.expanduser("~/scaNNer/data/scanner.db"))

DB = os.environ.get("SCANNER_DB") or _repo_default_db()
LOGFILE = os.environ.get("LEAKWATCH_LOG") or os.path.join(os.path.dirname(DB), "leakwatch.log")
HEARTBEAT_SEC = int(os.environ.get("LEAKWATCH_HEARTBEAT_SEC", "600"))
REFRESH_SEC = int(os.environ.get("LEAKWATCH_REFRESH_SEC", "15"))

# DNS query name in tcpdump output: "... A? foo.example.com. (32)" / "AAAA? x. (43)"
_QRE = re.compile(r"\?\s+([A-Za-z0-9._-]+?)\.?\s+\(")
# destination server (…> 1.0.0.1.53:)
_DSTRE = re.compile(r">\s+([0-9a-fA-F:.]+)\.53:")

_stop = threading.Event()
_state_lock = threading.Lock()
_leaks_total = 0


def now():
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def log(msg):
    line = f"{now()} {msg}"
    print(line, flush=True)
    try:
        with open(LOGFILE, "a") as f:
            f.write(line + "\n")
    except Exception:
        pass


def killswitch_state():
    """(armed: bool, scope: 'scan_only'|'all_traffic'|None, vpn_iface: str|None)."""
    try:
        out = subprocess.run(["iptables", "-S", "OUTPUT"], capture_output=True,
                             text=True, timeout=5).stdout
    except Exception:
        return (False, None, None)
    rules = [l for l in out.splitlines() if KS_COMMENT in l]
    if not rules:
        return (False, None, None)
    vpn, scope = None, "all_traffic"
    for l in rules:
        if "-j DROP" in l:
            m = re.search(r"! -o (\S+)", l)
            if m:
                vpn = m.group(1)
            if SCAN_MARK in l:
                scope = "scan_only"
    return (True, scope, vpn)


def nonvpn_ifaces(vpn):
    try:
        out = subprocess.run(["ip", "-br", "link"], capture_output=True,
                             text=True, timeout=5).stdout
    except Exception:
        return []
    ifs = []
    for l in out.splitlines():
        parts = l.split()
        if not parts:
            continue
        name = parts[0].split("@")[0]
        if name == "lo" or name == vpn:
            continue
        if name.startswith(("tun", "wg", "ppp")):  # other tunnels are VPN-like too
            continue
        if "UP" in l:  # link up (state col or flags)
            ifs.append(name)
    return ifs


def guess_vpn(vpn_from_rule):
    if vpn_from_rule:
        return vpn_from_rule
    try:
        out = subprocess.run(["ip", "-br", "link"], capture_output=True,
                             text=True, timeout=5).stdout
    except Exception:
        return None
    for l in out.splitlines():
        parts = l.split()
        if parts and parts[0].split("@")[0].startswith(("tun", "wg", "ppp")) and "UP" in l:
            return parts[0].split("@")[0]
    return None


def _norm(t):
    t = (t or "").strip().lower()
    t = re.sub(r"^[a-z]+://", "", t)
    t = t.split("/")[0].split(":")[0]
    return t


def scan_targets():
    """Domain-shaped targets of running/pending scans (skip bare IPs — no DNS)."""
    targets = set()
    try:
        con = sqlite3.connect(f"file:{DB}?mode=ro", uri=True, timeout=3)
        try:
            cur = con.execute("SELECT config FROM scans WHERE status IN ('running','pending')")
            for (cfg,) in cur.fetchall():
                try:
                    d = json.loads(cfg or "{}")
                except Exception:
                    continue
                vals = []
                for key in ("targets", "domains", "hosts", "urls"):
                    v = d.get(key)
                    if isinstance(v, list):
                        vals += v
                for key in ("target", "domain", "url"):
                    v = d.get(key)
                    if isinstance(v, str):
                        vals.append(v)
                for t in vals:
                    n = _norm(t)
                    # keep only names (a DNS leak needs a name to resolve)
                    if n and not re.fullmatch(r"[0-9.]+", n) and "." in n:
                        targets.add(n)
        finally:
            con.close()
    except Exception:
        pass
    return targets


def is_allowlisted(q):
    return any(q == a or q.endswith("." + a) for a in ALLOWLIST)


def matched_target(q, targets):
    for t in targets:
        if q == t or q.endswith("." + t):
            return t
    return None


# shared snapshot updated by the refresher, read by the sniffers
_snap = {"armed": False, "scope": None, "vpn": None, "targets": set()}


def sniff(iface):
    """Run tcpdump -Q out on iface; correlate outbound DNS query names to targets."""
    global _leaks_total
    cmd = ["tcpdump", "-i", iface, "-nn", "-l", "-p", "-Q", "out",
           "udp port 53 or tcp port 53"]
    while not _stop.is_set():
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                    text=True, bufsize=1)
        except FileNotFoundError:
            log(f"ERROR tcpdump not found — cannot sniff {iface}")
            return
        except Exception as e:
            log(f"ERROR tcpdump on {iface}: {e}")
            time.sleep(5)
            continue
        try:
            for line in proc.stdout:
                if _stop.is_set():
                    break
                m = _QRE.search(line)
                if not m:
                    continue
                q = m.group(1).lower().rstrip(".")
                if not q or is_allowlisted(q):
                    continue
                with _state_lock:
                    armed = _snap["armed"]; scope = _snap["scope"]
                    vpn = _snap["vpn"]; targets = _snap["targets"]
                t = matched_target(q, targets)
                if not t:
                    continue  # not a scan target → not our concern (browsing, etc.)
                dm = _DSTRE.search(line)
                dst = dm.group(1) if dm else "?"
                if armed:
                    _leaks_total += 1
                    log(f"LEAK        iface={iface} query={q} target={t} dst={dst} "
                        f"killswitch=armed/{scope} vpn={vpn} leaks_total={_leaks_total}")
                else:
                    log(f"UNPROTECTED iface={iface} query={q} target={t} dst={dst} "
                        f"killswitch=off (scan-target DNS on non-VPN iface while killswitch disabled)")
        except Exception as e:
            log(f"WARN sniff loop {iface}: {e}")
        finally:
            try:
                proc.terminate()
            except Exception:
                pass
        if not _stop.is_set():
            time.sleep(2)  # tcpdump died (iface flap) — respawn


def main():
    log(f"START leakwatch db={DB} log={LOGFILE} heartbeat={HEARTBEAT_SEC}s refresh={REFRESH_SEC}s")
    if os.geteuid() != 0:
        log("WARN not running as root — tcpdump/iptables likely to fail")

    prev_ks = None
    sniffers = {}
    last_hb = 0.0

    def handle_sig(*_):
        _stop.set()
    signal.signal(signal.SIGTERM, handle_sig)
    signal.signal(signal.SIGINT, handle_sig)

    while not _stop.is_set():
        armed, scope, vpn = killswitch_state()
        vpn = guess_vpn(vpn)
        targets = scan_targets()
        with _state_lock:
            _snap.update(armed=armed, scope=scope, vpn=vpn, targets=targets)

        nv = nonvpn_ifaces(vpn)
        # start a sniffer per non-VPN iface (once)
        for iface in nv:
            if iface not in sniffers or not sniffers[iface].is_alive():
                th = threading.Thread(target=sniff, args=(iface,), daemon=True)
                th.start()
                sniffers[iface] = th
                log(f"SNIFF start iface={iface}")

        ks = f"{'armed/'+str(scope) if armed else 'off'}"
        if prev_ks is not None and ks != prev_ks:
            log(f"KILLSWITCH changed {prev_ks} -> {ks} vpn={vpn}")
        prev_ks = ks

        t = time.time()
        if t - last_hb >= HEARTBEAT_SEC:
            log(f"STATE       killswitch={ks} vpn={vpn} nonvpn={','.join(nv) or '-'} "
                f"active_targets={len(targets)} leaks_total={_leaks_total}")
            last_hb = t

        _stop.wait(REFRESH_SEC)

    log("STOP leakwatch")


if __name__ == "__main__":
    main()
