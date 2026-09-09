# leakwatch — DNS-leak detector for the scaNNer killswitch

A tiny always-on watchdog (`leakwatch.py`, Python 3 stdlib only) that runs on
the same box as scaNNer and tells you, over the long term, whether scan DNS is
leaking off the VPN — so you don't have to test every module by hand.

## What counts as a leak

scaNNer's killswitch is supposed to keep **scan** traffic (and, in `all_traffic`
mode, all traffic) on the VPN interface. leakwatch watches the **non-VPN**
interface(s) and flags **scan-target** traffic of ANY protocol appearing there —
a DNS query for a target **domain**, OR a new TCP connection to a target **IP**
(any port, not just DNS):

- It reads killswitch state straight from the live iptables rules — no coupling
  to scaNNer internals:
  - **armed?** an `OUTPUT` rule tagged `scaNNer-killswitch` exists
  - **scope** the `DROP` rule carrying `--mark 0x5343` ⇒ `scan_only`, else `all_traffic`
  - **VPN iface** the `! -o <iface>` in that DROP rule
- It reads the **active scan targets** (running/pending scans) from
  `data/scanner.db` (read-only).
- If scan-target traffic (a DNS query for a target domain, or a TCP SYN to a
  target IP) appears on a non-VPN iface **and** the killswitch is armed → **LEAK**.
- **Scope-aware by construction**: it only ever flags SCAN-TARGET traffic.
  Management (the connectivity health check to `cloudflare.com`, NVD/GitHub/NTP,
  self-update, SMTP) is never a scan target, so it is never flagged — which is
  exactly what you want when the admin runs `scan_only` (management IS allowed
  off the VPN there). Your own browsing isn't a scan target either. Scan traffic
  off-VPN is flagged in every mode; the killswitch mode is logged for context.

## Install (deploy box)

```bash
# scaNNer at /home/user/scaNNer (edit the .service paths if different)
sudo cp /home/user/scaNNer/scripts/scanner-leakwatch.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now scanner-leakwatch
```

Ad-hoc run instead of a service:
```bash
sudo python3 /home/user/scaNNer/scripts/leakwatch.py
```

## Read the findings

```bash
tail -f /home/user/scaNNer/data/leakwatch.log      # or: journalctl -u scanner-leakwatch -f
grep -E ' LEAK | UNPROTECTED ' /home/user/scaNNer/data/leakwatch.log
```

Line types:
- `LEAK        iface=eth0 query=sub.t.com target=t.com dst=1.0.0.1 killswitch=armed/scan_only vpn=tun0`
  — a scan target's DNS left the box off-VPN **while the killswitch was armed**. This is the bug to fix.
- `UNPROTECTED iface=eth0 query=… target=…` — a scan-target query off-VPN while the killswitch is **off** (you were unprotected; not a killswitch bug, but worth knowing).
- `STATE       killswitch=armed/scan_only vpn=tun0 nonvpn=eth0 active_targets=3 leaks_total=0` — periodic heartbeat (default every 10 min) so you can see it's alive and the mode history.
- `KILLSWITCH  changed armed/scan_only -> off` — integrity alert: the rules vanished while you expected them (a silent disarm would leak everything).

## If you see a LEAK — report it to Claude

Paste this into a fresh chat (Claude will re-load the killswitch design from
memory and adapt fast):

```
scaNNer DNS-leak follow-up. leakwatch tespit etti (ya da şüpheleniyorum).
Aşağıdakileri oku, memory'lerini yükle (project_dns_killswitch + project_leak_detector),
sızıntının kökenini bul ve düzelt.

leakwatch log (son satırlar):
$ tail -50 /home/user/scaNNer/data/leakwatch.log
<yapıştır>

killswitch kuralları:
$ sudo iptables -S OUTPUT | grep scaNNer
<yapıştır>

resolv.conf + route:
$ cat /etc/resolv.conf ; ip route
<yapıştır>
```

## Env / tuning

| var | default | meaning |
|---|---|---|
| `SCANNER_DB` | `~/scaNNer/data/scanner.db` (auto-detected) | scaNNer SQLite DB |
| `LEAKWATCH_LOG` | `<db-dir>/leakwatch.log` | findings log |
| `LEAKWATCH_HEARTBEAT_SEC` | `600` | STATE heartbeat interval |
| `LEAKWATCH_REFRESH_SEC` | `15` | killswitch/target re-read interval |
