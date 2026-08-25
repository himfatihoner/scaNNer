# scaNNer install & runtime-tuning scripts

Root-run, security-sensitive helpers that provision the host for scaNNer and
let the running scanner re-tune the network stack from its UI. **Author-only:
these are meant to be run by the operator with `sudo`; do not run them from
automation.**

## Why these exist

On a NAT'd VM, heavy scans exhaust the ephemeral local-port range. The kernel
default `ip_local_port_range` is `32768-60999` (28 232 usable ports) and
`tcp_fin_timeout` is `60s`, so every short-lived outbound socket parks a port
for a minute. A big scan opens tens of thousands of connections, the port table
fills, and new connects fail with `EADDRNOTAVAIL` — "the network fills up".
`install.sh` widens the range and shortens the timeout; `scanner-tune` lets you
adjust it later without editing files by hand.

## Files

| File | Purpose |
|------|---------|
| `install.sh` | One-shot installer (run once, as root). Checks prerequisites (and can auto-install them), **builds the `./scanner` binary**, tunes sysctl, sets FD limits, installs the systemd unit (with `AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW`), installs `scanner-tune` + sudoers rules, and on Kali sets up the killswitch's netfilter/xtables prerequisites. |
| `uninstall.sh` | Reverses the installer: stops/disables/removes the service, removes the sudoers/sysctl/limits/Kali drop-ins, and removes the built `./scanner` binary (`--keep-binary` to keep it). Leaves the repo source and your data (`data/scanner.db`) untouched. |
| `scanner-tune` | Runtime re-tuning helper, installed to `/usr/local/sbin/scanner-tune`. The scanner calls it via `sudo -n` to change the six network tunables live. |
| `README.md` | This file. |

## Install

```sh
sudo scripts/install.sh          # interactive: shows current vs recommended, prompts
sudo scripts/install.sh --yes    # non-interactive: apply without prompting
```

The installer auto-detects the target user (`$SUDO_USER`/`logname`) and the repo
directory (parent of `scripts/`), and templates both into every file it writes.
It is idempotent — safe to re-run to change values or after moving the repo. If any
step fails it **rolls back every change** and leaves the system as it was.

### Prerequisites

The installer runs a **prerequisite preflight** first: it checks the tools the
scanner shells out to plus the build/update toolchain, prints each as present ✓ /
missing, and offers to **auto-install the apt-packaged ones** (interactive prompt,
or automatic under `--yes`). Tools that install per-user — Go binaries
(`subfinder`, `puredns`, `kerbrute` → `~/go/bin`) and pipx tools (`netexec`,
`bloodhound-python`, `mitm6`, … → `~/.local/bin`) — are shown as copy-paste
commands rather than auto-installed, and those dirs must be on the user's `$PATH`.

After the preflight, `install.sh` **builds the `./scanner` binary itself** (as the
target user, `go build -o ./scanner ./cmd/scanner`) before provisioning the
service — you don't run `go build` by hand.

- **Go ≥ 1.25 + git** are needed to build the binary and for the in-app self-update
  (`Software Update` page). Without Go the installer stops at the build step with
  the exact fix; git is only needed later for self-update.
- **nmap** powers most scan modules. Everything else is optional — a missing tool
  just makes its module unavailable; the app degrades gracefully.

Missing tools never block the install (its own job — the service + killswitch —
succeeds regardless); they're reported with exact fix commands. Auto-installed apt
packages persist even if a later install step rolls back.

### Tuning overrides

Every tunable has a default you can override with an environment variable:

| Env var | Default | sysctl key |
|---------|---------|-----------|
| `PORT_LO` | `10000` | `net.ipv4.ip_local_port_range` (low) |
| `PORT_HI` | `65535` | `net.ipv4.ip_local_port_range` (high) |
| `FIN_TIMEOUT` | `15` | `net.ipv4.tcp_fin_timeout` |
| `TW_REUSE` | `1` | `net.ipv4.tcp_tw_reuse` |
| `CONNTRACK_MAX` | `262144` | `net.netfilter.nf_conntrack_max` (only if the param exists) |
| `TW_BUCKETS` | `262144` | `net.ipv4.tcp_max_tw_buckets` |

```sh
sudo PORT_LO=15000 FIN_TIMEOUT=10 scripts/install.sh --yes
```

In interactive mode you can also type `e` at the confirm prompt to edit each
value inline. Values are validated (numeric, sane ranges, `port_lo < port_hi`)
before anything is written.

### The service is NOT auto-enabled

The installer writes and `daemon-reload`s the unit but does not enable it by
default, because you currently run `./scanner` by hand. It prints the exact
command and offers to enable it. If you enable it while a manual instance is
still on `:9090`, the service can't bind — stop the manual one first.

```sh
sudo systemctl enable --now scanner
```

## Re-tuning from the UI

Settings → **Network Tuning** invokes:

```sh
sudo -n /usr/local/sbin/scanner-tune port_lo=15000 fin_timeout=10
```

`scanner-tune` only accepts the six allowlisted keys
(`port_lo`, `port_hi`, `fin_timeout`, `tw_reuse`, `conntrack_max`, `tw_buckets`),
validates them as integers in range, rewrites `/etc/sysctl.d/99-scanner.conf`
(keeping any key you didn't pass at its current value), runs `sysctl --system`,
and prints `OK` plus the applied `key=value` lines. On any bad input it prints
`ERROR: ...` to stderr and exits non-zero. You can run the same command by hand.

**Security model:** the sudoers grant is NOPASSWD but bounded — a fixed
root-owned path, a strict argument allowlist, and numeric validation mean the
helper can only ever set those six kernel tunables to in-range integers.

## Rebuild loop

Because capabilities are ambient (injected by systemd, not `setcap` on the
binary), a rebuild doesn't lose them:

```sh
go build -o ./scanner ./cmd/scanner && sudo systemctl restart scanner
```

## Verify the killswitch after install

```sh
sudo systemctl status scanner
journalctl -u scanner --since "1 minute ago" | grep -i killswitch
```

## Uninstall

```sh
sudo scripts/uninstall.sh          # interactive: lists what it will remove, asks
sudo scripts/uninstall.sh --yes    # non-interactive
```

Removes only the system integration the installer added (the service, sudoers,
sysctl/limits/Kali drop-ins) — the repo, the `./scanner` binary, and your data
(`data/scanner.db`, loot, logs) are left untouched. It's idempotent, and prints
an honest note about the few things (live sysctl values, already-loaded kernel
modules, `netdev` membership) that only fully revert on the next reboot.

