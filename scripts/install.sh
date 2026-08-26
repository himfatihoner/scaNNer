#!/usr/bin/env bash
#
# scaNNer — one-shot installer (run as root, once, at install time only).
#
#   sudo scripts/install.sh          # interactive (prompts before applying)
#   sudo scripts/install.sh --yes    # non-interactive (accept defaults/overrides)
#
# WHAT THIS DOES
#   1. Tunes the OS network stack so heavy scans stop exhausting the ephemeral
#      port range (the "the network fills up" symptom). Writes
#      /etc/sysctl.d/99-scanner.conf and applies it.
#   2. Raises the open-file limit (systemd unit LimitNOFILE + limits.d fallback).
#   3. Installs a systemd system unit that runs the scanner as the *regular*
#      user but injects CAP_NET_ADMIN/CAP_NET_RAW via AmbientCapabilities, so
#      the killswitch (network namespace + iptables) works without setcap and
#      without root-owned data files. (See the project memory
#      project_install_systemd.md for the rationale — setcap is deliberately
#      rejected because every `go build` overwrites the file and drops the cap.)
#   4. Installs /usr/local/sbin/scanner-tune plus a tightly-scoped sudoers rule
#      so the running scanner can re-tune the network stack from its Settings UI
#      (bounded privilege: fixed path + arg allowlist + numeric validation).
#   5. On Kali: loads the netfilter modules the killswitch needs at boot and
#      makes /run/xtables.lock group-accessible so a CAP_NET_ADMIN (non-root)
#      process can acquire the iptables mutex.
#
# WHY the sysctl tuning matters (root cause):
#   Default ip_local_port_range is 32768-60999 = 28232 usable local ports, and
#   default tcp_fin_timeout is 60s. Every half-closed outbound socket parks a
#   port for that long. A heavy scan opens tens of thousands of short-lived
#   connections; the port table fills and new connections fail with EADDRNOTAVAIL
#   ("cannot assign requested address"). Widening the range and shrinking the
#   FIN timeout keeps ports available.
#
# The script is IDEMPOTENT: re-running overwrites the managed drop-ins in place
# and never duplicates group membership. Safe to run again after a repo move or
# to change tuning values.
#
set -eEuo pipefail   # -E: the ERR trap (transaction rollback) also fires inside functions

# ---------------------------------------------------------------------------
# Tunable defaults. Override any of these via the environment, e.g.:
#   sudo PORT_LO=15000 FIN_TIMEOUT=10 scripts/install.sh --yes
# ---------------------------------------------------------------------------
PORT_LO="${PORT_LO:-10000}"        # net.ipv4.ip_local_port_range (low)
PORT_HI="${PORT_HI:-65535}"        # net.ipv4.ip_local_port_range (high)
FIN_TIMEOUT="${FIN_TIMEOUT:-15}"   # net.ipv4.tcp_fin_timeout (seconds)
TW_REUSE="${TW_REUSE:-1}"          # net.ipv4.tcp_tw_reuse (0..2)
CONNTRACK_MAX="${CONNTRACK_MAX:-262144}"  # net.netfilter.nf_conntrack_max
TW_BUCKETS="${TW_BUCKETS:-262144}"        # net.ipv4.tcp_max_tw_buckets

NOFILE_LIMIT=1048576               # open-file limit for the service + login shell

ASSUME_YES=0

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
usage() {
  cat <<'USAGE'
Usage: sudo scripts/install.sh [--yes|-y]

  --yes, -y   Non-interactive: apply the tuning values without prompting.
              (Use environment variables to override any default.)
  --help, -h  Show this help.

Environment overrides (with defaults):
  PORT_LO=10000  PORT_HI=65535  FIN_TIMEOUT=15  TW_REUSE=1
  CONNTRACK_MAX=262144  TW_BUCKETS=262144
USAGE
}

# Colors — auto-disabled when stdout is not a TTY, NO_COLOR is set, or dumb term,
# so piping to a file / log stays clean.
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ] && [ "${TERM:-dumb}" != "dumb" ]; then
  c_reset=$'\e[0m'; c_bold=$'\e[1m'; c_dim=$'\e[2m'
  c_red=$'\e[31m'; c_grn=$'\e[32m'; c_ylw=$'\e[33m'; c_blu=$'\e[34m'; c_cyn=$'\e[36m'
else
  c_reset=''; c_bold=''; c_dim=''; c_red=''; c_grn=''; c_ylw=''; c_blu=''; c_cyn=''
fi

log()  { printf '%s\n' "$*"; }
info() { printf '  %s%s%s\n' "$c_dim" "$*" "$c_reset"; }              # secondary detail
ok()   { printf '  %s✓%s %s\n' "$c_grn" "$c_reset" "$*"; }           # a completed action
step() { printf '\n%s%s▶%s %s%s%s\n' "$c_bold" "$c_cyn" "$c_reset" "$c_bold" "$*" "$c_reset"; }
hdr()  { printf '%s%s%s%s\n' "$c_bold" "$c_blu" "$*" "$c_reset"; }    # summary section header
warn() { printf '%s⚠%s  %s\n' "$c_ylw" "$c_reset" "$*" >&2; }
die()  {
  printf '%s✗ ERROR:%s %s\n' "$c_red" "$c_reset" "$*" >&2
  # If the transaction is armed, a die() mid-apply must roll everything back.
  if [ "${TX_ARMED:-0}" -eq 1 ]; then tx_rollback "aborted: $*"; fi
  exit 1
}

# ---------------------------------------------------------------------------
# Transaction: if ANY apply step fails, undo everything and leave the system
# exactly as it was before. Files are snapshotted before being overwritten
# (restored on rollback) or removed if we created them; the service is
# stopped/disabled; sysctl values and 'netdev' membership are reverted.
# ---------------------------------------------------------------------------
TX_ARMED=0
STATE_DIR=""
TX_FILES=()
TX_ACTIONS=()
SYSCTL_KEYS="net.ipv4.ip_local_port_range net.ipv4.tcp_fin_timeout net.ipv4.tcp_tw_reuse net.ipv4.tcp_max_tw_buckets net.netfilter.nf_conntrack_max"

fkey() { printf '%s' "$1" | tr '/ ' '__'; }   # filesystem-safe backup key

# tx_backup <path> — call BEFORE overwriting <path>; snapshots its current state.
tx_backup() {
  local f="$1" k
  [ "$TX_ARMED" -eq 1 ] || return 0
  case " ${TX_FILES[*]-} " in *" $f "*) return 0 ;; esac  # once per file
  TX_FILES+=("$f")
  k="$(fkey "$f")"
  if [ -e "$f" ]; then
    cp -a "$f" "$STATE_DIR/f_$k" 2>/dev/null || true
    : > "$STATE_DIR/existed_$k"
  fi
}

tx_note() { [ "$TX_ARMED" -eq 1 ] && TX_ACTIONS+=("$1") || true; }

# tx_begin — arm the transaction: snapshot sysctl values + install the ERR trap.
tx_begin() {
  STATE_DIR="$(mktemp -d)"
  : > "$STATE_DIR/sysctl_orig"
  local k v
  for k in $SYSCTL_KEYS; do
    v="$(sysctl -n "$k" 2>/dev/null || true)"
    [ -n "$v" ] && printf '%s = %s\n' "$k" "$v" >> "$STATE_DIR/sysctl_orig"
  done
  TX_ARMED=1
  trap 'tx_rollback "a step failed"' ERR
}

# tx_rollback [reason] — restore the pre-install state and exit non-zero.
tx_rollback() {
  trap - ERR
  [ "${TX_ARMED:-0}" -eq 1 ] || { rm -rf "$STATE_DIR" 2>/dev/null || true; exit 1; }
  TX_ARMED=0
  printf '\n%s⟲ Rolling back — %s%s\n' "$c_ylw" "${1:-install failed}" "$c_reset" >&2
  # Undo the service we may have enabled/started.
  systemctl stop scanner    >/dev/null 2>&1 || true
  systemctl disable scanner >/dev/null 2>&1 || true
  # Undo extra actions (only ones WE performed this run), newest first.
  local i
  for (( i=${#TX_ACTIONS[@]}-1 ; i>=0 ; i-- )); do
    case "${TX_ACTIONS[$i]}" in
      netdev_added)
        gpasswd -d "$TARGET_USER" netdev >/dev/null 2>&1 || true
        printf '  %s−%s removed %s from the netdev group\n' "$c_ylw" "$c_reset" "$TARGET_USER" >&2 ;;
    esac
  done
  # Restore (if it existed) or remove (if we created it) each touched file.
  for (( i=${#TX_FILES[@]}-1 ; i>=0 ; i-- )); do
    local f="${TX_FILES[$i]}" k; k="$(fkey "$f")"
    if [ -e "$STATE_DIR/existed_$k" ]; then
      cp -a "$STATE_DIR/f_$k" "$f" 2>/dev/null || true
      printf '  %s↺%s restored %s\n' "$c_ylw" "$c_reset" "$f" >&2
    else
      rm -f "$f"
      printf '  %s−%s removed %s\n' "$c_ylw" "$c_reset" "$f" >&2
    fi
  done
  systemctl daemon-reload >/dev/null 2>&1 || true
  [ -s "$STATE_DIR/sysctl_orig" ] && sysctl -p "$STATE_DIR/sysctl_orig" >/dev/null 2>&1 || true
  sysctl --system >/dev/null 2>&1 || true
  rm -rf "$STATE_DIR" 2>/dev/null || true
  printf '%s✗ install rolled back — your system is back to its pre-install state.%s\n' "$c_red" "$c_reset" >&2
  printf '  %sThe failing command'\''s output is above. Fix the cause, then re-run:  sudo scripts/install.sh%s\n' "$c_dim" "$c_reset" >&2
  exit 1
}

# tx_commit — everything succeeded: drop the trap + discard the snapshots.
tx_commit() {
  trap - ERR
  TX_ARMED=0
  rm -rf "$STATE_DIR" 2>/dev/null || true
}

# is_uint <val> -> 0 if a non-negative decimal integer.
is_uint() {
  case "${1:-}" in
    ''|*[!0-9]*) return 1 ;;
    *) return 0 ;;
  esac
}

# in_range <val> <lo> <hi> -> 0 if lo<=val<=hi (val must already be a uint).
in_range() {
  [ "$1" -ge "$2" ] && [ "$1" -le "$3" ]
}

# show_kernel_val <proc-relative-path> <label> — print the live kernel value.
show_kernel_val() {
  local p="/proc/sys/$1" label="$2" v
  if [ -r "$p" ]; then
    # xargs collapses the tab in ip_local_port_range to a single space and
    # strips the trailing newline.
    v="$(xargs <"$p" 2>/dev/null || true)"
    printf '    %-24s = %s\n' "$label" "$v"
  else
    printf '    %-24s = (unavailable)\n' "$label"
  fi
}

# validate_values — check every tunable is numeric and in a sane range.
# Prints all problems to stderr and returns non-zero if any fail (does NOT
# exit, so the interactive editor can re-prompt).
validate_values() {
  local ok=1 pair name val
  for pair in "port_lo:$PORT_LO" "port_hi:$PORT_HI" "fin_timeout:$FIN_TIMEOUT" \
              "tw_reuse:$TW_REUSE" "conntrack_max:$CONNTRACK_MAX" "tw_buckets:$TW_BUCKETS"; do
    name="${pair%%:*}"; val="${pair#*:}"
    if ! is_uint "$val"; then
      printf '  invalid %s: must be a non-negative integer (got %q)\n' "$name" "$val" >&2
      ok=0
    fi
  done
  # Range/cross checks only make sense once every value is a valid integer.
  [ "$ok" -ne 1 ] && return 1
  in_range "$PORT_LO" 1024 65534 || { printf '  port_lo out of range [1024..65534] (got %s)\n' "$PORT_LO" >&2; ok=0; }
  in_range "$PORT_HI" 1025 65535 || { printf '  port_hi out of range [1025..65535] (got %s)\n' "$PORT_HI" >&2; ok=0; }
  [ "$PORT_LO" -lt "$PORT_HI" ]   || { printf '  port_lo (%s) must be < port_hi (%s)\n' "$PORT_LO" "$PORT_HI" >&2; ok=0; }
  in_range "$FIN_TIMEOUT" 1 600   || { printf '  fin_timeout out of range [1..600] (got %s)\n' "$FIN_TIMEOUT" >&2; ok=0; }
  in_range "$TW_REUSE" 0 2         || { printf '  tw_reuse out of range [0..2] (got %s)\n' "$TW_REUSE" >&2; ok=0; }
  in_range "$CONNTRACK_MAX" 1024 33554432 || { printf '  conntrack_max out of range [1024..33554432] (got %s)\n' "$CONNTRACK_MAX" >&2; ok=0; }
  in_range "$TW_BUCKETS" 1024 33554432    || { printf '  tw_buckets out of range [1024..33554432] (got %s)\n' "$TW_BUCKETS" >&2; ok=0; }
  [ "$ok" -eq 1 ]
}

# edit_one <VARNAME> <label> — prompt for a replacement value (blank keeps it).
edit_one() {
  local var="$1" label="$2" cur new
  eval "cur=\${$var}"
  printf '  %-40s [%s]: ' "$label" "$cur"
  read -r new </dev/tty || new=""
  [ -n "$new" ] && eval "$var=\$new"
  return 0
}

edit_values() {
  log "Enter new values (blank keeps the shown value):"
  edit_one PORT_LO       "port_lo  (ip_local_port_range low)"
  edit_one PORT_HI       "port_hi  (ip_local_port_range high)"
  edit_one FIN_TIMEOUT   "fin_timeout  (tcp_fin_timeout secs)"
  edit_one TW_REUSE      "tw_reuse  (tcp_tw_reuse 0..2)"
  edit_one CONNTRACK_MAX "conntrack_max  (nf_conntrack_max)"
  edit_one TW_BUCKETS    "tw_buckets  (tcp_max_tw_buckets)"
}

print_plan() {
  step "Network stack tuning"
  log "  Current kernel values:"
  show_kernel_val net/ipv4/ip_local_port_range   "ip_local_port_range"
  show_kernel_val net/ipv4/tcp_fin_timeout       "tcp_fin_timeout"
  show_kernel_val net/ipv4/tcp_tw_reuse          "tcp_tw_reuse"
  show_kernel_val net/ipv4/tcp_max_tw_buckets    "tcp_max_tw_buckets"
  show_kernel_val net/netfilter/nf_conntrack_max "nf_conntrack_max"
  log "  Values to apply (edit with 'e', override via env vars):"
  printf '    %-24s = %s %s\n' "ip_local_port_range" "$PORT_LO" "$PORT_HI"
  printf '    %-24s = %s\n' "tcp_fin_timeout" "$FIN_TIMEOUT"
  printf '    %-24s = %s\n' "tcp_tw_reuse" "$TW_REUSE"
  printf '    %-24s = %s\n' "tcp_max_tw_buckets" "$TW_BUCKETS"
  if [ "$CONNTRACK_OK" -eq 1 ]; then
    printf '    %-24s = %s\n' "nf_conntrack_max" "$CONNTRACK_MAX"
  else
    printf '    %-24s = %s  (SKIPPED: nf_conntrack param absent)\n' "nf_conntrack_max" "$CONNTRACK_MAX"
  fi
}

# render_sysctl_conf — emit the managed drop-in body to stdout. Kept byte-for-
# byte compatible with scanner-tune's writer so the two never fight over format.
render_sysctl_conf() {
  cat <<EOF
# Managed by scaNNer — /etc/sysctl.d/99-scanner.conf
# Written by scripts/install.sh at ${TS}.
# Re-run scripts/install.sh, or use Settings -> Network Tuning (scanner-tune),
# to change these. Manual edits here are preserved as long as the key names and
# the "key = value" format stay intact.
#
# Purpose: prevent ephemeral-port exhaustion during heavy scans. The kernel
# default range (32768-60999 = 28232 ports) plus tcp_fin_timeout=60 lets a big
# scan park every local port in FIN-WAIT and fail new connects with
# EADDRNOTAVAIL. Widen the range and shorten the timeout to keep ports free.
net.ipv4.ip_local_port_range = ${PORT_LO} ${PORT_HI}
net.ipv4.tcp_fin_timeout = ${FIN_TIMEOUT}
net.ipv4.tcp_tw_reuse = ${TW_REUSE}
net.ipv4.tcp_max_tw_buckets = ${TW_BUCKETS}
EOF
  if [ "$CONNTRACK_OK" -eq 1 ]; then
    printf 'net.netfilter.nf_conntrack_max = %s\n' "$CONNTRACK_MAX"
  else
    # Written as a comment so the value is remembered but sysctl --system does
    # not error on a param that the nf_conntrack module hasn't exposed yet.
    printf '# net.netfilter.nf_conntrack_max = %s  (skipped: nf_conntrack param not present at install time)\n' "$CONNTRACK_MAX"
  fi
}

# MANAGED collects every file this run actually wrote, so the final summary
# reports exactly what changed (never a file that was skipped).
MANAGED=()

# atomic_write <dest> <mode> — install stdin to dest atomically (mktemp + install
# = no truncated file if the disk fills or the script is interrupted mid-write),
# root-owned, and record it for the summary.
atomic_write() {
  local dest="$1" mode="$2" tmp
  tx_backup "$dest"          # snapshot for rollback before overwriting
  tmp="$(mktemp)"
  cat >"$tmp"
  install -m "$mode" -o root -g root "$tmp" "$dest"
  rm -f "$tmp"
  MANAGED+=("$dest")
}

# write_sudoers <name>  (content on stdin) — validate with visudo before install.
# NEVER installs an unvalidated sudoers file: a syntax error in /etc/sudoers.d
# can lock the operator out of sudo entirely.
write_sudoers() {
  local name="$1" tmp
  tx_backup "/etc/sudoers.d/$name"   # snapshot for rollback before overwriting
  tmp="$(mktemp)"
  cat >"$tmp"
  if visudo -cf "$tmp" >/dev/null 2>&1; then
    install -m 0440 -o root -g root "$tmp" "/etc/sudoers.d/$name"
    rm -f "$tmp"
    MANAGED+=("/etc/sudoers.d/$name")
    ok "sudoers /etc/sudoers.d/$name  ${c_dim}(chmod 440, visudo-validated)${c_reset}"
  else
    log "  visudo -cf output for the rejected file:" >&2
    visudo -cf "$tmp" >&2 || true
    rm -f "$tmp"
    die "generated sudoers '$name' failed validation; refusing to install it."
  fi
}

# port_in_use — is something already listening on the scanner's default :9090?
port_in_use() {
  if command -v ss >/dev/null 2>&1; then
    ss -ltn 2>/dev/null | grep -qE '[:.]9090[[:space:]]'
  else
    return 1
  fi
}

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
for arg in "$@"; do
  case "$arg" in
    -y|--yes)  ASSUME_YES=1 ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; die "unknown argument: $arg" ;;
  esac
done

# ---------------------------------------------------------------------------
# Preconditions: must be root; must resolve a real target user and repo dir.
# ---------------------------------------------------------------------------
[ "$(id -u)" -eq 0 ] || die "must be run as root:  sudo scripts/install.sh"

# The real, non-root user this install is FOR. SUDO_USER is set when invoked
# via sudo; logname is the fallback for a plain root login.
TARGET_USER="${SUDO_USER:-$(logname 2>/dev/null || true)}"
[ -n "$TARGET_USER" ] || die "could not determine the target user (set SUDO_USER or run via sudo)."
[ "$TARGET_USER" != "root" ] || die "target user resolved to root; run via 'sudo' from your normal account so files stay user-owned."
id "$TARGET_USER" >/dev/null 2>&1 || die "target user '$TARGET_USER' does not exist."
TARGET_GROUP="$(id -gn "$TARGET_USER")"

# Repo dir = parent of this scripts/ directory, fully resolved.
SCRIPT_DIR="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"
REPO_DIR="$(readlink -f "$SCRIPT_DIR/..")"
[ -f "$REPO_DIR/go.mod" ] || die "$REPO_DIR does not look like the scaNNer repo (no go.mod). Run this from the repo's scripts/ dir."
# systemd exec lines can't reliably carry a path with spaces, so reject it early
# with a clear message rather than writing a unit that fails to start.
case "$REPO_DIR" in
  *[[:space:]]*) die "the repo path contains a space:  $REPO_DIR
       systemd can't reliably launch it. Move the repo to a path without spaces and re-run." ;;
esac

TS="$(date -u '+%Y-%m-%d %H:%M:%S UTC')"

# Detected absolute tool paths (templated into the managed files so sudo/systemd
# match the exact binary). Falls back to conventional locations if not found.
SYSTEMCTL_BIN="$(command -v systemctl 2>/dev/null || echo /usr/bin/systemctl)"
MODPROBE_BIN="$(command -v modprobe 2>/dev/null || echo /usr/sbin/modprobe)"

# Distro gate for the Kali-specific killswitch prerequisites.
IS_KALI=0
if grep -qi kali /etc/os-release 2>/dev/null; then IS_KALI=1; fi

printf '\n  %s%ssca%sNN%ser%s %s· installer%s\n' "$c_bold" "$c_reset" "$c_cyn" "$c_reset$c_bold" "$c_reset" "$c_dim" "$c_reset"
printf '  %starget user%s  %s (group %s)\n' "$c_dim" "$c_reset" "$TARGET_USER" "$TARGET_GROUP"
printf '  %srepo dir%s     %s\n' "$c_dim" "$c_reset" "$REPO_DIR"
printf '  %skali target%s  %s\n' "$c_dim" "$c_reset" "$([ "$IS_KALI" -eq 1 ] && echo yes || echo no)"
[ -x "$REPO_DIR/scanner" ] || warn "binary $REPO_DIR/scanner not built yet — build with: (cd $REPO_DIR && go build -o ./scanner ./cmd/scanner)"

# nf_conntrack exposes its sysctl param only once the module is loaded. Try to
# load it now (harmless if already loaded / unavailable) so we can decide
# whether to emit the conntrack line at all.
modprobe nf_conntrack >/dev/null 2>&1 || true
CONNTRACK_OK=0
[ -r /proc/sys/net/netfilter/nf_conntrack_max ] && CONNTRACK_OK=1

# Guard: interactive mode needs a terminal for the prompts.
if [ "$ASSUME_YES" -ne 1 ] && [ ! -e /dev/tty ]; then
  die "no controlling terminal for prompts; re-run with --yes for non-interactive install."
fi

# ---------------------------------------------------------------------------
# 0a. Prerequisite preflight — check the tools the app runs + the build/update
#     toolchain, BEFORE any system change (read-only; no rollback concern).
#     Mirrors internal/modules/adpentest/preflight.go, the main.go banner slice,
#     and the Dockerfile install methods.
# ---------------------------------------------------------------------------

# Catalog rows: check-binary | class | pkg-or-installcmd | used-by | tier
#   class ∈ apt | go | pipx | source | toolchain
#   tier  ∈ core (build/update/heavily-used) | soft (module degrades if absent)
# apt packages are deduped when the aggregated install line is built (the whole
# impacket-* set → one python3-impacket; snmp* → one snmp).
read -r -d '' TOOL_CATALOG <<'CATALOG' || true
go|toolchain|golang (>=1.25; apt install golang or https://go.dev/dl)|build + self-update|core
git|toolchain|git|self-update (git pull)|core
nmap|apt|nmap|host/port/AD scans (many modules)|core
dig|apt|dnsutils|dnsenum, AD discovery|soft
whois|apt|whois|whoisinfo|soft
whatweb|apt|whatweb|techdetect|soft
amass|apt|amass|dnsenum|soft
recon-ng|apt|recon-ng|dnsenum|soft
wpscan|apt|wpscan|wpscan|soft
nuclei|apt|nuclei|nuclei|soft
hydra|apt|hydra|brutef|soft
smbclient|apt|smbclient|smbenum|soft
enum4linux|apt|enum4linux|smbenum, AD|soft
enum4linux-ng|apt|enum4linux-ng|AD unauth-enum|soft
nbtscan|apt|nbtscan|AD discovery|soft
snmpwalk|apt|snmp|snmpenum|soft
onesixtyone|apt|onesixtyone|snmpenum|soft
theHarvester|apt|theharvester|emailharvest|soft
sslscan|apt|sslscan|SSL/TLS scanner|soft
openssl|apt|openssl|SSL/TLS scanner|soft
ldapsearch|apt|ldap-utils|AD discovery/enum|soft
impacket-GetUserSPNs|apt|python3-impacket|AD (kerberoast, enum, roast)|soft
responder|apt|responder|AD LLMNR/NBT-NS poisoning|soft
hashcat|apt|hashcat|AD hash cracking|soft
john|apt|john|AD hash cracking fallback|soft
seclists|apt|seclists|wordlists (direnum, brutef)|soft
subfinder|go|go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest|dnsenum|soft
puredns|go|go install github.com/d3mondev/puredns/v2@latest|dnsenum|soft
kerbrute|go|go install github.com/ropnop/kerbrute@latest|AD user-enum|soft
massdns|source|git clone https://github.com/blechschmidt/massdns && cd massdns && make|dnsenum (puredns backend)|soft
nxc|pipx|pipx install netexec|AD auth-enum, spray, vuln-probe|soft
ldapdomaindump|pipx|pipx install ldapdomaindump|AD enum|soft
bloodhound-python|pipx|pipx install bloodhound|AD BloodHound collection|soft
certipy-ad|pipx|pipx install certipy-ad|AD ADCS enum|soft
mitm6|pipx|pipx install mitm6|AD IPv6 takeover|soft
coercer|pipx|pipx install coercer|AD coercion|soft
CATALOG

# TU_HOME — the target user's home, for locating per-user go/pipx binaries.
TU_HOME="$(getent passwd "$TARGET_USER" 2>/dev/null | cut -d: -f6)"
[ -n "$TU_HOME" ] || TU_HOME="/home/$TARGET_USER"

# have <binary> — present on PATH, or in the user's go/pipx dirs, or the repo's
# bundled tools/ dir (mirrors how the app resolves subfinder/kerbrute/mitm6).
have() {
  command -v "$1" >/dev/null 2>&1 && return 0
  [ -x "$TU_HOME/go/bin/$1" ]     && return 0
  [ -x "$TU_HOME/.local/bin/$1" ] && return 0
  [ -x "$REPO_DIR/tools/$1" ]     && return 0
  return 1
}

# go_version_lt_125 — 0 (true) if the installed Go is older than 1.25.
go_version_lt_125() {
  local v
  v="$(go version 2>/dev/null | grep -oE 'go[0-9]+\.[0-9]+' | head -1 | sed 's/go//')" || return 1
  [ -n "$v" ] || return 1
  local maj="${v%%.*}" min="${v#*.}"
  [ "$maj" -lt 1 ] && return 0
  [ "$maj" -eq 1 ] && [ "$min" -lt 25 ] && return 0
  return 1
}

APT_MISSING=()          # deduped apt packages to (optionally) auto-install
GO_STEPS=(); PIPX_STEPS=(); SOURCE_STEPS=()
CORE_MISSING=()

check_prerequisites() {
  step "Checking prerequisites (tools the scanner runs + build/update toolchain)"
  local seen_pkg=" "     # dedup guard for apt packages
  local n_present=0 n_missing=0
  local check class pkg usedby tier
  while IFS='|' read -r check class pkg usedby tier; do
    [ -n "$check" ] || continue
    if have "$check"; then
      n_present=$((n_present + 1))
      # Flag an outdated Go even when present (build/self-update need >=1.25).
      if [ "$check" = go ] && go_version_lt_125; then
        warn "go is $(go version 2>/dev/null | grep -oE 'go[0-9.]+' | head -1 | sed 's/go//') — build + self-update need >= 1.25 (https://go.dev/dl)"
      fi
      continue
    fi
    n_missing=$((n_missing + 1))
    if [ "$tier" = core ]; then
      CORE_MISSING+=("$check")
      printf '  %s✗%s %-18s %s(%s — %s)%s\n' "$c_red" "$c_reset" "$check" "$c_dim" "$tier" "$usedby" "$c_reset"
    else
      printf '  %s⚠%s %-18s %s(%s)%s\n' "$c_ylw" "$c_reset" "$check" "$c_dim" "$usedby" "$c_reset"
    fi
    case "$class" in
      apt|toolchain)
        # go + git are apt-installable. Go's distro package can lag behind 1.25,
        # so auto-install it (pkg 'golang') AND leave a tarball fallback note.
        if [ "$check" = go ]; then
          case "$seen_pkg" in *" golang "*) : ;; *) APT_MISSING+=("golang"); seen_pkg="$seen_pkg golang " ;; esac
          GO_STEPS+=("${c_dim}(if the apt 'golang' turns out < 1.25, use the tarball: https://go.dev/dl)${c_reset}")
        else
          case "$seen_pkg" in *" $pkg "*) : ;; *) APT_MISSING+=("$pkg"); seen_pkg="$seen_pkg$pkg " ;; esac
        fi ;;
      go)     GO_STEPS+=("$pkg") ;;
      pipx)   PIPX_STEPS+=("$pkg") ;;
      source) SOURCE_STEPS+=("$pkg") ;;
    esac
  done <<< "$TOOL_CATALOG"

  ok "$n_present present"
  if [ "$n_missing" -eq 0 ]; then
    ok "all known tools found — nothing to install"
    return 0
  fi
  printf '  %s%d tool(s) missing.%s The scanner runs, but the modules above stay unavailable\n' "$c_ylw" "$n_missing" "$c_reset"
  printf '  %suntil their tool is installed. Fixes:%s\n' "$c_dim" "$c_reset"

  # Aggregated apt line.
  if [ "${#APT_MISSING[@]}" -gt 0 ]; then
    hdr $'\n  apt packages (system-wide):'
    printf '     %ssudo apt-get install -y %s%s\n' "$c_cyn" "${APT_MISSING[*]}" "$c_reset"
  fi
  # go-install steps (per-user → ~/go/bin; ensure it is on $PATH).
  if [ "${#GO_STEPS[@]}" -gt 0 ]; then
    hdr $'\n  Go tools (install into ~/go/bin — ensure it is on $PATH):'
    local s; for s in "${GO_STEPS[@]}"; do printf '     %s\n' "$s"; done
  fi
  # pipx steps (per-user → ~/.local/bin).
  if [ "${#PIPX_STEPS[@]}" -gt 0 ]; then
    hdr $'\n  Python tools (pipx → ~/.local/bin — ensure it is on $PATH):'
    local s; for s in "${PIPX_STEPS[@]}"; do printf '     %s\n' "$s"; done
  fi
  # source-build steps.
  if [ "${#SOURCE_STEPS[@]}" -gt 0 ]; then
    hdr $'\n  From source:'
    local s; for s in "${SOURCE_STEPS[@]}"; do printf '     %s\n' "$s"; done
  fi

  # Offer to auto-install the apt packages (only apt; go/pipx stay per-user steps).
  if [ "${#APT_MISSING[@]}" -gt 0 ] && command -v apt-get >/dev/null 2>&1; then
    local do_apt=0
    if [ "$ASSUME_YES" -eq 1 ]; then
      do_apt=1
    else
      printf '\n  Install the %d missing apt package(s) now? [y/N] ' "${#APT_MISSING[@]}"
      read -r a </dev/tty || a="n"
      case "${a:-n}" in [Yy]*) do_apt=1 ;; esac
    fi
    if [ "$do_apt" -eq 1 ]; then
      step "Installing apt packages"
      # Outside the transaction on purpose: installed tools should persist even
      # if a later step rolls back (they're apt-managed and generally useful).
      # 'apt-get update' is best-effort: a non-zero here (a stale/──warning repo)
      # must NOT stop us from installing packages that are already fetchable, and
      # its output stays visible so a real failure is diagnosable.
      info "\$ apt-get update"
      apt-get update || warn "apt-get update reported an error (continuing — packages may still install from cache)."
      info "\$ apt-get install -y ${APT_MISSING[*]}"
      if DEBIAN_FRONTEND=noninteractive apt-get install -y "${APT_MISSING[@]}"; then
        ok "apt packages installed"
      else
        warn "apt install did not finish cleanly — see the apt output just above for the reason."
        warn "Fix that (e.g. 'sudo apt-get update' by hand), or install manually:"
        warn "    sudo apt-get install -y ${APT_MISSING[*]}"
        warn "Continuing — the scanner still builds/runs; unmet tools just stay unavailable."
      fi
      # Re-check regardless of the exit code (a partial install still helped).
      local still=() check2
      for check2 in go git nmap dig whois whatweb amass recon-ng wpscan nuclei hydra smbclient enum4linux enum4linux-ng nbtscan snmpwalk onesixtyone theHarvester sslscan openssl ldapsearch impacket-GetUserSPNs responder hashcat john; do
        have "$check2" || still+=("$check2")
      done
      [ "${#still[@]}" -gt 0 ] && warn "still missing after apt (may need go/pipx or a different pkg name): ${still[*]}"
      # Go just arrived via apt? Make sure it's new enough for the build.
      if have go && go_version_lt_125; then
        warn "the apt 'golang' is $(go version 2>/dev/null | grep -oE 'go[0-9.]+' | head -1 | sed 's/go//') — the build needs >= 1.25. Install the tarball from https://go.dev/dl, then re-run."
      fi
    else
      info "skipped — install them later with the command above."
    fi
  fi

  # Core misses (go/git/nmap) get a prominent note but never block the install.
  # Recompute fresh — an auto-install above may have resolved some of them.
  local core_now=() c
  for c in go git nmap; do have "$c" || core_now+=("$c"); done
  if [ "${#core_now[@]}" -gt 0 ]; then
    warn "core tool(s) still missing: ${core_now[*]} — go is needed to build + self-update, git for self-update, nmap powers most scans."
  fi
}
check_prerequisites

# ---------------------------------------------------------------------------
# 0b. Build the scanner binary (as the target user, so the binary + Go build
#     cache stay user-owned). Runs BEFORE the transaction: a build failure
#     aborts cleanly with nothing yet changed on the system.
# ---------------------------------------------------------------------------
build_binary() {
  step "Building the scanner binary"
  if ! have go; then
    die "Go isn't installed, so the binary can't be built.
       Install Go >= 1.25 first:  apt install golang   (or the tarball at https://go.dev/dl)
       Then re-run:  sudo scripts/install.sh"
  fi
  local go_bin; go_bin="$(command -v go)"
  info "\$ go build -o ./scanner ./cmd/scanner   (as $TARGET_USER — first build can take a minute)"
  if sudo -u "$TARGET_USER" env HOME="$TU_HOME" PATH="/usr/local/go/bin:/usr/bin:/bin:$TU_HOME/go/bin" \
       sh -c "cd '$REPO_DIR' && '$go_bin' build -o ./scanner ./cmd/scanner"; then
    ok "built $REPO_DIR/scanner"
  else
    die "go build failed (see the compiler output above).
       Common causes: Go older than 1.25 (check: go version), or a local change that doesn't compile.
       Fix it, then re-run:  sudo scripts/install.sh"
  fi
}
build_binary

# ---------------------------------------------------------------------------
# 0. Show the operator exactly what will change before anything is touched.
# ---------------------------------------------------------------------------
step "What this installer will change (root, one-time)"
log "  • network-stack sysctl tuning + an open-file-limit drop-in"
log "  • a systemd service 'scanner' running as '$TARGET_USER' with the killswitch"
log "    caps CAP_NET_ADMIN + CAP_NET_RAW (ambient — survive rebuilds; data stays user-owned)"
log "  • PASSWORDLESS sudo, tightly scoped: systemctl start/stop/restart/status scanner,"
log "    the Settings -> Network Tuning helper, and VPN-watchdog nmcli up/down"
if [ "$IS_KALI" -eq 1 ]; then
  log "  • Kali: autoload netfilter modules at boot, add '$TARGET_USER' to 'netdev',"
  log "    and make /run/xtables.lock group-accessible (killswitch prerequisites)"
fi
log "  Only these managed files are touched; re-running is safe (idempotent)."

# ---------------------------------------------------------------------------
# 1. Confirm / edit the tuning values.
# ---------------------------------------------------------------------------
if [ "$ASSUME_YES" -eq 1 ]; then
  print_plan
  if ! validate_values; then die "invalid tuning values (see above)."; fi
else
  while :; do
    print_plan
    printf 'Apply these values? [Y/n]  (or "e" to edit each) '
    read -r ans </dev/tty || ans="y"
    case "${ans:-y}" in
      ''|[Yy]*)
        if validate_values; then break; fi
        log "Fix the values above (choose 'e' to edit)." ;;
      [Ee]*) edit_values ;;
      [Nn]*) die "aborted by operator; no changes made." ;;
      *) log 'Please answer Y, n, or e.' ;;
    esac
  done
fi

# ---------------------------------------------------------------------------
# 2. Write /etc/sysctl.d/99-scanner.conf and apply it.
# ---------------------------------------------------------------------------
# Arm the transaction: from here on, ANY failure rolls every change back.
tx_begin
step "Writing /etc/sysctl.d/99-scanner.conf"
# Process substitution (not a pipe) so atomic_write runs in THIS shell and its
# MANAGED+= is not lost to a subshell.
atomic_write /etc/sysctl.d/99-scanner.conf 0644 < <(render_sysctl_conf)
ok "sysctl drop-in written + applied"

# sysctl --system reloads every drop-in. Suppress its stdout (noisy) but keep
# an eye on the exit code.
if ! sysctl --system >/dev/null 2>&1; then
  warn "'sysctl --system' reported an error. It usually names the offending drop-in — inspect with:"
  warn "    sudo sysctl --system        # shows which key/file failed"
  warn "Our drop-in is /etc/sysctl.d/99-scanner.conf; a pre-existing unrelated drop-in may be at fault."
fi
log "  Applied kernel values now:"
show_kernel_val net/ipv4/ip_local_port_range   "ip_local_port_range"
show_kernel_val net/ipv4/tcp_fin_timeout       "tcp_fin_timeout"
show_kernel_val net/ipv4/tcp_tw_reuse          "tcp_tw_reuse"
show_kernel_val net/ipv4/tcp_max_tw_buckets    "tcp_max_tw_buckets"
show_kernel_val net/netfilter/nf_conntrack_max "nf_conntrack_max"

# ---------------------------------------------------------------------------
# 3. FD limit fallback for a manually-run ./scanner (login shell / PAM).
#    The systemd service uses LimitNOFILE in the unit instead; limits.d does
#    not apply to systemd-started processes.
# ---------------------------------------------------------------------------
step "Raising open-file limit (limits.d fallback)"
atomic_write /etc/security/limits.d/99-scanner.conf 0644 <<EOF
# Managed by scaNNer — raise the open-file limit for '$TARGET_USER'.
# FALLBACK path: applies only to a login shell running ./scanner by hand.
# The scanner.service unit sets LimitNOFILE=$NOFILE_LIMIT for the service itself.
$TARGET_USER - nofile $NOFILE_LIMIT
EOF
ok "open-file limit drop-in written  ${c_dim}($TARGET_USER nofile $NOFILE_LIMIT)${c_reset}"

# ---------------------------------------------------------------------------
# 4. Install the runtime re-tuning helper the scanner calls from Settings.
# ---------------------------------------------------------------------------
step "Installing /usr/local/sbin/scanner-tune"
[ -f "$SCRIPT_DIR/scanner-tune" ] || die "$SCRIPT_DIR/scanner-tune is missing; cannot install the runtime tuner."
tx_backup /usr/local/sbin/scanner-tune
install -m 0755 -o root -g root "$SCRIPT_DIR/scanner-tune" /usr/local/sbin/scanner-tune
MANAGED+=("/usr/local/sbin/scanner-tune")
ok "scanner-tune installed  ${c_dim}(/usr/local/sbin, root:root 0755)${c_reset}"

# ---------------------------------------------------------------------------
# 5. systemd unit — runs as the regular user, caps injected via ambient set.
# ---------------------------------------------------------------------------
step "Installing systemd unit /etc/systemd/system/scanner.service"
# Paths are written unquoted — systemd's WorkingDirectory=/ExecStart= take the
# value verbatim and reject surrounding quotes ("bad unit file setting"). A repo
# path with a space is rejected up front (precondition below) instead.
atomic_write /etc/systemd/system/scanner.service 0644 <<EOF
[Unit]
Description=scaNNer pentest toolkit
After=network.target

[Service]
Type=simple
User=$TARGET_USER
Group=$TARGET_GROUP
WorkingDirectory=$REPO_DIR
ExecStart=$REPO_DIR/scanner
# Inject the killswitch capabilities at spawn time. Because they are ambient,
# a plain 'go build' overwriting the binary does NOT drop them (unlike setcap),
# and they even survive the in-app self-update's re-exec — while the process
# still runs as $TARGET_USER so scanner.db / loot stay user-owned.
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW
# NOTE: do NOT add 'CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW'. It bounds
# every child too, so 'sudo' (needs CAP_SETUID/SETGID/AUDIT_WRITE to become root)
# fails with "unable to change to root gid" — silently breaking Network Tuning
# (scanner-tune), VPN control (nmcli) and modprobe, which the app runs via
# 'sudo -n'. The ambient grant above already limits what the app itself holds.
Restart=on-failure
RestartSec=2
LimitNOFILE=$NOFILE_LIMIT

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
ok "systemd unit written + daemon-reloaded"
# On a re-run, a service that's already up keeps the OLD unit settings (caps,
# LimitNOFILE, netdev membership) until an explicit restart — so apply them now.
if systemctl is-active --quiet scanner; then
  if systemctl restart scanner >/dev/null 2>&1; then
    ok "running service restarted so new unit settings are live"
  else
    warn "service is running but could not be restarted; run: sudo systemctl restart scanner"
  fi
fi

# ---------------------------------------------------------------------------
# 6. sudoers — passwordless service control + the runtime tuner.
# ---------------------------------------------------------------------------
step "Installing sudoers drop-ins"
write_sudoers scanner-restart <<EOF
# Managed by scaNNer — passwordless service control for the dev/restart loop.
# Exact-match verbs (no extra flags): start / stop / restart / status / is-active.
$TARGET_USER ALL=(root) NOPASSWD: $SYSTEMCTL_BIN start scanner, $SYSTEMCTL_BIN stop scanner, $SYSTEMCTL_BIN restart scanner, $SYSTEMCTL_BIN status scanner, $SYSTEMCTL_BIN is-active scanner
EOF

write_sudoers scanner-tune <<EOF
# Managed by scaNNer — the running scanner calls this from its Network Tuning
# panel via: sudo -n /usr/local/sbin/scanner-tune KEY=VAL ...
# Privilege is bounded NOT by sudoers args (any args are allowed here) but by
# scanner-tune itself: fixed install path (root-owned, 0755) + a strict
# key=value allowlist + numeric range validation inside the helper.
$TARGET_USER ALL=(root) NOPASSWD: /usr/local/sbin/scanner-tune
EOF

# VPN watchdog auto-reconnect (Settings -> VPN Watchdog): the running scanner
# brings a dropped tunnel back with `nmcli connection down/up id <name>`. In an
# active desktop session nmcli is authorized via polkit; as the systemd service
# (no login session) it falls back to `sudo -n nmcli`, which needs this rule.
# Scoped to connection up/down only — NOT arbitrary nmcli (no delete/modify/add).
NMCLI_BIN="$(command -v nmcli 2>/dev/null || echo /usr/bin/nmcli)"
if [ -x "$NMCLI_BIN" ]; then
  write_sudoers scanner-nmcli <<EOF
# Managed by scaNNer — VPN watchdog auto-reconnect.
$TARGET_USER ALL=(root) NOPASSWD: $NMCLI_BIN connection up id *, $NMCLI_BIN connection down id *
EOF
else
  warn "nmcli not found — skipping VPN-watchdog sudoers (auto-reconnect will rely on session polkit)."
fi

# ---------------------------------------------------------------------------
# 7. Kali-only killswitch prerequisites (harmless / skipped elsewhere).
# ---------------------------------------------------------------------------
if [ "$IS_KALI" -eq 1 ]; then
  step "Kali killswitch prerequisites"

  # 7a. Autoload the netfilter modules at boot. On a default Kali install
  #     nf_tables/nft_nat are not loaded, so the namespace + iptables path
  #     can't even reach the netlink layer on the first scan after a reboot.
  atomic_write /etc/modules-load.d/scanner.conf 0644 <<'EOF'
# Managed by scaNNer — netfilter modules the killswitch (netns + iptables NAT)
# depends on. Not autoloaded on a stock Kali install; load them at boot so the
# killswitch works on the first scan after a reboot.
iptable_nat
iptable_filter
nf_nat
nf_tables
nft_nat
nft_compat
EOF
  ok "netfilter modules-load drop-in written"
  # Best-effort load now so a reboot isn't required to try the killswitch.
  for m in iptable_nat iptable_filter nf_nat nf_tables nft_nat nft_compat; do
    modprobe "$m" >/dev/null 2>&1 || true
  done

  # 7b. Passwordless modprobe fallback (one-time-per-boot, if modules-load.d
  #     hasn't run yet). Exact-arg match: only this module set is permitted.
  write_sudoers scanner-modprobe <<EOF
# Managed by scaNNer (Kali) — fallback module load if modules-load.d hasn't run.
$TARGET_USER ALL=(root) NOPASSWD: $MODPROBE_BIN nf_tables nft_nat
EOF

  # 7c. /run/xtables.lock is root:root 0600 on Kali, so even a CAP_NET_ADMIN
  #     non-root process is denied the iptables mutex ("Could not fetch rule
  #     set generation id"). Make it group-owned by 'netdev' and add the user.
  if getent group netdev >/dev/null 2>&1; then
    atomic_write /etc/tmpfiles.d/scanner-xtables.conf 0644 <<'EOF'
# Managed by scaNNer (Kali) — let a CAP_NET_ADMIN, non-root process acquire the
# iptables mutex by making /run/xtables.lock group-writable by 'netdev'.
f /run/xtables.lock 0660 root netdev -
EOF
    ok "xtables.lock tmpfiles drop-in written"
    if command -v systemd-tmpfiles >/dev/null 2>&1; then
      systemd-tmpfiles --create /etc/tmpfiles.d/scanner-xtables.conf >/dev/null 2>&1 || true
    fi

    # Idempotent group add: only touch the account if not already a member.
    if id -nG "$TARGET_USER" | tr ' ' '\n' | grep -qx netdev; then
      ok "$TARGET_USER already in the 'netdev' group"
    else
      usermod -aG netdev "$TARGET_USER"
      tx_note netdev_added
      ok "added $TARGET_USER to 'netdev'  ${c_dim}(restart the service to apply)${c_reset}"
    fi
  else
    warn "'netdev' group not present; skipping xtables.lock grant (killswitch may need real root)."
  fi
fi

# ---------------------------------------------------------------------------
# 8. Offer to enable + start the service. Not enabled by default because the
#    operator currently runs ./scanner by hand.
# ---------------------------------------------------------------------------
step "Enabling the service"
STARTED=0
if [ ! -x "$REPO_DIR/scanner" ]; then
  # Refuse to start a service whose binary doesn't exist — it would only
  # crash-loop. Guide the operator to build first.
  warn "the scanner binary isn't built yet, so the service was NOT started."
  if ! have go; then
    warn "Go isn't installed either — install it first (see the prerequisites above):"
    warn "    apt install golang        # or the tarball at https://go.dev/dl (need >= 1.25)"
  fi
  warn "Build the binary, then start the service:"
  warn "    cd $REPO_DIR && go build -o ./scanner ./cmd/scanner"
  warn "    sudo systemctl enable --now scanner"
else
  BUSY=0
  if port_in_use; then
    BUSY=1
    warn "something is already listening on :9090 (a manually-run ./scanner?)."
    warn "Stop it first, or the new service will crash-loop failing to bind the port."
  fi

  DO_ENABLE=1
  if [ "$ASSUME_YES" -eq 1 ]; then
    DO_ENABLE=1
  else
    # Default YES — anyone running the installer almost certainly wants the
    # service up; Enter enables it, only an explicit 'n' skips.
    printf 'Enable and start scanner.service now? [Y/n] '
    read -r ans </dev/tty || ans="y"
    case "${ans:-y}" in [Nn]*) DO_ENABLE=0 ;; esac
  fi

  if [ "$DO_ENABLE" -eq 1 ]; then
    if [ "$BUSY" -eq 1 ]; then
      systemctl enable scanner >/dev/null 2>&1 || true
      log "  enabled at boot but NOT started (port :9090 is busy)."
      log "  Stop the manual instance, then:  sudo systemctl start scanner"
    # '|| { ... }' keeps 'set -e' from aborting before the summary + journal hint
    # if the service fails to start.
    elif systemctl enable --now scanner; then
      STARTED=1
      ok "scanner.service enabled and started"
    else
      # A genuine start failure (unit valid, binary present, port free) means the
      # install didn't fully succeed. Tell the operator WHY + how to inspect,
      # THEN roll everything back to pristine (so the system isn't half-configured
      # yet the failure is still explained).
      warn "the service failed to start. Inspect it with:"
      warn "    sudo systemctl status scanner"
      warn "    journalctl -u scanner -b --no-pager | tail -40"
      warn "Common causes: port :9090 already in use · the ./scanner binary is broken/again-unbuilt ·"
      warn "  ambient capabilities not permitted (older kernel, or inside a container) · a bad unit setting."
      tx_rollback "the service failed to start"
    fi
  else
    log "  left disabled. Enable + start later with:  sudo systemctl enable --now scanner"
  fi
fi

# All apply steps succeeded — commit the transaction (drop the rollback trap).
tx_commit

# ---------------------------------------------------------------------------
# Summary — what changed + how to actually use it.
# ---------------------------------------------------------------------------
rule="======================================================================"
echo
printf '%s%s%s%s\n'   "$c_grn" "$c_bold" "$rule" "$c_reset"
printf '  %s%s✓  scaNNer install complete%s\n' "$c_grn" "$c_bold" "$c_reset"
printf '%s%s%s%s\n'   "$c_grn" "$c_bold" "$rule" "$c_reset"

hdr $'\n Files written / managed this run'
for f in "${MANAGED[@]}"; do printf '   %s•%s %s\n' "$c_dim" "$c_reset" "$f"; done

hdr $'\n OPEN THE APP'
printf '   %s%shttps://localhost:9090%s   %s(self-signed cert — the browser warns once; expected)%s\n' \
       "$c_bold" "$c_grn" "$c_reset" "$c_dim" "$c_reset"

hdr $'\n FIRST LOGIN  — important, do this now'
cat <<EOF
   On its FIRST start the app creates an 'admin' account and prints a one-time
   password to the systemd journal (NOT this terminal). Capture it with:

     ${c_bold}${c_cyn}sudo journalctl -u scanner | grep -A6 'INITIAL ADMIN'${c_reset}

   Then sign in as 'admin' with that password; you'll be prompted to change it.
EOF

hdr $'\n SERVICE CONTROL  — passwordless via the installed sudoers rule'
cat <<EOF
   sudo systemctl status scanner
   sudo systemctl restart scanner       # after a rebuild
   sudo systemctl stop scanner
   journalctl -u scanner -f             # live logs
EOF

hdr $'\n REBUILD + RESTART  after code changes'
cat <<EOF
   cd $REPO_DIR
   go build -o ./scanner ./cmd/scanner && sudo systemctl restart scanner
EOF

hdr $'\n KILLSWITCH'
cat <<EOF
   The SERVICE runs with CAP_NET_ADMIN + CAP_NET_RAW, so the killswitch works
   without root — arm it in Settings -> Outbound Network Interface. A hand-run
   './scanner' has NO capabilities (no killswitch); always use the service.
EOF

hdr $'\n IN-APP UPDATES'
cat <<EOF
   The Software Update page pulls the latest code, rebuilds, and re-execs into
   it. The ambient capabilities survive that re-exec, so the killswitch keeps
   working after an update — no re-install needed.
EOF

printf '\n %sRe-tune the network stack anytime from Settings -> Network Tuning, or by hand:%s\n' "$c_dim" "$c_reset"
printf '   sudo -n /usr/local/sbin/scanner-tune fin_timeout=10 port_lo=15000\n'

if [ "$IS_KALI" -eq 1 ]; then
  hdr $'\n KALI NOTE'
  cat <<EOF
   The killswitch needs the netfilter modules loaded and (if '$TARGET_USER' was
   just added to 'netdev') a fresh service start. If the first arm fails, run:
     sudo systemctl restart scanner
   A reboot also applies both cleanly.
EOF
fi
printf '%s%s%s%s\n' "$c_grn" "$c_bold" "$rule" "$c_reset"
