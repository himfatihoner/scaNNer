#!/usr/bin/env bash
#
# scaNNer — uninstaller. Reverses the SYSTEM changes made by scripts/install.sh.
#
#   sudo scripts/uninstall.sh          # interactive (lists what it will remove, asks)
#   sudo scripts/uninstall.sh --yes    # non-interactive
#
# WHAT THIS REMOVES (only what scaNNer's installer created):
#   - the systemd service (stopped + disabled first)
#   - the sysctl + open-file-limit drop-ins
#   - /usr/local/sbin/scanner-tune
#   - the sudoers drop-ins (service control, scanner-tune, nmcli, modprobe)
#   - on Kali: the netfilter modules-load + xtables.lock tmpfiles drop-ins
#   - the ./scanner binary that install.sh built  (use --keep-binary to keep it)
#
# WHAT IT DOES NOT TOUCH:
#   - the repo source and your data (data/scanner.db, loot, logs). This reverses
#     the install; it never deletes source or scan history. Rebuild the binary
#     any time with `go build -o ./scanner ./cmd/scanner` or re-run install.sh.
#
# It is idempotent: anything already gone is skipped without error.
#
set -euo pipefail

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
usage() {
  cat <<'USAGE'
Usage: sudo scripts/uninstall.sh [--yes|-y] [--keep-binary]

  --yes, -y      Non-interactive: remove everything without prompting.
  --keep-binary  Leave the ./scanner binary in place (it is removed by default).
  --help, -h     Show this help.

Reverses the installer: removes the systemd unit, sudoers, sysctl/limits
drop-ins, the Kali killswitch prerequisites, and the ./scanner binary that
install.sh built. Your repo source and data/scanner.db are left untouched.
USAGE
}

# Colors — auto-disabled when stdout is not a TTY, NO_COLOR is set, or dumb term.
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ] && [ "${TERM:-dumb}" != "dumb" ]; then
  c_reset=$'\e[0m'; c_bold=$'\e[1m'; c_dim=$'\e[2m'
  c_red=$'\e[31m'; c_grn=$'\e[32m'; c_ylw=$'\e[33m'; c_blu=$'\e[34m'; c_cyn=$'\e[36m'
else
  c_reset=''; c_bold=''; c_dim=''; c_red=''; c_grn=''; c_ylw=''; c_blu=''; c_cyn=''
fi

log()  { printf '%s\n' "$*"; }
info() { printf '  %s%s%s\n' "$c_dim" "$*" "$c_reset"; }
ok()   { printf '  %s✓%s %s\n' "$c_grn" "$c_reset" "$*"; }
rm_ok(){ printf '  %s−%s %s\n' "$c_ylw" "$c_reset" "$*"; }             # a removed item
step() { printf '\n%s%s▶%s %s%s%s\n' "$c_bold" "$c_cyn" "$c_reset" "$c_bold" "$*" "$c_reset"; }
hdr()  { printf '%s%s%s%s\n' "$c_bold" "$c_blu" "$*" "$c_reset"; }
warn() { printf '%s⚠%s  %s\n' "$c_ylw" "$c_reset" "$*" >&2; }
die()  { printf '%s✗ ERROR:%s %s\n' "$c_red" "$c_reset" "$*" >&2; exit 1; }

ASSUME_YES=0
KEEP_BINARY=0
for arg in "${@:-}"; do
  case "$arg" in
    -y|--yes)     ASSUME_YES=1 ;;
    --keep-binary) KEEP_BINARY=1 ;;
    -h|--help)    usage; exit 0 ;;
    "" )          ;;
    *) usage >&2; die "unknown argument: $arg" ;;
  esac
done

# ---------------------------------------------------------------------------
# Preconditions
# ---------------------------------------------------------------------------
[ "$(id -u)" -eq 0 ] || die "must be run as root:  sudo scripts/uninstall.sh"

# Target user only needed for the netdev-membership note.
TARGET_USER="${SUDO_USER:-$(logname 2>/dev/null || true)}"

SYSTEMCTL_BIN="$(command -v systemctl 2>/dev/null || echo /usr/bin/systemctl)"

# The ./scanner binary install.sh built (parent of this scripts/ dir). Removed
# by default; --keep-binary opts out. Only the artifact — never the source.
REPO_DIR="$(cd "$(dirname "$(readlink -f "$0")")/.." && pwd)"
BINARY="$REPO_DIR/scanner"
REMOVE_BINARY=0
[ "$KEEP_BINARY" -eq 0 ] && [ -f "$BINARY" ] && REMOVE_BINARY=1

# Every file scaNNer's installer may have created.
MANAGED_FILES=(
  /etc/systemd/system/scanner.service
  /etc/sysctl.d/99-scanner.conf
  /etc/security/limits.d/99-scanner.conf
  /usr/local/sbin/scanner-tune
  /etc/sudoers.d/scanner-restart
  /etc/sudoers.d/scanner-tune
  /etc/sudoers.d/scanner-nmcli
  /etc/sudoers.d/scanner-modprobe
  /etc/modules-load.d/scanner.conf
  /etc/tmpfiles.d/scanner-xtables.conf
)

# ---------------------------------------------------------------------------
# Preview: what actually exists to remove.
# ---------------------------------------------------------------------------
printf '\n  %s%ssca%sNN%ser%s %s· uninstaller%s\n' "$c_bold" "$c_reset" "$c_cyn" "$c_reset$c_bold" "$c_reset" "$c_dim" "$c_reset"
step "Uninstall — what will be removed"
PRESENT=()
for f in "${MANAGED_FILES[@]}"; do
  [ -e "$f" ] && PRESENT+=("$f")
done

SERVICE_KNOWN=0
if "$SYSTEMCTL_BIN" list-unit-files scanner.service >/dev/null 2>&1 && \
   "$SYSTEMCTL_BIN" cat scanner.service >/dev/null 2>&1; then
  SERVICE_KNOWN=1
fi

if [ "${#PRESENT[@]}" -eq 0 ] && [ "$SERVICE_KNOWN" -eq 0 ] && [ "$REMOVE_BINARY" -eq 0 ]; then
  ok "Nothing to remove — scaNNer's installer artifacts are not present."
  info "(Your repo source and data are untouched, as always.)"
  exit 0
fi

if [ "$SERVICE_KNOWN" -eq 1 ]; then
  printf '   %s−%s systemd service scanner  (stop + disable + remove)\n' "$c_ylw" "$c_reset"
fi
for f in "${PRESENT[@]}"; do printf '   %s−%s %s\n' "$c_ylw" "$c_reset" "$f"; done
if [ "$REMOVE_BINARY" -eq 1 ]; then
  printf '   %s−%s %s  %s(built binary — rebuildable; source & data kept)%s\n' "$c_ylw" "$c_reset" "$BINARY" "$c_dim" "$c_reset"
fi
info "(The repo, ./scanner, and data/scanner.db are NOT touched.)"

if [ "$ASSUME_YES" -ne 1 ]; then
  [ -e /dev/tty ] || die "no controlling terminal for the prompt; re-run with --yes."
  printf 'Proceed with uninstall? [y/N] '
  read -r ans </dev/tty || ans="n"
  case "${ans:-n}" in [Yy]*) : ;; *) die "aborted; nothing removed." ;; esac
fi

# ---------------------------------------------------------------------------
# 1. Stop + disable the service, then remove its unit.
# ---------------------------------------------------------------------------
step "Removing the systemd service"
"$SYSTEMCTL_BIN" stop scanner    >/dev/null 2>&1 || true
"$SYSTEMCTL_BIN" disable scanner >/dev/null 2>&1 || true
if [ -e /etc/systemd/system/scanner.service ]; then
  rm -f /etc/systemd/system/scanner.service
  rm_ok "/etc/systemd/system/scanner.service"
fi
"$SYSTEMCTL_BIN" daemon-reload >/dev/null 2>&1 || true
"$SYSTEMCTL_BIN" reset-failed scanner >/dev/null 2>&1 || true
ok "service stopped, disabled, and unit removed"

# ---------------------------------------------------------------------------
# 2. Remove the remaining managed files (idempotent).
# ---------------------------------------------------------------------------
step "Removing managed files"
REMOVED=0
for f in "${MANAGED_FILES[@]}"; do
  [ "$f" = /etc/systemd/system/scanner.service ] && continue  # handled above
  if [ -e "$f" ]; then
    rm -f "$f"
    rm_ok "$f"
    REMOVED=$((REMOVED + 1))
  fi
done
[ "$REMOVED" -eq 0 ] && info "(no further managed files present)"

# ---------------------------------------------------------------------------
# 3. Remove the built binary (the install.sh artifact). Source + data stay.
# ---------------------------------------------------------------------------
if [ "$REMOVE_BINARY" -eq 1 ]; then
  step "Removing the built binary"
  rm -f "$BINARY"
  rm_ok "$BINARY"
  info "(rebuild any time: cd $REPO_DIR && go build -o ./scanner ./cmd/scanner)"
elif [ "$KEEP_BINARY" -eq 1 ] && [ -f "$BINARY" ]; then
  step "Keeping the built binary"
  info "--keep-binary set — left $BINARY in place."
fi

# ---------------------------------------------------------------------------
# 4. Reload sysctl so the removed drop-in is no longer reapplied.
# ---------------------------------------------------------------------------
step "Reloading sysctl"
if sysctl --system >/dev/null 2>&1; then
  ok "sysctl reloaded — the removed tuning drop-in will not be reapplied"
else
  warn "'sysctl --system' returned an error; harmless here (the drop-in is gone)."
fi

# ---------------------------------------------------------------------------
# Summary + honest notes about what only reverts on reboot.
# ---------------------------------------------------------------------------
rule="======================================================================"
echo
printf '%s%s%s%s\n'   "$c_grn" "$c_bold" "$rule" "$c_reset"
printf '  %s%s✓  scaNNer uninstalled  %s%s(system integration removed)%s\n' "$c_grn" "$c_bold" "$c_reset" "$c_dim" "$c_reset"
printf '%s%s%s%s\n'   "$c_grn" "$c_bold" "$rule" "$c_reset"

hdr $'\n Left untouched (on purpose)'
cat <<EOF
   - the repo source (rebuild the binary any time)
   - your data: data/scanner.db, loot, logs
EOF
[ "$KEEP_BINARY" -eq 1 ] && [ -f "$BINARY" ] && printf '   - the ./scanner binary (--keep-binary)\n'

hdr $'\n Only fully reverts on the next reboot (nothing is broken now)'
cat <<EOF
   - Live sysctl values (port range / fin_timeout) stay until reboot; the
     drop-in is removed so they won't be set again. To reset now, reboot or set
     them by hand with sysctl.
   - Netfilter modules already loaded this boot stay loaded (harmless); they
     just won't autoload next boot.
EOF
if [ -n "$TARGET_USER" ] && id -nG "$TARGET_USER" 2>/dev/null | tr ' ' '\n' | grep -qx netdev; then
  cat <<EOF
   - '$TARGET_USER' is still in the 'netdev' group (added by the installer for
     xtables.lock access). Left in place to be safe; remove it yourself with:
       ${c_bold}${c_cyn}sudo gpasswd -d $TARGET_USER netdev${c_reset}
EOF
fi

hdr $'\n Run scaNNer again'
if [ -f "$BINARY" ]; then
  cat <<EOF
   by hand (no service):   cd $REPO_DIR && ./scanner
   or re-install service:  sudo scripts/install.sh
EOF
else
  cat <<EOF
   re-install service:     sudo scripts/install.sh   ${c_dim}(rebuilds + provisions)${c_reset}
   or by hand:             cd $REPO_DIR && go build -o ./scanner ./cmd/scanner && ./scanner
EOF
fi
printf '%s%s%s%s\n' "$c_grn" "$c_bold" "$rule" "$c_reset"
