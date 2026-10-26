#!/usr/bin/env bash
#
# Builds data/direnum-wordlists/<lang>-t{1,2,3}.txt.gz — per-language, 3-tier
# directory-scan wordlists for the direnum module, merged + deduped from ~100
# public sources (SecLists, Assetnote, fuzzdb, random-robbie, OneListForAll,
# dirsearch, Bo0oM, nuclei-derived seeds). direnum reads .gz natively.
#
# The heavy .gz output is GITIGNORED (one-time local build, hundreds of MB).
# What ships in-repo: this script, scripts/build-direnum-wordlists.py, the
# curated scripts/direnum-seeds/*.txt, data/direnum-wordlists/SOURCES.md and
# data/direnum-wordlists/manifest.json. A fresh clone with no built lists
# degrades gracefully to system SecLists (see internal/modules/direnum).
#
# Usage (from anywhere):
#   scripts/build-direnum-wordlists.sh                 # full build (large!)
#   scripts/build-direnum-wordlists.sh --sample        # small online smoke test
#   scripts/build-direnum-wordlists.sh --only dotnet,php
#   scripts/build-direnum-wordlists.sh --selftest /tmp/direnum-selftest   # offline
#
# All flags are passed straight through to build-direnum-wordlists.py.
set -euo pipefail

REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
CORE="$REPO_DIR/scripts/build-direnum-wordlists.py"

if ! command -v python3 >/dev/null 2>&1; then
    echo "error: python3 is required" >&2
    exit 1
fi

# -I: isolated mode (ignore env/user-site) — these sources are untrusted downloads.
exec python3 -I "$CORE" "$@"
