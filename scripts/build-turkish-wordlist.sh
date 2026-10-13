#!/usr/bin/env bash
#
# Regenerates data/hashcat-wordlists/turkish-merged.txt.gz — a deduplicated merge
# of public GitHub Turkish password/word lists, shipped in-repo so the Hashcat
# module offers one comprehensive Turkish option (hashcat reads .gz natively).
#
# Sources (see data/hashcat-wordlists/SOURCES.md):
#   - utkusen/turkce-wordlist         (canonical ~303k)
#   - UtkuBasarann/turkish-wordlist-100k
#   - regrews/turkce-wordlist         ("word password" → both become candidates)
#
# Usage (from anywhere):  scripts/build-turkish-wordlist.sh
set -euo pipefail

REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$REPO_DIR/data/hashcat-wordlists/turkish-merged.txt.gz"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

echo "[*] downloading sources..."
curl -fsSL "https://raw.githubusercontent.com/utkusen/turkce-wordlist/master/wordlist.txt"          -o "$TMP/utkusen.txt"
curl -fsSL "https://raw.githubusercontent.com/UtkuBasarann/turkish-wordlist-100k/main/wordlist.txt" -o "$TMP/utkubasaran.txt"
curl -fsSL "https://raw.githubusercontent.com/regrews/turkce-wordlist/master/wordlist.txt"           -o "$TMP/regrews.txt"

mkdir -p "$(dirname "$OUT")"
echo "[*] merging + deduping (case-sensitive, first occurrence wins)..."
python3 -I - "$TMP" "$OUT" <<'PY'
import gzip, os, sys
tmp, out = sys.argv[1], sys.argv[2]
# (file, mode): plain = one entry/line; ws = whitespace-split, each token a candidate.
sources = [(os.path.join(tmp, "utkusen.txt"), "plain"),
           (os.path.join(tmp, "utkubasaran.txt"), "plain"),
           (os.path.join(tmp, "regrews.txt"), "ws")]
seen, order = set(), []
def add(w):
    if w and w not in seen:
        seen.add(w); order.append(w)
for path, mode in sources:
    n0 = len(order)
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.rstrip("\r\n")
            if mode == "ws":
                for tok in line.split():
                    add(tok)
            else:
                add(line)
    print("    %-16s +%d (total %d)" % (os.path.basename(path), len(order) - n0, len(order)))
with gzip.open(out, "wt", encoding="utf-8") as g:
    g.write("\n".join(order))
    g.write("\n")
print("[*] unique entries:", len(order), "| gz bytes:", os.path.getsize(out))
PY
echo "[*] wrote $OUT"
