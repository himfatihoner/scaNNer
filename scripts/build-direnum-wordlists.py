#!/usr/bin/env python3
"""Build tiered, per-language directory-scan wordlists for scaNNer's direnum module.

Output : data/direnum-wordlists/<lang>-t{1,2,3}.txt.gz  (GITIGNORED — one-time local build)
         data/direnum-wordlists/manifest.json          (refreshed with real counts)
Inputs : scripts/direnum-seeds/<lang>.txt       curated seeds (shipped, priority-ordered)
         scripts/direnum-seeds/_extensions.json per-language extension research (shipped)
         scripts/direnum-seeds/_sources.json    per-language source catalog    (shipped)

Pulls from ~100 public sources (SecLists, Assetnote, fuzzdb, random-robbie,
OneListForAll, dirsearch, Bo0oM, nuclei-derived seeds, …) — see
data/direnum-wordlists/SOURCES.md. Downloads are cached; a full build is large
(hundreds of MB download + output). A source that fails to download is skipped
with a warning, so a partial/offline build still produces usable tiers from the
seeds + whatever was reachable. Output is case-SENSITIVE-deduped (first wins) so
deliberate casing variants such as `web.config` and `Web.config` both survive.

Tiers (per language L and for the shared `general` directory-name list):
  t1  ~200k   seeds + high-signal real corpora + top backup permutations
  t2  ~1M     t1 + full real corpora + (generic base x L-extensions) + more perms
  t3  ~3M     t2 + exhaustive extension-expansion + big generic aggregates

Modes:
  (default)         full build into data/direnum-wordlists/
  --sample          small real-network subset (quick online smoke test)
  --selftest DIR    offline synthetic build + invariant asserts (verification/CI)
  --only L1,L2,...  restrict to some languages (comma list; 'general' allowed)
  --cache DIR       download cache dir (default: $DIRENUM_WL_CACHE or a temp dir)
  --caps a,b,c      override tier caps (default 200000,1000000,3000000)

This file is intentionally dependency-free (stdlib only) and safe to run with
`python3 -I`.
"""

import argparse
import gzip
import hashlib
import json
import os
import re
import sys
import tempfile
import time
import urllib.error
import urllib.request

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SEEDDIR = os.path.join(REPO, "scripts", "direnum-seeds")
OUTDIR = os.path.join(REPO, "data", "direnum-wordlists")

LANGS = ["dotnet", "php", "java", "python", "ruby", "nodejs", "coldfusion", "perl", "classicasp"]
GENERAL = "general"
ALL_KEYS = LANGS + [GENERAL]

DEFAULT_CAPS = (200_000, 1_000_000, 3_000_000)

# Backup/archive suffixes appended to a language's base + config names (the
# `web.config.bak` / `web.rar` / `bin.rar` family the user asked for).
BACKUP_SUFFIXES = [
    ".bak", ".old", ".orig", ".save", ".swp", "~", ".1", ".2", ".tmp", ".temp",
    ".copy", ".backup", ".bkp", ".bk", ".zip", ".rar", ".tar", ".tar.gz", ".tgz",
    ".7z", ".gz", ".sql", ".sql.gz", ".txt", ".dev", ".prod", ".local", ".new",
    ".sample", ".example", ".disabled", ".inc",
]

# Bare archive/base names so permutation yields web.rar, bin.rar, backup.zip, …
PERM_BASES = [
    "web", "bin", "backup", "backups", "bak", "site", "www", "app", "application",
    "data", "database", "db", "sql", "dump", "config", "configuration", "admin",
    "release", "releases", "deploy", "dist", "build", "old", "new", "test", "tests",
    "dev", "prod", "production", "staging", "public", "private", "assets", "static",
    "upload", "uploads", "files", "file", "archive", "archives", "source", "sources",
    "src", "home", "index", "main", "default", "wwwroot", "htdocs", "inetpub",
    "temp", "tmp", "log", "logs", "export", "exports", "import", "backup_old",
]

# Real file extensions we will append to generic base-names per language (quality
# over quantity — junk path-tokens from the research are filtered out by this
# allowlist). The generator intersects each language's researched extension set
# with VALID_EXT to form its extension-expansion set.
VALID_EXT = {
    # php
    "php", "php3", "php4", "php5", "php7", "php8", "phtml", "pht", "phps", "phar",
    "inc", "tpl", "twig", "ctp", "blade.php", "module", "install",
    # asp / .net
    "asp", "aspx", "asax", "ascx", "ashx", "asmx", "axd", "svc", "cshtml", "vbhtml",
    "config", "cs", "vb", "dll", "pdb", "mdf", "ldf", "resx", "disco", "vsdisco",
    "soap", "rem", "csproj", "vbproj", "sln", "nupkg", "master", "sitemap",
    # java
    "jsp", "jspx", "jspa", "jspf", "jhtml", "do", "action", "java", "class", "war",
    "ear", "jar", "properties", "jsf", "xhtml", "seam", "wss",
    # coldfusion
    "cfm", "cfml", "cfc", "cfr", "cfs", "cfswf", "dbm",
    # perl / cgi
    "pl", "pm", "cgi", "fcgi", "plx", "epl", "ep", "psgi", "pod", "mhtml", "tmpl",
    # python
    "py", "pyc", "pyd", "pyo", "pyw", "pyx", "pyi", "pyz", "whl", "ipynb", "wsgi",
    "asgi", "mako", "jinja2", "j2", "cfg", "toml",
    # ruby
    "rb", "rbi", "rbs", "erb", "rhtml", "rjs", "ru", "haml", "slim", "rake",
    "gemspec", "jbuilder", "builder", "rabl",
    # node / js
    "js", "mjs", "cjs", "ts", "jsx", "tsx", "vue", "json", "map", "lock",
    # data / backup / generic-servable
    "xml", "yml", "yaml", "ini", "env", "conf", "txt", "log", "sql", "db", "sqlite",
    "sqlite3", "bak", "old", "orig", "tmp", "swp", "zip", "rar", "tar", "gz", "tgz",
    "7z", "html", "htm", "shtml", "stm", "xhtml", "md", "csv", "pem", "key", "crt",
    "htr", "htaccess", "htpasswd", "cer", "cdx", "idc", "idq", "ida", "shtm",
}

# ---- normalization -----------------------------------------------------------

# Host-list leak guard. A bare `label.label.tld` token with no path is almost
# certainly a hostname rather than a probe path. We only treat it as a host when
# the FINAL label is a real TLD — so filenames like `web.config`, `index.html`,
# `Default.aspx`, `backup.sql` (whose final label is a FILE extension, never a
# TLD) are kept. TLDs that collide with plausible filenames (io/co/me/app/dev)
# are deliberately omitted; the obvious host-list sources are already excluded
# at the catalog level, so this is only a secondary straggler filter.
COMMON_TLDS = {
    "com", "net", "org", "edu", "gov", "mil", "int", "info", "biz", "xyz",
    "online", "cloud", "tech", "store", "pro", "name", "mobi",
    "uk", "de", "fr", "ru", "cn", "jp", "br", "in", "au", "ca", "nl", "it",
    "es", "pl", "tr", "ir", "us", "eu", "kr", "se", "ch", "be", "at", "dk",
    "no", "fi", "cz", "gr", "pt", "hu", "ro", "ua", "za", "mx", "ar", "id",
}
_HOSTLIKE = re.compile(r"^[a-z0-9][a-z0-9.-]*\.([a-z]{2,24})$", re.I)
_BAD_CHARS = re.compile(r"[\x00-\x1f\x7f\s]")
_SCHEME = re.compile(r"^[a-z][a-z0-9+.-]*://", re.I)


def normalize_line(line):
    """Return a clean candidate path, or None to drop the line.

    Drops comments, blanks, whitespace/control chars, host-list stragglers,
    over-long paths; strips scheme + host if a full URL slipped in, and strips a
    single leading slash so the path joins cleanly onto a base URL in direnum.
    """
    if line is None:
        return None
    s = line.strip()
    if not s or s[0] == "#":
        return None
    # A full URL → keep only the path (+query/fragment).
    if _SCHEME.match(s):
        s = re.sub(r"^[a-z][a-z0-9+.-]*://[^/]+", "", s, flags=re.I)
        if not s:
            return None
    s = s.lstrip("/")
    if not s:
        return None
    if len(s) > 255:
        return None
    if _BAD_CHARS.search(s):
        return None
    # Pure hostname with no path → host-list leak (final label must be a TLD).
    if "/" not in s and "?" not in s:
        m = _HOSTLIKE.match(s)
        if m and m.group(1).lower() in COMMON_TLDS:
            return None
    return s


def stem_of(path):
    """Base name without its (final) extension or trailing slash — the permutation base."""
    p = path.rstrip("/")
    p = p.split("?", 1)[0]
    base = p.rsplit("/", 1)[-1]
    if "." in base:
        base = base.rsplit(".", 1)[0]
    return base


# ---- download ----------------------------------------------------------------

UA = "scaNNer-direnum-wordlist-builder/1.0 (+https://github.com/himfatihoner/scaNNer)"


def cache_path(cache_dir, url):
    h = hashlib.sha1(url.encode("utf-8")).hexdigest()[:16]
    safe = re.sub(r"[^a-zA-Z0-9._-]", "_", url.rsplit("/", 1)[-1])[:60]
    return os.path.join(cache_dir, h + "_" + safe)


def fetch(url, cache_dir, retries=3, timeout=60):
    """Download url to the cache (if not already cached). Return local path or None."""
    dst = cache_path(cache_dir, url)
    if os.path.exists(dst) and os.path.getsize(dst) > 0:
        return dst
    tmp = dst + ".part"
    for attempt in range(1, retries + 1):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": UA})
            with urllib.request.urlopen(req, timeout=timeout) as r, open(tmp, "wb") as f:
                while True:
                    chunk = r.read(1 << 16)
                    if not chunk:
                        break
                    f.write(chunk)
            os.replace(tmp, dst)
            return dst
        except (urllib.error.HTTPError, urllib.error.URLError, OSError, TimeoutError) as e:
            code = getattr(e, "code", None)
            if code == 404:
                print("    [skip 404] %s" % url)
                return None
            if attempt == retries:
                print("    [skip after %d tries: %s] %s" % (retries, e, url))
                return None
            time.sleep(1.5 * attempt)
        finally:
            if os.path.exists(tmp):
                try:
                    os.remove(tmp)
                except OSError:
                    pass
    return None


def iter_lines(path):
    """Yield normalized candidate lines from a (maybe .gz) file."""
    opener = gzip.open if path.endswith(".gz") else open
    try:
        with opener(path, "rt", encoding="utf-8", errors="replace") as f:
            for line in f:
                n = normalize_line(line)
                if n is not None:
                    yield n
    except OSError as e:
        print("    [read error %s] %s" % (e, path))


# ---- source catalog (derived from scripts/direnum-seeds/_sources.json) --------

# URL role classification. GENERIC sources feed the shared `general` list and act
# as the permutation/extension-expansion substrate for every language. EXCLUDEd
# URLs are repo-tree links, catalogs, reference docs, or verified HOST lists
# (not path corpora). Everything else is a language-specific path corpus.
_GENERIC_PAT = re.compile(
    r"(httparchive_directories_1m|httparchive_apiroutes|directory-list-2\.3|"
    r"raft-large|/common\.txt|/big\.txt|quickhits|combined_directories|"
    r"combined_words|Bo0oM/fuzz|dirsearch/.*dicc|onelistforall(micro|short)|"
    r"wordlist_no_underscores|wordlist_with_underscores|web-extensions|"
    r"trickest/.*(parameters|inventory))",
    re.I,
)
_EXCLUDE_PAT = re.compile(
    r"(github\.com/[^/]+/[^/]+/tree/|github\.com/[^/]+/[^/]+/?$|"
    r"\.md($|\?)|automated\.json|manual\.json|technologies\.json|kiterunner\.json|"
    r"/data/automated\.json|wordlists\.assetnote\.io/?$|PayloadsAllTheThings|"
    r"/technologies/httparchive_(rails|django|flask|coldfusion)_)",
    re.I,
)


def load_catalog():
    with open(os.path.join(SEEDDIR, "_sources.json"), encoding="utf-8") as f:
        src = json.load(f)
    # url -> {"role": "generic"|"exclude"|"lang", "langs": set()}
    catalog = {}
    for key, blob in src.items():
        for s in blob.get("sources", []):
            url = (s.get("url") or "").strip()
            if not url or not url.startswith("http"):
                continue
            ent = catalog.setdefault(url, {"role": None, "langs": set()})
            ent["langs"].add(key)
    for url, ent in catalog.items():
        if _EXCLUDE_PAT.search(url):
            ent["role"] = "exclude"
        elif _GENERIC_PAT.search(url):
            ent["role"] = "generic"
        else:
            ent["role"] = "lang"
    return catalog


def load_extensions():
    with open(os.path.join(SEEDDIR, "_extensions.json"), encoding="utf-8") as f:
        ext = json.load(f)
    out = {}
    for k, lst in ext.items():
        picked = [e for e in lst if e in VALID_EXT]
        # Guarantee at least a sane default so extension-expansion is never empty.
        out[k] = picked
    return out


def load_seeds(key):
    p = os.path.join(SEEDDIR, key + ".txt")
    if not os.path.exists(p):
        return []
    out = []
    for n in iter_lines(p):
        out.append(n)
    return out


# ---- tier builder ------------------------------------------------------------

class Tier:
    """Ordered, case-sensitive-deduped accumulator with a hard cap."""

    def __init__(self, cap):
        self.cap = cap
        self.seen = set()
        self.items = []

    @property
    def full(self):
        return len(self.items) >= self.cap

    def add(self, w):
        if self.full:
            return False
        if w in self.seen:
            return False
        self.seen.add(w)
        self.items.append(w)
        return True

    def extend(self, it):
        for w in it:
            if not self.add(w):
                if self.full:
                    break
        return self


def backup_perms(bases):
    """Yield base+suffix for each base and suffix (web -> web.bak, web.rar, …)."""
    for b in bases:
        b = b.rstrip("/")
        if not b:
            continue
        for suf in BACKUP_SUFFIXES:
            yield b + suf


def ext_expand(bases, exts):
    """Yield base.ext for each base and extension (admin -> admin.aspx, …)."""
    for b in bases:
        b = b.rstrip("/").split("?", 1)[0]
        if not b or b.endswith("/"):
            continue
        for e in exts:
            yield b + "." + e


def build_language(key, corpora, generic_bases, exts, caps, is_general):
    """Compose t1/t2/t3 for one key from already-loaded corpora + substrate."""
    seeds = corpora["seeds"]
    real_files = corpora["real"]      # list of local paths (language-specific)
    cap1, cap2, cap3 = caps

    # Permutation bases: PERM_BASES + stems of seeds (so web.config -> web.*, etc.)
    seed_stems = []
    seen_stem = set()
    for s in seeds:
        st = stem_of(s)
        if st and st not in seen_stem:
            seen_stem.add(st)
            seed_stems.append(st)
    perm_bases = list(dict.fromkeys(PERM_BASES + seed_stems))

    # ---- T1: seeds first (priority), then a bounded slice of real corpora, then perms
    t1 = Tier(cap1)
    t1.extend(seeds)
    if not is_general:
        t1.extend(backup_perms(perm_bases))
    for p in real_files:
        if t1.full:
            break
        t1.extend(iter_lines(p))

    # ---- T2: everything in T1 + full real corpora + (generic base x exts) + perms
    t2 = Tier(cap2)
    t2.extend(t1.items)
    for p in real_files:
        if t2.full:
            break
        t2.extend(iter_lines(p))
    if is_general:
        # general = directory names verbatim from the generic substrate
        for p in generic_bases["files"]:
            if t2.full:
                break
            t2.extend(iter_lines(p))
    else:
        if exts:
            t2.extend(ext_expand(generic_bases["bases_iter"](), exts))
        t2.extend(backup_perms(perm_bases))

    # ---- T3: everything in T2 + exhaustive expansion + big generic aggregates
    t3 = Tier(cap3)
    t3.extend(t2.items)
    if is_general:
        for p in generic_bases["files_big"]:
            if t3.full:
                break
            t3.extend(iter_lines(p))
    else:
        for p in real_files:
            if t3.full:
                break
            t3.extend(iter_lines(p))
        if exts:
            t3.extend(ext_expand(generic_bases["bases_iter_big"](), exts))
        # pad with generic directory names crossed with the primary extension too
        t3.extend(backup_perms(perm_bases))

    return {1: t1.items, 2: t2.items, 3: t3.items}


def write_gz(path, items):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with gzip.open(path, "wt", encoding="utf-8") as g:
        g.write("\n".join(items))
        if items:
            g.write("\n")
    return os.path.getsize(path)


# ---- orchestration -----------------------------------------------------------

def collect_sources(catalog, cache_dir, only_keys, sample):
    """Download everything (cached) and return per-key corpus path lists + generic paths."""
    generic_small, generic_big = [], []
    per_lang = {k: [] for k in LANGS}

    # Order generic by size hint so T2 gets smaller/high-signal substrate first.
    def generic_rank(url):
        u = url.lower()
        if "common.txt" in u or "quickhits" in u or "raft-large-dir" in u or "raft-large-file" in u:
            return 0
        if "raft-large-words" in u or "dicc" in u or "bo0om" in u or "onelistforallmicro" in u:
            return 1
        if "medium" in u or "combined" in u or "apiroutes" in u:
            return 2
        return 3  # directories_1m / directory-list-big / onelistforallshort / wordlist_*

    urls = sorted(catalog.keys())
    if sample:
        # Only small, stable, fast sources for an online smoke test.
        small = re.compile(
            r"(ror\.txt|PHP\.fuzz|ColdFusion\.fuzz|/common\.txt|CGIs\.txt|"
            r"Java-Spring-Boot|IIS\.txt|/php/PHP\.txt|login-file-locations/cfm)", re.I)
        urls = [u for u in urls if small.search(u)]

    for url in urls:
        ent = catalog[url]
        if ent["role"] == "exclude":
            continue
        p = fetch(url, cache_dir)
        if not p:
            continue
        if ent["role"] == "generic":
            (generic_small if generic_rank(url) <= 1 else generic_big).append((generic_rank(url), url, p))
        else:
            for lang in ent["langs"]:
                if lang in per_lang:
                    per_lang[lang].append(p)
    generic_small.sort(key=lambda t: t[0])
    generic_big.sort(key=lambda t: t[0])
    return per_lang, [p for _, _, p in generic_small], [p for _, _, p in generic_big]


def generic_base_provider(generic_small_paths, generic_big_paths, limit_small=400_000, limit_big=2_000_000):
    """Return callables that stream deduped base-names from the generic substrate."""
    def make(paths, limit):
        def gen():
            seen = set()
            n = 0
            for p in paths:
                for line in iter_lines(p):
                    base = line.rstrip("/").split("?", 1)[0]
                    if not base or base.endswith("/") or "." in base.rsplit("/", 1)[-1]:
                        # keep pure directory/word tokens as expansion bases
                        base = base.rsplit("/", 1)[-1]
                    base = base.rsplit("/", 1)[-1]
                    if not base or base in seen:
                        continue
                    seen.add(base)
                    n += 1
                    yield base
                    if n >= limit:
                        return
        return gen
    return make(generic_small_paths, limit_small), make(generic_big_paths or generic_small_paths, limit_big)


def run_build(outdir, cache_dir, only_keys, caps, sample):
    os.makedirs(cache_dir, exist_ok=True)
    catalog = load_catalog()
    ext_table = load_extensions()
    print("[*] catalog: %d urls (%d generic, %d lang, %d excluded)" % (
        len(catalog),
        sum(1 for e in catalog.values() if e["role"] == "generic"),
        sum(1 for e in catalog.values() if e["role"] == "lang"),
        sum(1 for e in catalog.values() if e["role"] == "exclude"),
    ))
    print("[*] downloading sources into %s ..." % cache_dir)
    per_lang, gsmall, gbig = collect_sources(catalog, cache_dir, only_keys, sample)
    small_prov, big_prov = generic_base_provider(gsmall, gbig)

    manifest = {"built_at": None, "caps": list(caps), "tiers": {}}
    keys = [k for k in ALL_KEYS if (not only_keys or k in only_keys)]
    for key in keys:
        is_general = key == GENERAL
        seeds = load_seeds(key)
        corpora = {"seeds": seeds, "real": per_lang.get(key, [])}
        generic_bases = {
            "files": gsmall,
            "files_big": gbig or gsmall,
            "bases_iter": small_prov,
            "bases_iter_big": big_prov,
        }
        exts = ext_table.get(key, []) if not is_general else []
        tiers = build_language(key, corpora, generic_bases, exts, caps, is_general)
        manifest["tiers"][key] = {}
        for t in (1, 2, 3):
            items = tiers[t]
            fn = "%s-t%d.txt.gz" % (key, t)
            sz = write_gz(os.path.join(outdir, fn), items)
            manifest["tiers"][key]["t%d" % t] = {"file": fn, "words": len(items), "bytes": sz}
            print("    %-12s t%d  %8d words  %9d gz-bytes" % (key, t, len(items), sz))

    manifest["built_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    manifest["built"] = True
    with open(os.path.join(outdir, "manifest.json"), "w", encoding="utf-8") as f:
        json.dump(manifest, f, ensure_ascii=False, indent=2, sort_keys=True)
        f.write("\n")
    print("[*] wrote manifest.json")
    print("[*] done -> %s" % outdir)


# ---- offline self-test (no network) ------------------------------------------

def run_selftest(outdir):
    """Synthetic, network-free build that exercises the full pipeline + asserts."""
    os.makedirs(outdir, exist_ok=True)
    caps = (2000, 5000, 12000)
    ext_table = load_extensions()

    # tiny synthetic corpora in a temp cache
    cache = os.path.join(outdir, "_synthetic")
    os.makedirs(cache, exist_ok=True)
    dotnet_corpus = os.path.join(cache, "dotnet_real.txt")
    with open(dotnet_corpus, "w", encoding="utf-8") as f:
        f.write("\n".join([
            "/admin/login.aspx", "Default.aspx", "api/values.svc",
            "evil.example.com",            # host-like → must be dropped
            "https://cdn.example.net/x.js", "# comment", "", "trace.axd",
        ]) + "\n")
    general_small = os.path.join(cache, "general_small.txt")
    with open(general_small, "w", encoding="utf-8") as f:
        f.write("\n".join(["admin", "login", "backup", "config", "uploads", "api", "test"]) + "\n")

    def small_prov():
        def gen():
            for b in ["admin", "login", "backup", "config", "uploads", "api", "test"]:
                yield b
        return gen()

    results = {}
    for key, real, is_general, exts in [
        ("dotnet", [dotnet_corpus], False, ext_table.get("dotnet", [])),
        ("general", [general_small], True, []),
    ]:
        corpora = {"seeds": load_seeds(key), "real": real}
        generic_bases = {
            "files": [general_small], "files_big": [general_small],
            "bases_iter": lambda: small_prov(), "bases_iter_big": lambda: small_prov(),
        }
        tiers = build_language(key, corpora, generic_bases, exts, caps, is_general)
        for t in (1, 2, 3):
            write_gz(os.path.join(outdir, "%s-t%d.txt.gz" % (key, t)), tiers[t])
        results[key] = tiers

    # ---- invariants
    errs = []
    d = results["dotnet"]
    if not (len(d[1]) <= len(d[2]) <= len(d[3])):
        errs.append("dotnet tier ordering t1<=t2<=t3 violated: %d/%d/%d" % (len(d[1]), len(d[2]), len(d[3])))
    allset = set(d[3])
    if "web.config" not in allset:
        errs.append("dotnet missing seed web.config")
    if "web.config.bak" not in set(d[2]) and "web.config.bak" not in allset:
        errs.append("dotnet missing backup-perm web.config.bak")
    if not any(x == "web.rar" for x in allset):
        errs.append("dotnet missing archive-perm web.rar")
    if not any(x.endswith(".aspx") for x in allset):
        errs.append("dotnet missing any .aspx extension-expansion")
    if "evil.example.com" in allset:
        errs.append("host-like line leaked into dotnet output (normalizer failed)")
    if "admin/login.aspx" not in allset:
        errs.append("dotnet real-corpus path admin/login.aspx (leading slash stripped) missing")
    # gz readable round-trip
    rt = list(iter_lines(os.path.join(outdir, "dotnet-t1.txt.gz")))
    if not rt:
        errs.append("dotnet-t1.txt.gz round-trip read empty")

    print("[selftest] dotnet tiers: %d / %d / %d" % (len(d[1]), len(d[2]), len(d[3])))
    print("[selftest] general tiers: %d / %d / %d" % (
        len(results["general"][1]), len(results["general"][2]), len(results["general"][3])))
    print("[selftest] sample dotnet-t3 head:", [x for x in d[3][:8]])
    if errs:
        print("\n[selftest] FAIL:")
        for e in errs:
            print("   -", e)
        return 1
    print("\n[selftest] OK — all invariants passed")
    return 0


def main(argv):
    ap = argparse.ArgumentParser(description="Build tiered per-language direnum wordlists.")
    ap.add_argument("--sample", action="store_true", help="small real-network subset (smoke test)")
    ap.add_argument("--selftest", metavar="DIR", help="offline synthetic build + asserts into DIR")
    ap.add_argument("--only", help="comma list of keys to build (default: all)")
    ap.add_argument("--cache", help="download cache dir")
    ap.add_argument("--out", help="output dir (default: data/direnum-wordlists)")
    ap.add_argument("--caps", help="override tier caps, e.g. 200000,1000000,3000000")
    args = ap.parse_args(argv)

    if args.selftest:
        return run_selftest(args.selftest)

    caps = DEFAULT_CAPS
    if args.caps:
        parts = [int(x) for x in args.caps.split(",")]
        if len(parts) == 3:
            caps = tuple(parts)
    only_keys = None
    if args.only:
        only_keys = set(x.strip() for x in args.only.split(",") if x.strip())
    cache_dir = args.cache or os.environ.get("DIRENUM_WL_CACHE") or os.path.join(
        tempfile.gettempdir(), "direnum-wl-cache")
    outdir = args.out or OUTDIR
    run_build(outdir, cache_dir, only_keys, caps, args.sample)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
