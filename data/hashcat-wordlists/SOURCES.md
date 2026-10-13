# Bundled Turkish wordlist — sources

`turkish-merged.txt.gz` is a deduplicated merge of public Turkish password/word
lists, shipped in-repo so the Hashcat module offers one comprehensive Turkish
option out of the box (hashcat reads `.gz` natively). Regenerate it with
[`scripts/build-turkish-wordlist.sh`](../../scripts/build-turkish-wordlist.sh).

**405,472 unique, case-sensitive entries**, merged in priority order (first
occurrence wins; regrews' `word password` lines are split so both the word and
the password become candidates).

| Source | What |
|---|---|
| [utkusen/turkce-wordlist](https://github.com/utkusen/turkce-wordlist) | Study of Turkish users' password choices (`wordlist.txt`, ~303k deduped) — the canonical Turkish list (SecLists' `turk303k.txt` is the same data). |
| [UtkuBasarann/turkish-wordlist-100k](https://github.com/UtkuBasarann/turkish-wordlist-100k) | ~92k realistic name + birth-year + symbol password variants. |
| [regrews/turkce-wordlist](https://github.com/regrews/turkce-wordlist) | RockYou passwords containing Turkish words (fork of utkusen; `word password` pairs). |

These are factual / common-password lists derived from public data,
redistributed here (as SecLists and similar projects do) for **authorized**
password auditing only. Use solely against systems you are permitted to test.
