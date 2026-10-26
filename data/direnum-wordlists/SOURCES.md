# Bundled per-language direnum wordlists — sources

`data/direnum-wordlists/<lang>-t{1,2,3}.txt.gz` are tiered, per-programming-language
directory/file wordlists for the **direnum** module, merged + deduplicated from ~100
public sources. direnum reads `.gz` natively. Build (or rebuild) them with
[`scripts/build-direnum-wordlists.sh`](../../scripts/build-direnum-wordlists.sh).

The heavy `.gz` output is **gitignored** (a one-time local build — hundreds of MB
download + output). What ships in-repo: the generator
([`build-direnum-wordlists.sh`](../../scripts/build-direnum-wordlists.sh) +
[`build-direnum-wordlists.py`](../../scripts/build-direnum-wordlists.py)), the curated
seeds ([`scripts/direnum-seeds/*.txt`](../../scripts/direnum-seeds/)), this file and
`manifest.json`. A fresh clone that hasn't built the lists **degrades gracefully** to
system SecLists (`/usr/share/seclists/...`) — exactly as before — until the generator runs.

## Tiers

Per language `L` (and a shared `general` directory-name list), three tiers, each an
additive superset of the previous, hybrid **real corpus + synthetic expansion**:

| Tier | Scan level | Cap | Contents |
|---|---|---|---|
| `t1` | Popular | ~200K | curated seeds + high-signal real corpora + top backup permutations |
| `t2` | Extended | ~1M | t1 + full real corpora + (generic base × L-extensions) + more permutations |
| `t3` | Exhaustive | ~3M | t2 + exhaustive extension-expansion + big generic aggregates |

Most languages have no 3M of *real* filenames (only PHP ~3.17M and the JS/dotfile
corpora approach it); for the rest, `t3` is mostly **synthetic**: generic directory
names crossed with the language's file extensions (`admin.aspx`, `backup.axd`, …) plus
backup/archive permutation (`web.config.bak`, `web.rar`, `bin.rar`, `db.sql.gz`, …) —
exactly the `web.rar`/`bin.rar` intent. Dedup is **case-sensitive, first-wins**, so
deliberate casing variants (`web.config` *and* `Web.config`) both survive; seeds come
first so the highest-signal probes lead each tier.

## Classification

- **Language-specific** path corpora feed only their language's tiers.
- **Generic** directory corpora (SecLists `directory-list-2.3`, `raft-*`, `common.txt`,
  Assetnote `directories_1m`, OneListForAll, …) feed the `general` list and act as the
  base substrate for every language's extension-expansion — kept separate, unioned at
  scan time (tick a language **and** `general`).
- A **host-list guard** drops bare `host.tld` tokens from every source, and verified
  host-lists (Assetnote `httparchive_{rails,django,flask,coldfusion}` — hostnames, not
  paths), repo-tree links, catalog JSON and reference docs are excluded outright.

## Sources by language

Line counts / sizes are as reported when the catalog was compiled (Assetnote `httparchive_*`
snapshots rotate monthly; the generator tolerates a rotated/410'd URL by skipping it).

### ASP.NET / IIS (`dotnet`)

| Source | Detail / size | URL |
|---|---|---|
| Assetnote — httparchive aspx/asp/cfm/svc/ashx/asmx (automated) | 71,623 lines (latest snapshot 2026_08_27); 48 monthly snapsh | https://wordlists-cdn.assetnote.io/data/automated/httparchive_aspx_asp_cfm_svc_ashx_asmx_2026_08_27.txt |
| random-robbie/bruteforce-lists — aspx.txt | 70,851 lines | https://raw.githubusercontent.com/random-robbie/bruteforce-lists/master/aspx.txt |
| random-robbie/bruteforce-lists — dll.txt | 77,156 lines | https://raw.githubusercontent.com/random-robbie/bruteforce-lists/master/dll.txt |
| random-robbie/bruteforce-lists — asp.txt | 20,239 lines | https://raw.githubusercontent.com/random-robbie/bruteforce-lists/master/asp.txt |
| random-robbie/bruteforce-lists — ashx.txt (HTTP handlers) | 19,252 lines | https://raw.githubusercontent.com/random-robbie/bruteforce-lists/master/ashx.txt |
| random-robbie/bruteforce-lists — web-service lists (asmx.txt, svc.txt) | asmx.txt 2,040; svc.txt 1,672 | https://raw.githubusercontent.com/random-robbie/bruteforce-lists/master/asmx.txt |
| random-robbie/bruteforce-lists — source/backup/config lists (cs, old, webconfig, config, web-inf, csproj, env) | old.txt 9,897; cs.txt 4,678; env.txt 1,396; webconfig.txt 89 | https://raw.githubusercontent.com/random-robbie/bruteforce-lists/master/old.txt |
| SecLists — .NET CMS lists (SharePoint/DNN/Umbraco/Kentico/Sitefinity/Sitecore) | kentico-cms-modules-themes ~545KB; dotnetnuke ~116KB; Umbrac | https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/CMS/dotnetnuke.txt |
| SecLists — Programming-Language-Specific/ASP.NET (webshells + ELMAH) | backdoors ~23; ELMAH-Debugger.txt ~6 | https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/Programming-Language-Specific/ASP.NET/CommonBackdoors-ASP.fuzz.txt |
| SecLists — Microsoft-Frontpage.txt | ~43 lines | https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/Microsoft-Frontpage.txt |
| fuzzdb — predictable-filepaths/webservers-appservers (IIS, ADFS, SharePoint, FrontPage) | IIS.txt ~200; ADFS.txt ~90; Sharepoint.txt ~1-2k; Frontpage. | https://raw.githubusercontent.com/fuzzdb-project/fuzzdb/master/discovery/predictable-filepaths/webservers-appservers/IIS.txt |
| ProjectDiscovery nuclei-templates — http/exposures + http/technologies (seed source, not a list) | N/A — per-template path matchers | https://github.com/projectdiscovery/nuclei-templates/tree/main/http/exposures |
| Generic permutation bases (DirBuster big / Assetnote directories_1m / raft-large-words) | DirBuster big 1,273,832 lines; Assetnote directories_1m ~1,0 | https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-big.txt |

> **Research notes:** REAL .NET-specific downloadable corpus (deduped union) tops out around ~250-300k lines — there is no multi-million real .NET wordlist in existence, so T2/T3 are permutation-driven. Measured line counts (wc -l): Assetnote httparchive aspx latest (2026_08_27)=71,623 with 48 monthly snapshots whose union (high overlap) is ~300-450k unique; random-robbie aspx=70,851, dll=77,156, asp=20,239, ashx=19,252, asmx=2,040, svc=1,672, cs=4,678, old=9,897; SecLists .NET CMS (kentico/dnn/umbraco/sharepoint/sitefinity/sitecore) ~40-60k combined; fuzzdb IIS/ADFS/SharePoint/FrontPage ~3-4k. T1 (~200k): essentially ALL REAL. Union {all recent Assetnote monthly aspx snapshots} + {random-robbie aspx/asp/ashx/asmx/svc/cs/old/dll} + {SecLists .NET CMS} + {fuzzdb dotnet} dedupes to ~200-280k. Only light synthesis needed: add the config-backup variants of web.config / appsettings.json / global.asax (a few hundre

### PHP (`php`)

| Source | Detail / size | URL |
|---|---|---|
| Assetnote manual/php.txt (THE massive real PHP corpus) | 3,174,758 lines / 81.3 MB (85,270,800 bytes, verified HTTP 2 | https://wordlists-cdn.assetnote.io/data/manual/php.txt |
| Assetnote manual/phpmillion.txt | 1,000,000 lines / 55.1 MB (verified HTTP 200) | https://wordlists-cdn.assetnote.io/data/manual/phpmillion.txt |
| Assetnote technologies/httparchive_laravel (latest monthly) | 169,388 lines / 4.6 MB (verified HTTP 200) | https://wordlists-cdn.assetnote.io/data/technologies/httparchive_laravel_2026_08_27.txt |
| Assetnote technologies/httparchive_symfony (latest monthly) | 16,988 lines / 0.48 MB | https://wordlists-cdn.assetnote.io/data/technologies/httparchive_symfony_2026_08_27.txt |
| Assetnote technologies/httparchive_yii (latest monthly) | 32,220 lines / 0.89 MB | https://wordlists-cdn.assetnote.io/data/technologies/httparchive_yii_2026_08_27.txt |
| Assetnote technologies/httparchive_zend (latest monthly) | 339 lines / 10.6 kb | https://wordlists-cdn.assetnote.io/data/technologies/httparchive_zend_2026_08_27.txt |
| Assetnote automated/httparchive_php (latest monthly) | 169,336 lines / 3.1 MB (verified HTTP 200) | https://wordlists-cdn.assetnote.io/data/automated/httparchive_php_2026_08_27.txt |
| Assetnote automated/httparchive_directories_1m (latest monthly) | 696,827 lines / 19.2 MB | https://wordlists-cdn.assetnote.io/data/automated/httparchive_directories_1m_2026_08_27.txt |
| Assetnote manual/dot_filenames.txt | 3,191,712 lines / 71.3 MB (74,750,104 bytes, verified HTTP 2 | https://wordlists-cdn.assetnote.io/data/manual/dot_filenames.txt |
| Assetnote manual/bak.txt (backup-suffix driver) | 31,725 lines / 0.65 MB (verified HTTP 200) | https://wordlists-cdn.assetnote.io/data/manual/bak.txt |
| Assetnote manual/raft-large-files.txt (+ -directories, -words) | files 37,042 / directories 62,283 / words 119,600 | https://wordlists-cdn.assetnote.io/data/manual/raft-large-files.txt |
| random-robbie/bruteforce-lists larv.txt (Laravel) | 30,134 lines | https://raw.githubusercontent.com/random-robbie/bruteforce-lists/master/larv.txt |
| random-robbie/bruteforce-lists php.txt | 12,924 lines | https://raw.githubusercontent.com/random-robbie/bruteforce-lists/master/php.txt |
| random-robbie/bruteforce-lists env.txt | 1,396 lines | https://raw.githubusercontent.com/random-robbie/bruteforce-lists/master/env.txt |
| random-robbie/bruteforce-lists old.txt | 9,897 lines | https://raw.githubusercontent.com/random-robbie/bruteforce-lists/master/old.txt |
| random-robbie/bruteforce-lists combined_directories.txt | 1,377,725 lines | https://raw.githubusercontent.com/random-robbie/bruteforce-lists/master/combined_directories.txt |
| SecLists Common-PHP-Filenames.txt | 5,163 lines | https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/Programming-Language-Specific/Common-PHP-Filenames.txt |
| SecLists PHP.fuzz.txt | 104 lines | https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/Programming-Language-Specific/PHP.fuzz.txt |
| SecLists CommonBackdoors-PHP.fuzz.txt (web shells) | 422 lines | https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/Programming-Language-Specific/CommonBackdoors-PHP.fuzz.txt |
| SecLists CMS/symfony-315-demo.txt | 305 lines | https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/CMS/symfony-315-demo.txt |
| SecLists raft-large-directories.txt (+ files, words) | directories 62,281 / files 37,050 / words 119,600 | https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-large-directories.txt |
| SecLists DirBuster-2007 directory-list-2.3-medium.txt | ~220,560 lines | https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt |
| SecLists DirBuster-2007 directory-list-2.3-big.txt | ~1,273,833 lines | https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-big.txt |
| fuzzdb discovery/predictable-filepaths/php/PHP.txt | 29 lines (+ PHP_CommonBackdoors.txt alongside) | https://raw.githubusercontent.com/fuzzdb-project/fuzzdb/master/discovery/predictable-filepaths/php/PHP.txt |
| ProjectDiscovery nuclei-templates (path-mining source, not a flat list) | N/A - mine payload paths from ~50 PHP-stack templates | https://github.com/projectdiscovery/nuclei-templates |

> **Research notes:** CLASSIFIER: bucket a generic-corpus line into PHP when its final segment ends in one of the php extensions (php/phtml/php3-8/pht/phps/phar/inc/phpt) OR the path contains a distinctive token (artisan, telescope, horizon, nova, _debugbar, _ignition, livewire, _profiler, _wdt, _fragment, app_dev.php, appkernel, symfony.lock, composer.json/lock, vendor/, phpmyadmin, adminer, parameters.yml, bundles.php). The backup-prone config tokens (env, config.php, config.inc.php, configuration.php, settings.php, database.php, parameters.yml, composer.lock, auth.json) are listed so the classifier also catches their suffixed/backup forms (.env.old, config.php.bak, parameters.yml.dist) which the bare 'php' extension misses. REAL CORPUS (deduped approx, all verified reachable): Assetnote php.txt=3.17M, phpmillion.txt=1.0M, dot_filenames.txt=3.19M (dotfiles, cross-tech); httparchive per-tech laravel=169k, ph

### Java / JSP / Spring (`java`)

| Source | Detail / size | URL |
|---|---|---|
| Assetnote manual do.txt (Struts / Spring-MVC .do paths) | ~5.0 MB, ~160k lines | https://wordlists-cdn.assetnote.io/data/manual/do.txt |
| Assetnote manual jsp.txt (JSP paths) | ~2.3 MB, ~90k lines | https://wordlists-cdn.assetnote.io/data/manual/jsp.txt |
| Assetnote automated httparchive_jsp_jspa_do_action (current) | ~345 KB, ~12k lines | https://wordlists-cdn.assetnote.io/data/automated/httparchive_jsp_jspa_do_action_2026_08_27.txt |
| Assetnote manual xml_filenames.txt | ~53 MB, ~2M lines | https://wordlists-cdn.assetnote.io/data/manual/xml_filenames.txt |
| SecLists Programming-Language-Specific/Java-Spring-Boot.txt | ~3.6 KB, ~250 lines | https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/Programming-Language-Specific/Java-Spring-Boot.txt |
| SecLists Web-Servers framework files (Tomcat/JBoss/GlassFish/JRun/Axis) | Apache-Tomcat.txt ~3.6 KB; JBoss.txt 365 B; Glassfish-Sun-Mi | https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/Web-Servers/Apache-Tomcat.txt |
| SecLists JSP/J2EE misc lists | small (56 B - 5 KB each) | https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/JavaServlets-Common.fuzz.txt |
| fuzzdb webservers-appservers (JBoss/WebLogic/Tomcat/WebSphere/GlassFish/Oracle) | small, high-signal (dozens-hundreds of lines each) | https://raw.githubusercontent.com/fuzzdb-project/fuzzdb/master/discovery/predictable-filepaths/webservers-appservers/Weblogic.txt |
| random-robbie/bruteforce-lists web-inf.txt + Java config/backup lists | web-inf.txt ~2.9 KB; properties-files.txt ~1 KB; swagger.txt | https://raw.githubusercontent.com/random-robbie/bruteforce-lists/master/web-inf.txt |
| Assetnote automated httparchive_directories_1m (generic directories) | ~20 MB, ~1,000,000 lines | https://wordlists-cdn.assetnote.io/data/automated/httparchive_directories_1m_2026_08_27.txt |
| Assetnote automated httparchive_apiroutes (REST/API routes) | ~12 MB, ~400k lines | https://wordlists-cdn.assetnote.io/data/automated/httparchive_apiroutes_2026_08_27.txt |
| SecLists DirBuster directory-list-2.3 (generic big dirs) | big ~14.8 MB (~1.2M lines); medium ~2 MB (~220k) | https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/directory-list-2.3-big.txt |
| SecLists raft-large lists + api/ endpoint lists | raft-large-words.txt ~1 MB (~90k); raft-large-directories.tx | https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-large-words.txt |
| Assetnote manual bak.txt + raft extensions (permutation inputs) | bak.txt ~650 KB (~40k backup bases) | https://wordlists-cdn.assetnote.io/data/manual/bak.txt |
| ProjectDiscovery nuclei-templates (seed provenance, not a corpus) | n/a (YAML templates) | https://github.com/projectdiscovery/nuclei-templates/tree/main/http/exposures |
| random-robbie combined_directories.txt (generic big, optional) | ~16 MB | https://raw.githubusercontent.com/random-robbie/bruteforce-lists/master/combined_directories.txt |

> **Research notes:** REAL Java-specific corpus is unusually large for this stack thanks to Assetnote's manual per-extension lists, so tiers lean more on real data than most stacks. T1 (~200k) - REACHABLE WITH REAL DATA, little/no permutation: Assetnote manual do.txt (~160k .do/Struts/Spring-MVC) + jsp.txt (~90k JSP), deduped ~=180-220k; top up with httparchive_jsp_jspa_do_action (~12k), SecLists raft-large-directories (~62k) and the curated framework seeds/fuzzdb/SecLists/random-robbie files (~3-5k). Clean, high-signal. T2 (~1M): unique REAL Java-specific content plateaus around ~250-300k (do.txt + jsp.txt + httparchive + framework files heavily overlap). Reach 1M by (a) folding in generic-but-applicable big corpora the classifier buckets into Java -- httparchive_directories_1m (~1M), httparchive_apiroutes (~400k, great for Spring REST), SecLists DirBuster directory-list-2.3-big (~1.2M), raft-large-words (~9

### Python / Django / Flask (`python`)

| Source | Detail / size | URL |
|---|---|---|
| OneListForAll dict/django_long.txt (six2dez) | 584 KB, ~38-40k lines | https://raw.githubusercontent.com/six2dez/OneListForAll/main/dict/django_long.txt |
| OneListForAll dict/python_long.txt (six2dez) | 10 KB, ~400 lines | https://raw.githubusercontent.com/six2dez/OneListForAll/main/dict/python_long.txt |
| Assetnote httparchive_apiroutes (automated) | 11.5 MB, 403,119 lines | https://wordlists-cdn.assetnote.io/data/automated/httparchive_apiroutes_2026_08_27.txt |
| Assetnote httparchive_directories_1m (automated) | 19.2 MB, 696,827 lines | https://wordlists-cdn.assetnote.io/data/automated/httparchive_directories_1m_2026_08_27.txt |
| OneListForAll dict/swagger_long.txt + swagger_short.txt | long 16.7 MB (~800k-1M lines); short 101 KB | https://raw.githubusercontent.com/six2dez/OneListForAll/main/dict/swagger_long.txt |
| OneListForAll dict/graphql_long.txt + graphql_short.txt | long 19 MB (~0.9-1.1M lines); short 69 KB | https://raw.githubusercontent.com/six2dez/OneListForAll/main/dict/graphql_long.txt |
| OneListForAll dict/api_long.txt + api_short.txt | long 49.4 MB (~2.3-3M lines); short 10.2 MB | https://raw.githubusercontent.com/six2dez/OneListForAll/main/dict/api_long.txt |
| OneListForAll dict/paths_long.txt + paths_short.txt | long 37.4 MB (~1.5-2M lines); short 3.3 MB | https://raw.githubusercontent.com/six2dez/OneListForAll/main/dict/paths_long.txt |
| SecLists api/ endpoint lists (api-endpoints, api-seen-in-wild, actions, objects) | api-endpoints ~5k; api-seen-in-wild ~2.5k; actions/objects s | https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/api/api-endpoints.txt |
| OneListForAll config/secret pieces (config_long, env_long, debug_long, dotfiles_long, db_backups_long) | config_long 1.3 MB; env_long 20 KB; debug_long 5.7 KB; dotfi | https://raw.githubusercontent.com/six2dez/OneListForAll/main/dict/config_long.txt |
| Random-Robbie/bruteforce-lists secret-file lists (env, config, keys, dotfiles) | small, hundreds each | https://raw.githubusercontent.com/Random-Robbie/bruteforce-lists/master/env.txt |
| SecLists generic baseline (raft-large-directories/files/words, common.txt) | raft-large-directories ~62k; raft-large-files ~37k; raft-lar | https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-large-directories.txt |
| OneListForAll onelistforallshort.txt (aggregate) | 38.8 MB, ~2.3-2.6M lines | https://raw.githubusercontent.com/six2dez/OneListForAll/main/onelistforallshort.txt |
| dirsearch db/dicc.txt (maurosoria) | ~240 KB, ~11k lines | https://raw.githubusercontent.com/maurosoria/dirsearch/master/db/dicc.txt |
| Bo0oM/fuzz.txt | ~260 KB, ~4.7k lines | https://raw.githubusercontent.com/Bo0oM/fuzz.txt/master/fuzz.txt |
| OneListForAll dict/ssti_long.txt (niche) | 78 KB | https://raw.githubusercontent.com/six2dez/OneListForAll/main/dict/ssti_long.txt |
| EXCLUDE: Assetnote technologies httparchive_django/flask (host mappings) | django 46,000 lines; flask 1,313 lines | https://wordlists-cdn.assetnote.io/data/technologies/httparchive_django_2026_08_27.txt |
| EXCLUDE/skip: fuzzdb discovery/predictable-filepaths | n/a | https://github.com/fuzzdb-project/fuzzdb/tree/master/discovery/predictable-filepaths |

> **Research notes:** REALITY CHECK (this stack is unusual): Python web frameworks ROUTE URLs (regex/decorator dispatch) instead of mapping files to disk, so there is essentially NO large, high-quality, Python-framework-specific PATH corpus in the public ecosystem, and Assetnote has NO .py extension list (confirmed: automated.json has php/aspx/jsp/cgi_pl but no py). Verified traps: (1) Assetnote technologies/httparchive_django.txt and _flask.txt are HOST-MAPPING lists (lists of sites running the tech), NOT path wordlists - must be excluded from the generator. (2) OLFA flask_long.txt (652 B) is mostly Flask CONFIG KEY names (SECRET_KEY, SESSION_COOKIE_*), not paths; python_long.txt is small and polluted. NET: the real Python-SPECIFIC unique path content caps at roughly 50-100k lines (OLFA django_long ~39k + swagger/graphql/api-doc specifics + the ~320 curated seeds here). Everything bigger is generic web-path 

### Ruby / Rails (`ruby`)

| Source | Detail / size | URL |
|---|---|---|
| SecLists - ror.txt (Ruby on Rails, the only curated RoR path list) | 2.7 KB, ~190 lines | https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/Programming-Language-Specific/ror.txt |
| HackTricks - Ruby tricks (Rails/Rack CVE + traversal probe paths) | reference page (not a corpus) | https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/network-services-pentesting/pentesting-web/ruby-tricks.md |
| SecLists - Common-DB-Backups.txt (backup-suffix permutation seed) | 4.6 KB, ~280 lines | https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/Common-DB-Backups.txt |
| SecLists - quickhits.txt (dev/backup leftovers) | 40 KB, ~2,600 lines | https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/quickhits.txt |
| Assetnote - httparchive_directories_1m (biggest REAL generic path corpus) | 20.2 MB, 696,827 lines (verified) | https://wordlists-cdn.assetnote.io/data/automated/httparchive_directories_1m_2026_08_27.txt |
| Assetnote - httparchive_apiroutes (API routes, Rails API mode) | 12.1 MB, ~400-600k lines | https://wordlists-cdn.assetnote.io/data/automated/httparchive_apiroutes_2026_08_27.txt |
| SecLists - raft-large-directories.txt | 542 KB, ~62,000 lines | https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-large-directories.txt |
| SecLists - raft-large-files.txt | 494 KB, ~37,000 lines | https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-large-files.txt |
| SecLists - raft-large-words.txt | 1.05 MB, ~86,000 lines | https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-large-words.txt |
| random-robbie/bruteforce-lists - env.txt (.env variants) | 26.5 KB, ~2,000 lines | https://raw.githubusercontent.com/random-robbie/bruteforce-lists/master/env.txt |
| random-robbie/bruteforce-lists - old.txt + combined_directories.txt | old.txt 220 KB (~15k); combined_directories.txt 16.2 MB (~1M | https://raw.githubusercontent.com/random-robbie/bruteforce-lists/master/old.txt |
| six2dez/OneListForAll - onelistforallshort.txt (T3 kitchen-sink aggregate) | 38.9 MB, ~2.5-3M lines (verified size) | https://raw.githubusercontent.com/six2dez/OneListForAll/main/onelistforallshort.txt |
| six2dez/OneListForAll - onelistforallmicro.txt | 559 KB, ~40,000 lines | https://raw.githubusercontent.com/six2dez/OneListForAll/main/onelistforallmicro.txt |
| SecLists - DirBuster-2007_directory-list-2.3-big.txt | 14.8 MB, ~1,273,000 lines | https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-big.txt |
| SecLists - common.txt / big.txt (baseline generic) | common.txt 38.5 KB (~4,700); big.txt 166 KB (~20,500) | https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt |
| Assetnote - httparchive_rails HOST list (DISCOVERY ONLY - NOT PATHS) | 6.8 MB, 217,262 lines - ALL hostnames (verified: 0 non-URL l | https://wordlists-cdn.assetnote.io/data/technologies/httparchive_rails_2026_08_27.txt |
| fuzzdb - discovery/predictable-filepaths (low Ruby yield) | directory tree; no Ruby-specific file | https://github.com/fuzzdb-project/fuzzdb/tree/master/discovery/predictable-filepaths |

> **Research notes:** CORE REALITY: Unlike PHP/ASP.NET/Java, Ruby/Rails has essentially NO large public *path* wordlist. The file everyone assumes is one - Assetnote's httparchive_rails (6.8 MB) - is a technology->host mapping (217,262 hostnames, verified 0 non-URL lines), not paths. Genuinely Ruby-distinctive PATH content available publicly is tiny: SecLists ror.txt (~190) + the seed_lines here (~330) + HackTricks CVE/traversal paths (~15) = ~500 curated lines, plus maybe ~10-30k more mined by the classifier from the Ruby-token/ext slice of the big generic corpora (directories_1m, raft, OneListForAll, combined_directories). Everything beyond ~20-30k is synthetic permutation or generic spillover. This is also inherent to Rails: real structure hides behind RESTful controller#action routes that are app-specific and not brute-forceable from a generic list - so the highest-value Ruby targets are the FIXED framewo

### Node.js / Express (`nodejs`)

| Source | Detail / size | URL |
|---|---|---|
| Assetnote automated httparchive_js (PRIMARY .js corpus) | 3,986,162 lines / 75.7 MB | https://wordlists-cdn.assetnote.io/data/automated/httparchive_js_2026_08_27.txt |
| Assetnote manual dot_filenames (dotfiles corpus) | 3,191,712 lines / 71.3 MB | https://wordlists-cdn.assetnote.io/data/manual/dot_filenames.txt |
| Assetnote technologies httparchive_express (HIGHEST SIGNAL) | 146,929 lines / 4.3 MB | https://wordlists-cdn.assetnote.io/data/technologies/httparchive_express_2026_08_27.txt |
| Assetnote automated httparchive_apiroutes | 403,119 lines / 11.5 MB | https://wordlists-cdn.assetnote.io/data/automated/httparchive_apiroutes_2026_08_27.txt |
| Assetnote automated httparchive_directories_1m | 696,827 lines / 19.2 MB | https://wordlists-cdn.assetnote.io/data/automated/httparchive_directories_1m_2026_08_27.txt |
| Assetnote manual raft-large (words/files/directories) | words 119,600 / files 37,042 / directories 62,283 | https://wordlists-cdn.assetnote.io/data/manual/raft-large-words.txt |
| Assetnote manual bak.txt (backup-suffix seeds) | 31,725 lines / 634.8 KB | https://wordlists-cdn.assetnote.io/data/manual/bak.txt |
| Assetnote JSON catalogs (resolve current monthly filenames) | catalog (also technologies.json, manual.json) | https://wordlists-cdn.assetnote.io/data/automated.json |
| SecLists API endpoint lists | api-endpoints ~37k; also objects.txt, actions.txt, api-seen- | https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/api/api-endpoints.txt |
| SecLists graphql.txt | ~small (hundreds) | https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/graphql.txt |
| SecLists raft-large (words/files/directories) | words 119,600 / files 37,042 / directories 62,283 | https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-large-words.txt |
| random-robbie bruteforce-lists (curated Node-relevant files) | env.txt large (.env permutations); plus npmrc.txt, dotfiles. | https://raw.githubusercontent.com/random-robbie/bruteforce-lists/master/env.txt |
| ProjectDiscovery nuclei-templates (path mining, not bulk download) | N/A (extract path strings from YAML) | https://github.com/projectdiscovery/nuclei-templates/tree/main/http/exposures |
| fuzzdb discovery/predictable-filepaths | UnixDotfiles ~small, KitchensinkDirectories ~large | https://github.com/fuzzdb-project/fuzzdb/tree/master/discovery/predictable-filepaths |

> **Research notes:** TIER MATH (this stack). The Node-SPECIFIC real corpus is actually modest: the only high-precision real lists are Assetnote httparchive_express (147k), SecLists api/* (~40k), random-robbie curated (a few k), and the ~330 curated seeds. The big volume comes from generic-but-on-format corpora bucketed by extension (.js/.json/.ts/.map/.env). T1 ~200k (REAL): httparchive_express (147k) + SecLists api/* (~40k) + raft-large-words (120k) + seeds, dedup -> ~200k, essentially 100% real; OR a token-filtered slice of httparchive_js (lines with _next/_nuxt/dist/build/static/js/chunk/bundle/webpack/assets) which yields ~150-300k real. T2 ~1M (REAL, no synthetic needed): httparchive_js (3.99M raw, or token-filtered) + httparchive_apiroutes (403k) + httparchive_directories_1m (697k) + dot_filenames filtered to node dotfiles (.env/.npmrc/.babelrc/.eslintrc/.prettierrc/.nvmrc...), dedup -> comfortably 1M+

### Adobe ColdFusion (`coldfusion`)

| Source | Detail / size | URL |
|---|---|---|
| SecLists - CMS/ColdFusion.fuzz.txt | 203 lines / ~7 KB | https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/CMS/ColdFusion.fuzz.txt |
| fuzzdb - webservers-appservers/ColdFusion.txt | 111 lines | https://raw.githubusercontent.com/fuzzdb-project/fuzzdb/master/discovery/predictable-filepaths/webservers-appservers/ColdFusion.txt |
| fuzzdb - webservers-appservers/JRun.txt | 13 lines | https://raw.githubusercontent.com/fuzzdb-project/fuzzdb/master/discovery/predictable-filepaths/webservers-appservers/JRun.txt |
| fuzzdb - login-file-locations/cfm.txt | 294 lines | https://raw.githubusercontent.com/fuzzdb-project/fuzzdb/master/discovery/predictable-filepaths/login-file-locations/cfm.txt |
| fuzzdb - attack/file-upload/alt-extensions-coldfusion.txt | 40 lines | https://raw.githubusercontent.com/fuzzdb-project/fuzzdb/master/attack/file-upload/alt-extensions-coldfusion.txt |
| Assetnote automated - aspx_asp_cfm_svc_ashx_asmx (latest) | 71,623 lines / 1.5 MB | https://wordlists-cdn.assetnote.io/data/automated/httparchive_aspx_asp_cfm_svc_ashx_asmx_2026_08_27.txt |
| Assetnote automated - jsp_jspa_do_action (latest) | 19,569 lines / 346 KB | https://wordlists-cdn.assetnote.io/data/automated/httparchive_jsp_jspa_do_action_2026_08_27.txt |
| random-robbie/bruteforce-lists - cfm.txt | 1,006 lines | https://raw.githubusercontent.com/random-robbie/bruteforce-lists/master/cfm.txt |
| SecLists - SVNDigger/cat/Language/cfm.txt | 25 lines | https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/File-Extensions-Universal-SVNDigger-Project/cat/Language/cfm.txt |
| ProjectDiscovery nuclei-templates (coldfusion + lucee) | N/A (template repo) | https://github.com/projectdiscovery/nuclei-templates/tree/main/http |
| Assetnote automated - directories_1m (volume substrate) | ~1,000,000 lines | https://wordlists-cdn.assetnote.io/data/automated/httparchive_directories_1m_2026_08_27.txt |
| SecLists - directory-list-2.3-big.txt (volume substrate) | ~1.2M lines (big); medium ~220k | https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/directory-list-2.3-big.txt |
| Assetnote technologies - httparchive_coldfusion (HOST list, NOT paths) | 7,944 lines (hostnames) | https://wordlists-cdn.assetnote.io/data/technologies/httparchive_coldfusion_2026_08_27.txt |

> **Research notes:** REAL vs SYNTHETIC for ColdFusion/CFML. Truly CF-classified real paths are scarce: curated framework lists (SecLists ColdFusion.fuzz 203 + fuzzdb ColdFusion 111 + JRun 13 + login/cfm 294 + SVNDigger 25) plus these ~290 seeds dedupe to roughly 900-1,100 unique framework/secret/scaffold paths - these are exactly what generic corpora MISS (grepping Assetnote's 71.6k cfm corpus for CFIDE/lucee/railo/adminapi returned ZERO; only cfusion.cfm appeared). Real .cfm page-name volume comes from Assetnote cfm-series (71.6k mixed, realistically ~10-20k truly cfm after classifying) + random-robbie cfm.txt (1,006), i.e. ~15-25k real .cfm paths. So pure-real CF ~= 20-30k lines; the dedicated-stack corpus is far below any tier on its own. HOW TO HIT THE TIERS: T1 ~200k (~45% real / ~55% permutation): union all real (the ~1k framework seeds + full Assetnote cfm-series 71.6k used wholesale + jsp-series 19.5

### Perl / CGI (`perl`)

| Source | Detail / size | URL |
|---|---|---|
| Assetnote httparchive_cgi_pl (latest monthly) | 11,350 lines / 345 KB | https://wordlists-cdn.assetnote.io/data/automated/httparchive_cgi_pl_2026_08_27.txt |
| Assetnote directories_1m (generic feedstock for permutation) | ~1,000,000 lines / 20 MB | https://wordlists-cdn.assetnote.io/data/automated/httparchive_directories_1m_2026_08_27.txt |
| SecLists CGIs.txt (LEGACY-SERVICES) | 3,388 lines | https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/LEGACY-SERVICES/CGIs/CGIs.txt |
| SecLists CGI-XPlatform.fuzz.txt | 3,948 lines | https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/LEGACY-SERVICES/CGIs/CGI-XPlatform.fuzz.txt |
| SecLists CGI-Microsoft.fuzz.txt | 74 lines | https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/LEGACY-SERVICES/CGIs/CGI-Microsoft.fuzz.txt |
| SecLists raft-large-words.txt + raft-large-extensions.txt | 119,600 words (+ extensions list carries .pl/.cgi/.pm/.plx/. | https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-large-words.txt |
| SecLists SVNDigger Language/pl.txt | 135 lines | https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/File-Extensions-Universal-SVNDigger-Project/cat/Language/pl.txt |
| fuzzdb cgi/CGI_XPlatform.txt + CGI_Microsoft.txt + CGI_HTTP_POST.txt | 3,948 / 79 / small | https://raw.githubusercontent.com/fuzzdb-project/fuzzdb/master/discovery/predictable-filepaths/cgi/CGI_XPlatform.txt |
| fuzzdb attack/file-upload/alt-extensions-perl.txt | 33 lines | https://raw.githubusercontent.com/fuzzdb-project/fuzzdb/master/attack/file-upload/alt-extensions-perl.txt |
| random-robbie/bruteforce-lists perl-files.txt | 1,236 lines | https://raw.githubusercontent.com/random-robbie/bruteforce-lists/master/perl-files.txt |
| random-robbie/bruteforce-lists cgi-files.txt | 1,192 lines | https://raw.githubusercontent.com/random-robbie/bruteforce-lists/master/cgi-files.txt |
| Nikto db_tests (classic CGI mega-DB) | 7,288 lines | https://raw.githubusercontent.com/sullo/nikto/master/program/databases/db_tests |
| ProjectDiscovery nuclei-templates (exact app paths) | path source, not a flat wordlist | https://github.com/projectdiscovery/nuclei-templates/tree/main/http/exposures/configs |
| OneListForAll (optional mega aggregate) | onelistforallmicro ~37k up to onelistforall ~5.1M lines | https://github.com/six2dez/OneListForAll |

> **Research notes:** CORPUS REALITY: Perl/CGI has a SMALL real-world footprint and it is shrinking (legacy stack). Hard proof from Assetnote's own HTTP Archive extraction: the php list is 3.28 MB (~1M+ real paths) while cgi_pl is only 345 KB / 11,350 lines - roughly 30x smaller. After merging + dedupe + payload-stripping across Assetnote cgi_pl (~11k), SecLists CGIs/XPlatform/Microsoft (~7.4k raw -> ~3-4k unique base paths), fuzzdb CGI_* (overlaps SecLists), random-robbie perl/cgi (~2.5k), Nikto base paths (~2-3k unique after collapsing payload variants), SVNDigger pl (135) and the curated seed_lines (~380), the TRUE unique Perl-specific corpus is only ~25-35k lines. Everything above that is synthetic permutation.\n\nHOW TO HIT THE TIERS:\n- T1 ~200k: ~30k real corpus + permutation. Take ~35-40k base tokens (raft-medium/large-words or the distinct basenames already in the real corpus + common app dirs) x the

### Classic ASP / legacy IIS (`classicasp`)

| Source | Detail / size | URL |
|---|---|---|
| Assetnote httparchive combined asp/aspx family (PRIMARY real corpus) | ~1.56 MB, ~95k lines (bare filenames, no leading slash) | https://wordlists-cdn.assetnote.io/data/automated/httparchive_aspx_asp_cfm_svc_ashx_asmx_2026_08_27.txt |
| Assetnote httparchive_directories_1m (generic dir base for permutation) | ~1,000,000 lines (directory names) | https://wordlists-cdn.assetnote.io/data/automated/httparchive_directories_1m_2026_08_27.txt |
| random-robbie/bruteforce-lists aspx.txt | ~1.59 MB, ~90k-110k lines | https://raw.githubusercontent.com/random-robbie/bruteforce-lists/master/aspx.txt |
| random-robbie/bruteforce-lists asp.txt | ~372 KB, ~21k lines | https://raw.githubusercontent.com/random-robbie/bruteforce-lists/master/asp.txt |
| random-robbie/bruteforce-lists ashx.txt / asmx.txt / svc.txt / webconfig.txt / web-inf.txt | ashx ~455 KB/~27k; asmx ~44 KB; svc ~36 KB; webconfig ~1.7 K | https://raw.githubusercontent.com/random-robbie/bruteforce-lists/master/ashx.txt |
| random-robbie/bruteforce-lists old.txt + combined_directories.txt (backup/base) | old.txt ~220 KB/~13k backup base names; combined_directories | https://raw.githubusercontent.com/random-robbie/bruteforce-lists/master/old.txt |
| SecLists Web-Servers/IIS.txt (legacy IIS/classic-ASP canon) | ~100-150 lines (curated) | https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/Web-Servers/IIS.txt |
| SecLists Microsoft-Frontpage.txt (FrontPage Server Extensions) | ~60-80 lines | https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/Microsoft-Frontpage.txt |
| SecLists SVNDigger Language asp.txt / aspx.txt / ascx.txt (real app files) | asp.txt ~8.9 KB/~420 lines; aspx.txt ~3.3 KB/~160; ascx.txt  | https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/File-Extensions-Universal-SVNDigger-Project/cat/Language/asp.txt |
| SecLists generic high-volume (permutation base + extension list) | raft-large-words ~120k; raft-large-files ~37k; raft-large-di | https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-large-words.txt |
| fuzzdb webservers-appservers IIS.txt / Frontpage.txt / HTTP_POST_Microsoft.txt | IIS.txt ~90 lines; Frontpage.txt ~40; HTTP_POST_Microsoft.tx | https://raw.githubusercontent.com/fuzzdb-project/fuzzdb/master/discovery/predictable-filepaths/webservers-appservers/IIS.txt |
| Assetnote full-mirror (bulk) + wordlists.assetnote.io index | whole /data/ dir mirrorable via wget | https://wordlists.assetnote.io/ |

> **Research notes:** REALITY: classic ASP is a legacy stack, so there is NO giant single-stack corpus. Real, de-duplicated classic/aspnet-mixed material tops out around ~250k-300k lines; everything above that is synthetic permutation. The generator should (a) download the real sources, (b) extension-filter the mixed Assetnote/random-robbie files to .asp/.asa/.inc lines for the classicasp bucket (share .aspx/.ashx/.asmx/.svc with an aspnet bucket), then (c) permute.\n\nT1 ~200k (ESSENTIALLY ALL REAL): concat Assetnote combined asp/aspx family (~95k) + random-robbie asp.txt (~21k) + aspx.txt (~90k) + ashx.txt (~27k) + SecLists IIS/FrontPage/SVNDigger + fuzzdb + these seeds, then dedup. Lands ~200k-280k real lines. Optionally add one light backup pass (×{.bak,.old}) only if short. ~95-100% real.\n\nT2 ~1M (~25% real / ~75% synthetic): take base = (real classicasp filenames with extension stripped) ∪ raft-large-

### General directory names (`general`)

| Source | Detail / size | URL |
|---|---|---|
| SecLists - raft-* directories/files/words (Discovery/Web-Content) | raft-large-directories ~62k lines (529KB); raft-large-files  | https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-large-directories.txt |
| SecLists - quickhits.txt (high-signal) | ~2.4k lines (40KB) | https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/quickhits.txt |
| SecLists - common.txt (dirb) + big.txt | common.txt ~4.7k lines (38KB); big.txt ~20.5k lines (166KB); | https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt |
| SecLists - DirBuster directory-list-2.3 (big/medium/small) | big = 1,273,833 lines (14.8MB); medium = 220,560 (2.0MB); sm | https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt |
| SecLists - combined_directories / combined_words / web-extensions-big | combined_directories ~1.15MB; combined_words ~1.15MB; web-ex | https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/combined_directories.txt |
| Assetnote - httparchive_directories_1m (automated, MONTHLY) | 696,827 lines (19.2MB) as of 2026-08-27 snapshot | https://wordlists-cdn.assetnote.io/data/automated/httparchive_directories_1m_2026_08_27.txt |
| Assetnote - httparchive_apiroutes (automated) | 403,119 lines (11.5MB) | https://wordlists-cdn.assetnote.io/data/automated/httparchive_apiroutes_2026_08_27.txt |
| Assetnote - manual BigQuery corpora (wordlist_with/no_underscores) | wordlist_no_underscores 1,916,730 lines (25.5MB); wordlist_w | https://wordlists-cdn.assetnote.io/data/manual/wordlist_no_underscores.txt |
| Assetnote - CDN index + bulk mirror (operational) | automated.json (12 lists), manual.json, kiterunner.json, tec | https://wordlists-cdn.assetnote.io/data/automated.json |
| Bo0oM/fuzz.txt (curated high-signal) | ~4.8k lines (79KB) | https://raw.githubusercontent.com/Bo0oM/fuzz.txt/master/fuzz.txt |
| dirsearch - db/dicc.txt (default list, %EXT% templated) | ~11k entries (143KB) | https://raw.githubusercontent.com/maurosoria/dirsearch/master/db/dicc.txt |
| OneListForAll (six2dez) - aggregate | onelistforallmicro ~45k lines (559KB, curated); onelistforal | https://raw.githubusercontent.com/six2dez/OneListForAll/main/onelistforallmicro.txt |
| trickest/wordlists (supplementary) | inventory/parameters.txt 156KB (params); inventory/subdomain | https://raw.githubusercontent.com/trickest/wordlists/main/inventory/parameters.txt |
| PayloadsAllTheThings (NOT a directory corpus) | n/a - payload/reference repo, no bulk directory wordlist | https://github.com/swisskyrepo/PayloadsAllTheThings |

> **Research notes:** TIERING (real corpora, deduped, no leading slash). T1 ~200k 'fast': union of the curated seed_lines + SecLists quickhits.txt + Bo0oM fuzz.txt + dirsearch dicc.txt(%EXT% expanded) + common.txt + raft-large-{directories,files,words} (mixed-case). After casefold-dedup that lands ~170-200k; top up to 200k with DirBuster medium (which alone is 220,560 - a clean single-source T1 fallback). T2 ~1M 'deep': T1 UNION assetnote httparchive_directories_1m (696,827, resolve current dated file via automated.json) UNION DirBuster-2007_directory-list-2.3-medium (220,560) UNION big.txt/combined_directories -> dedup ~0.9-1.0M. T3 ~3M 'full': T2 UNION DirBuster-2007_directory-list-2.3-big (1,273,833) UNION assetnote wordlist_no_underscores (1.9M) [optionally wordlist_with_underscores 2.67M / OneListForAll onelistforallshort 2.5M] -> dedup ~3M real. REAL vs PERMUTATION: the counts above are REAL union lines

## Licence & ethics

These are public, factual discovery wordlists (SecLists — MIT; Assetnote — public
research corpora; fuzzdb — Apache/CC; OneListForAll, random-robbie, dirsearch, Bo0oM,
nikto — their respective OSS licences). They are redistributed/regenerated here for
**authorized** security testing only, as SecLists and similar projects do. Use solely
against systems you are permitted to test. No target data is included; nothing here is
secret.
