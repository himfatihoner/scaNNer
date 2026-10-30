// Self-contained Tailwind v4 stylesheet compiler for scaNNer.
//
// Why this exists: the app used to ship /static/js/tailwind.js (275 KB) and
// compile utilities in the browser on every page load. That re-download + the
// post-paint restyle ("columns fit for a second, then shift") are gone now that
// the stylesheet is compiled ONCE to web/static/css/app.css and linked statically.
//
// This script reproduces that compile WITHOUT npm or network: it feeds every
// class candidate found in the template + JS SOURCE (all {{if}} branches, not
// just one live DOM) to the SAME engine the app used to run (scripts/
// tailwind-engine.js) via headless chromium, and dumps the generated CSS.
// The result is a strict superset of whatever the per-page JIT ever emitted.
//
//   Usage:  node scripts/build-css.mjs
//   After editing any template or web/static/css/input.css, re-run it.

import fs from 'fs';
import path from 'path';
import os from 'os';
import { execFileSync } from 'child_process';
import { fileURLToPath } from 'url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const ENGINE = path.join(ROOT, 'scripts/tailwind-engine.js');
const INPUT = path.join(ROOT, 'web/static/css/input.css');
const OUT = path.join(ROOT, 'web/static/css/app.css');
const SCAN_DIRS = ['web/templates', 'web/static/js'];
const EXTS = new Set(['.html', '.js']);

for (const p of [ENGINE, INPUT]) {
  if (!fs.existsSync(p)) throw new Error('missing required file: ' + p);
}

const CHROMIUM = ['chromium', 'chromium-browser', 'google-chrome', 'chrome']
  .map(b => { try { return execFileSync('which', [b], { encoding: 'utf8' }).trim(); } catch { return ''; } })
  .find(Boolean);
if (!CHROMIUM) throw new Error('chromium not found on PATH (needed to run the Tailwind engine headless)');

function walk(d, acc) {
  for (const e of fs.readdirSync(d, { withFileTypes: true })) {
    const p = path.join(d, e.name);
    if (e.isDirectory()) walk(p, acc);
    else if (EXTS.has(path.extname(e.name))) acc.push(p);
  }
}
const files = [];
for (const d of SCAN_DIRS) walk(path.join(ROOT, d), files);

// Over-inclusive candidate extraction (mirrors Tailwind's own "scan everything,
// keep the valid" model): split on whitespace/quotes/=<>{} so Go-template {{ }}
// delimiters break cleanly, but KEEP []()/:.%-#!* inside tokens so arbitrary
// values (max-w-[26rem]), variants (hover:, lg:) and opacity (/50) survive.
const tokens = new Set();
for (const f of files) {
  for (const tok of fs.readFileSync(f, 'utf8').split(/[\s"'`=<>{}]+/)) {
    if (tok && tok.length < 120) tokens.add(tok.replace(/"/g, ''));
  }
}
const toks = [...tokens].filter(Boolean);

// Theme source = input.css minus the CLI-only directives the browser engine
// doesn't understand (@import "tailwindcss"; is implicit in the browser build,
// @source is a CLI scanning directive).
const themeBlock = fs.readFileSync(INPUT, 'utf8')
  .split('\n').filter(l => !/^\s*@(import|source)\b/.test(l)).join('\n');

let divs = '';
for (let i = 0; i < toks.length; i += 2000) {
  divs += '<div class="' + toks.slice(i, i + 2000).join(' ') + '"></div>\n';
}

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'scanner-css-'));
const genPath = path.join(tmp, 'gen.html');
fs.writeFileSync(genPath, `<!doctype html><html><head>
<script src="file://${ENGINE}"></script>
<style type="text/tailwindcss">${themeBlock}</style>
</head><body>
${divs}
<pre id="cssout"></pre>
<script>
function gather(){let c='';for(const s of document.styleSheets){try{for(const r of s.cssRules)c+=r.cssText+'\\n';}catch(e){}}for(const s of (document.adoptedStyleSheets||[])){try{for(const r of s.cssRules)c+=r.cssText+'\\n';}catch(e){}}return c;}
let last='',st=0;
function fin(c){document.getElementById('cssout').textContent=btoa(unescape(encodeURIComponent(c)));document.title='DONE';}
const iv=setInterval(()=>{const c=gather();if(c===last&&c.length>2000)st++;else{st=0;last=c;}if(st>=4){clearInterval(iv);fin(c);}},80);
setTimeout(()=>{clearInterval(iv);fin(gather());},11000);
</script>
</body></html>`);

const dump = execFileSync(CHROMIUM, [
  '--headless=new', '--no-sandbox', '--disable-gpu',
  '--virtual-time-budget=20000', '--dump-dom', 'file://' + genPath,
], { encoding: 'utf8', maxBuffer: 128 * 1024 * 1024 });

const m = dump.match(/<pre id="cssout">([\s\S]*?)<\/pre>/);
if (!m) throw new Error('chromium dump had no #cssout — engine failed to run');
const css = Buffer.from(m[1].trim(), 'base64').toString('utf8');
if (css.length < 20000) throw new Error('generated CSS suspiciously small (' + css.length + ' bytes) — aborting');

const header = '/* GENERATED FILE — do not edit by hand.\n'
  + '   Source: web/static/css/input.css + the class usage in web/templates and web/static/js.\n'
  + '   Rebuild: node scripts/build-css.mjs */\n';
fs.writeFileSync(OUT, header + css);
fs.rmSync(tmp, { recursive: true, force: true });
console.log('wrote', OUT, '—', css.length, 'bytes from', files.length, 'files /', toks.length, 'candidates');
