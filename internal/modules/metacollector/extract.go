package metacollector

import (
	"archive/zip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode"

	"scanner/internal/modules/shared"
)

// Faithful port of meta-collector/metacollector/extractor.py. Exact-suffix tag
// classification into FOCA categories + regex harvest of emails/paths/servers
// over every tag value and (for email/server) document body text.

// zipOffice/legacyOffice route body-text extraction (OOXML/ODF zip vs OLE2).
var zipOffice = map[string]bool{"docx": true, "xlsx": true, "pptx": true, "odt": true, "ods": true, "odp": true, "odg": true, "sxw": true}
var legacyOffice = map[string]bool{"doc": true, "xls": true, "ppt": true, "pps": true}

// Exact-suffix (last ':'-segment, lowercased) → category tag sets.
var userTags = set("author", "lastmodifiedby", "lastsavedby", "last-author", "lastauthor",
	"initial-creator", "initialcreator", "artist", "xpauthor", "ownername", "cameraownername")
var softwareTags = set("producer", "creatortool", "application", "appversion", "software", "generator")
var companyTags = set("company")
var osTags = set("operatingsystem", "platform", "hostcomputer")
var dateTags = set("createdate", "modifydate", "creationdate", "moddate", "metadatadate",
	"lastprinted", "printdate", "creation-date", "print-date")
var gpsTags = set("gpslatitude", "gpslongitude", "gpsaltitude", "gpsposition", "gpscoordinates")
var pathTags = set("template", "hyperlinkbase")
var printerTags = set("printername")

// softwareCreatorGroups: a bare 'creator' tag in these group1 prefixes is the
// generating tool (software), otherwise a human (user).
var softwareCreatorGroups = []string{"pdf", "xmp-pdf", "xmp-xmp"}

func set(items ...string) map[string]bool {
	m := make(map[string]bool, len(items))
	for _, s := range items {
		m[s] = true
	}
	return m
}

var (
	tmRe           = regexp.MustCompile(`[®™©]`)
	dateRe         = regexp.MustCompile(`^(\d{4}):(\d{2}):(\d{2})[ T](\d{2}:\d{2}:\d{2})(.*)$`)
	softwareHintRe = regexp.MustCompile(`(?i)\d+\.\d+|crystal report|crystal decision|acrobat|pdfmaker|ghostscript|distiller|pscript|powerpoint|openpdf|itext|pdffactory|ilovepdf|microsoft|libreoffice|openoffice|quartz|skia|chromium|foxit|nitro|primopdf|tcpdf|reportlab|\bword\b|\bexcel\b|adobe|scansnap|scanner`)
	emailRe        = regexp.MustCompile(`[A-Za-z0-9][A-Za-z0-9._%+-]*@[A-Za-z0-9.-]+\.[A-Za-z]{2,}`)
	pathRe         = regexp.MustCompile(`(?:[A-Za-z]:\\[^\s"<>|]+|\\\\[^\s"<>|]+)`)
	uncRe          = regexp.MustCompile(`\\\\([A-Za-z0-9][A-Za-z0-9._-]{1,62})\\[^\s\\"<>|]`)
	serverRe       = regexp.MustCompile(`^\s*\\\\([A-Za-z0-9][A-Za-z0-9._-]{1,62})\\`)
)

const okChars = "._@:/\\+-()&,;'\"%#=[]{}!?"

// rawFinding is a (category, value, tag) triple before the document URL is stamped.
type rawFinding struct {
	cat, value, tag string
}

// clean mirrors _clean: strip ®™©, reject control/replacement chars, reject
// mostly-symbol noise (len>=4 and <55% "ok" chars).
func clean(v string) string {
	v = strings.TrimSpace(tmRe.ReplaceAllString(v, ""))
	if v == "" {
		return ""
	}
	if strings.ContainsRune(v, '\uFFFD') {
		return ""
	}
	n, ok := 0, 0
	for _, c := range v {
		if c < 0x20 && c != '\t' {
			return ""
		}
		n++
		if unicode.IsLetter(c) || unicode.IsDigit(c) || unicode.IsSpace(c) || strings.ContainsRune(okChars, c) {
			ok++
		}
	}
	if n >= 4 && float64(ok)/float64(n) < 0.55 {
		return ""
	}
	return v
}

// normDate mirrors _norm_date: exiftool date → ISO 8601; zeroed → drop; non-date → clean.
func normDate(v string) (string, bool) {
	m := dateRe.FindStringSubmatch(strings.TrimSpace(v))
	if m == nil {
		c := clean(v)
		return c, c != ""
	}
	y, mo, d, t, tz := m[1], m[2], m[3], m[4], m[5]
	if y == "0000" || mo == "00" || d == "00" {
		return "", false
	}
	return y + "-" + mo + "-" + d + "T" + t + strings.TrimSpace(tz), true
}

// serverFrom mirrors _server_from: hostname from a value that STARTS with \\host\.
func serverFrom(v string) string {
	if m := serverRe.FindStringSubmatch(v); m != nil {
		return m[1]
	}
	return ""
}

// looksPath mirrors _looks_path.
func looksPath(v string) bool {
	return strings.Contains(v, "\\") || strings.Contains(v, "/") || strings.Contains(v, ":") || strings.Contains(strings.ToLower(v), "%5c")
}

// classify mirrors _classify's exact precedence.
func classify(grp, suffix string) string {
	g := strings.ToLower(grp)
	switch {
	case softwareTags[suffix]:
		return "software"
	case userTags[suffix]:
		return "user"
	case suffix == "creator":
		for _, p := range softwareCreatorGroups {
			if strings.HasPrefix(g, p) {
				return "software"
			}
		}
		return "user"
	case companyTags[suffix]:
		return "company"
	case pathTags[suffix]:
		return "path"
	case osTags[suffix]:
		return "os"
	case dateTags[suffix]:
		return "date"
	case printerTags[suffix]:
		return "printer"
	case gpsTags[suffix]:
		return "gps"
	}
	return ""
}

// categorize mirrors _categorize: classify the tag value (+ software-hint
// override + path gate), then regex-harvest email/path/server over the raw and
// percent-decoded value. Returns findings tagged with the source tag.
func categorize(grp, tag, value string) []rawFinding {
	var out []rawFinding
	suffix := tag
	if i := strings.LastIndex(tag, ":"); i >= 0 {
		suffix = tag[i+1:]
	}
	suffix = strings.ToLower(suffix)
	if cat := classify(grp, suffix); cat != "" {
		var nv string
		keep := true
		if cat == "date" {
			nv, keep = normDate(value)
		} else {
			nv = clean(value)
			keep = nv != ""
		}
		if keep && nv != "" {
			if cat == "user" && softwareHintRe.MatchString(nv) {
				cat = "software"
			}
			if !(cat == "path" && !looksPath(nv)) {
				out = append(out, rawFinding{cat, nv, tag})
			}
		}
	}
	candidates := []string{value}
	if dec, err := percentDecode(value); err == nil && dec != value {
		candidates = append(candidates, dec)
	}
	for _, v := range candidates {
		for _, m := range emailRe.FindAllString(v, -1) {
			out = append(out, rawFinding{"email", strings.ToLower(m), tag})
		}
		for _, m := range pathRe.FindAllString(v, -1) {
			if cm := clean(m); cm != "" {
				out = append(out, rawFinding{"path", cm, tag})
			}
		}
		if srv := serverFrom(v); srv != "" {
			out = append(out, rawFinding{"server", srv, tag})
		}
	}
	return out
}

// emitBody mirrors _emit_body: body text yields only emails + servers (\\host\share).
func emitBody(text string) []rawFinding {
	if text == "" {
		return nil
	}
	var out []rawFinding
	seenE := map[string]bool{}
	for _, m := range emailRe.FindAllString(text, -1) {
		lm := strings.ToLower(m)
		if !seenE[lm] {
			seenE[lm] = true
			out = append(out, rawFinding{"email", lm, "Body"})
		}
	}
	seenS := map[string]bool{}
	for _, m := range uncRe.FindAllStringSubmatch(text, -1) {
		h := m[1]
		if !seenS[h] {
			seenS[h] = true
			out = append(out, rawFinding{"server", h, "Body"})
		}
	}
	return out
}

// runExiftool invokes exiftool over a batch of paths and returns the parsed
// JSON array (empty on any failure — exit code is not checked, matching the
// reference which only trusts a '['-prefixed stdout).
func runExiftool(ctx context.Context, exiftoolPath string, paths []string) []map[string]interface{} {
	if len(paths) == 0 || exiftoolPath == "" {
		return nil
	}
	args := append([]string{"-json", "-G1", "-a", "-ee", "-charset", "filename=UTF8", "-api", "largefilesupport=1"}, paths...)
	out, _ := shared.Command(ctx, exiftoolPath, args...).Output()
	txt := strings.TrimSpace(string(out))
	if !strings.HasPrefix(txt, "[") {
		return nil
	}
	var arr []map[string]interface{}
	if json.Unmarshal([]byte(txt), &arr) != nil {
		return nil
	}
	return arr
}

// extractAll runs exiftool (batched 150) + body-text harvest over the
// downloaded docs and returns the deduped classified findings. onExtract is
// called once per doc processed in the body phase (progress accounting).
func extractAll(ctx context.Context, cfg Config, docs []*Document, tmp string, tl tools, onExtract func()) []Finding {
	downloaded := make([]*Document, 0, len(docs))
	byPath := map[string]*Document{}
	var paths []string
	for _, d := range docs {
		if d.Status == "downloaded" && d.LocalPath != "" {
			downloaded = append(downloaded, d)
			if _, ok := byPath[d.LocalPath]; !ok {
				paths = append(paths, d.LocalPath)
			}
			byPath[d.LocalPath] = d // last writer wins for a shared sha path (matches reference)
		}
	}
	if len(downloaded) == 0 {
		return nil
	}

	var findings []Finding
	seen := map[string]bool{}
	add := func(docURL string, rf rawFinding) {
		key := rf.cat + "\x00" + rf.value + "\x00" + rf.tag + "\x00" + docURL
		if seen[key] {
			return
		}
		seen[key] = true
		findings = append(findings, Finding{Category: rf.cat, Value: rf.value, Tag: rf.tag, DocURL: docURL})
	}

	// 1) exiftool metadata, batched.
	if tl.exiftool != "" {
		const batch = 150
		for i := 0; i < len(paths); i += batch {
			if ctx.Err() != nil {
				break
			}
			end := i + batch
			if end > len(paths) {
				end = len(paths)
			}
			for _, entry := range runExiftool(ctx, tl.exiftool, paths[i:end]) {
				src, _ := entry["SourceFile"].(string)
				row := byPath[src]
				if row == nil {
					row = byPath[strings.ReplaceAll(src, "/", "\\")]
				}
				if row == nil {
					continue
				}
				keys := make([]string, 0, len(entry))
				for k := range entry {
					keys = append(keys, k)
				}
				sort.Strings(keys) // deterministic order (Python keeps dict/insertion order)
				for _, tag := range keys {
					if tag == "SourceFile" {
						continue
					}
					sval := stringifyValue(entry[tag])
					if sval == "" {
						continue
					}
					grp := ""
					if j := strings.Index(tag, ":"); j >= 0 {
						grp = tag[:j]
					}
					for _, rf := range categorize(grp, tag, sval) {
						add(row.URL, rf)
					}
				}
			}
		}
	}

	// 2) body text — batch legacy OLE via one soffice call, then scan every doc.
	legacyText := map[string]string{}
	if cfg.ScanBody && tl.soffice != "" {
		var legacy []string
		for _, d := range downloaded {
			if legacyOffice[strings.ToLower(d.Filetype)] {
				legacy = append(legacy, d.LocalPath)
			}
		}
		if len(legacy) > 0 {
			legacyText = legacyTextMap(ctx, tl.soffice, legacy, tmp)
		}
	}
	for _, d := range downloaded {
		if ctx.Err() != nil {
			break
		}
		if cfg.ScanBody {
			for _, rf := range emitBody(bodyText(ctx, d.LocalPath, d.Filetype, tl, legacyText)) {
				add(d.URL, rf)
			}
		}
		d.Status = "extracted"
		if onExtract != nil {
			onExtract()
		}
	}
	return findings
}

// bodyText mirrors _body_text: pdf→pdftotext, zip-office→XML, rtf→raw, legacy→soffice output.
func bodyText(ctx context.Context, path, filetype string, tl tools, legacyText map[string]string) string {
	ft := strings.ToLower(filetype)
	pl := strings.ToLower(path)
	if (ft == "pdf" || strings.HasSuffix(pl, ".pdf")) && tl.pdftotext != "" {
		out, err := shared.Command(ctx, tl.pdftotext, "-q", path, "-").Output()
		if err != nil {
			return ""
		}
		return string(out)
	}
	if zipOffice[ft] || hasZipOfficeSuffix(pl) {
		return zipText(path)
	}
	if ft == "rtf" || strings.HasSuffix(pl, ".rtf") {
		b, err := os.ReadFile(path)
		if err != nil {
			return ""
		}
		return string(b)
	}
	if t, ok := legacyText[path]; ok {
		return t
	}
	return ""
}

func hasZipOfficeSuffix(pl string) bool {
	for ext := range zipOffice {
		if strings.HasSuffix(pl, "."+ext) {
			return true
		}
	}
	return false
}

// zipText mirrors _zip_text: concat every .xml/.rels entry in an OOXML/ODF zip.
func zipText(path string) string {
	zr, err := zip.OpenReader(path)
	if err != nil {
		return ""
	}
	defer zr.Close()
	var parts []string
	for _, f := range zr.File {
		if strings.HasSuffix(f.Name, ".xml") || strings.HasSuffix(f.Name, ".rels") {
			rc, err := f.Open()
			if err != nil {
				continue
			}
			b, _ := io.ReadAll(io.LimitReader(rc, 32<<20)) // guard a zip-bomb entry
			rc.Close()
			parts = append(parts, string(b))
		}
	}
	return strings.Join(parts, "\n")
}

// legacyTextMap mirrors _legacy_text_map: ONE soffice call converts all legacy
// OLE files to .txt; returns path→text.
func legacyTextMap(ctx context.Context, sofficePath string, paths []string, tmp string) map[string]string {
	if len(paths) == 0 {
		return map[string]string{}
	}
	outdir := filepath.Join(tmp, "soffice-out")
	if err := os.MkdirAll(outdir, 0o755); err != nil {
		return map[string]string{}
	}
	prof := filepath.Join(tmp, "soffice-prof")
	args := append([]string{"--headless", "--norestore",
		"-env:UserInstallation=file://" + prof,
		"--convert-to", "txt:Text", "--outdir", outdir}, paths...)
	_ = shared.Command(ctx, sofficePath, args...).Run()
	out := map[string]string{}
	for _, p := range paths {
		stem := strings.TrimSuffix(filepath.Base(p), filepath.Ext(p))
		txt := filepath.Join(outdir, stem+".txt")
		if b, err := os.ReadFile(txt); err == nil {
			out[p] = string(b)
		}
	}
	return out
}

// stringifyValue renders an exiftool JSON value as a string. Slices join with
// ", " (richer than Python's list-repr, so emails in multi-valued tags are
// still harvested — a deliberate, documented divergence).
func stringifyValue(v interface{}) string {
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		return x
	case bool:
		if x {
			return "true"
		}
		return "false"
	case float64:
		if x == math.Trunc(x) && !math.IsInf(x, 0) && math.Abs(x) < 1e15 {
			return strconv.FormatInt(int64(x), 10)
		}
		return strconv.FormatFloat(x, 'f', -1, 64)
	case []interface{}:
		parts := make([]string, 0, len(x))
		for _, e := range x {
			if s := stringifyValue(e); s != "" {
				parts = append(parts, s)
			}
		}
		return strings.Join(parts, ", ")
	default:
		return fmt.Sprintf("%v", x)
	}
}

// percentDecode mirrors Python urllib.parse.unquote (percent-decode only; '+'
// is left intact, unlike query unescaping).
func percentDecode(s string) (string, error) {
	return url.PathUnescape(s)
}

// toolResolve reports the usable binary path for each external tool ("" = absent).
type tools struct {
	exiftool  string
	pdftotext string
	soffice   string
}

func resolveTools() tools {
	look := func(name string) string {
		if p, err := exec.LookPath(name); err == nil {
			return p
		}
		return ""
	}
	return tools{exiftool: look("exiftool"), pdftotext: look("pdftotext"), soffice: look("soffice")}
}
