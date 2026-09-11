// Package i18n is scaNNer's translation layer. It uses gettext-style keys: the
// message id IS the English source string. English renders the key verbatim
// (identity); other languages look the key up in a catalog loaded from
// web/i18n/<lang>.json (English → translation), falling back to the English key
// when a translation is missing. So the English text in templates/Go is always
// the source of truth, and a missing translation degrades gracefully to English.
//
// Loading is fail-open: a missing or malformed catalog logs and leaves that
// language empty (→ English), never a fatal error.
package i18n

import (
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"os"
	"path/filepath"
	"sync"
)

// Supported language codes.
const (
	LangEN = "en"
	LangTR = "tr"
)

var (
	mu       sync.RWMutex
	catalogs = map[string]map[string]string{} // lang -> msgid -> translation
)

// Langs returns the supported language codes (English first / default).
func Langs() []string { return []string{LangEN, LangTR} }

// Normalize maps an arbitrary code to a supported language, defaulting to
// English. Use this at every cookie/DB read so an unknown value can never
// select a non-existent template tree.
func Normalize(lang string) string {
	if lang == LangTR {
		return LangTR
	}
	return LangEN
}

// Load (re)reads translation catalogs from dir (web/i18n/<lang>.json). English
// is identity and has no file. Fail-open per package doc.
func Load(dir string) {
	next := map[string]map[string]string{}
	for _, lang := range Langs() {
		if lang == LangEN {
			continue // identity — no catalog file
		}
		path := filepath.Join(dir, lang+".json")
		b, err := os.ReadFile(path)
		if err != nil {
			log.Printf("i18n: no catalog for %q (%v) — that language falls back to English", lang, err)
			continue
		}
		m := map[string]string{}
		if err := json.Unmarshal(b, &m); err != nil {
			log.Printf("i18n: catalog %s is malformed (%v) — that language falls back to English", path, err)
			continue
		}
		next[lang] = m
		log.Printf("i18n: loaded %d translations for %q", len(m), lang)
	}
	mu.Lock()
	catalogs = next
	mu.Unlock()
}

// lookup returns the translation of msgid in lang, or msgid itself when the
// language is English, the catalog is absent, or the key is missing/empty.
func lookup(lang, msgid string) string {
	if lang == LangEN {
		return msgid
	}
	mu.RLock()
	m := catalogs[lang]
	mu.RUnlock()
	if m != nil {
		if v, ok := m[msgid]; ok && v != "" {
			return v
		}
	}
	return msgid
}

// T translates msgid into lang. With args, the translated string is used as a
// fmt.Sprintf format (msgids use %s/%d and escape literal percents as %%). With
// NO args it is returned verbatim, so a bare '%' in a translation is always safe.
func T(lang, msgid string, args ...interface{}) string {
	s := lookup(lang, msgid)
	if len(args) == 0 {
		return s
	}
	return fmt.Sprintf(s, args...)
}

// Thtml is T for msgids that intentionally contain markup. Its args MUST be
// pre-escaped or absent — never pass raw user/scan data through a %s here or you
// reintroduce XSS.
func Thtml(lang, msgid string, args ...interface{}) template.HTML {
	return template.HTML(T(lang, msgid, args...))
}

// Tn picks the English singular or plural msgid by n, then translates. Both
// English forms should map to the (single) Turkish form in the catalog, since
// Turkish does not pluralize a noun after a numeral.
func Tn(lang string, n int, singular, plural string, args ...interface{}) string {
	if n == 1 {
		return T(lang, singular, args...)
	}
	return T(lang, plural, args...)
}
