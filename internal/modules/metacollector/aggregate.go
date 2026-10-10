package metacollector

import (
	"net/url"
	"sort"
	"strconv"
	"strings"
)

// Aggregation views computed from the flat Finding list (the single source of
// truth), mirroring meta-collector/metacollector/aggregate.py + pdfreport.py's
// _collect. Dedup/count semantics: a value's weight is the number of DISTINCT
// documents it appears in.

// CategoryOrder is _CAT_ORDER from pdfreport.py (drives appendix + category pie).
var CategoryOrder = []string{"user", "email", "software", "company", "path", "server", "os", "printer", "gps", "date"}

// AllCategories is aggregate.py's CATEGORIES (summary/JSON order).
var AllCategories = []string{"user", "software", "os", "printer", "path", "email", "server", "company", "date", "gps"}

// ValCount is one (value, distinct-document-count) pair.
type ValCount struct {
	Value string `json:"value"`
	Docs  int    `json:"docs"`
}

// Aggregator indexes findings + documents for the report/UI queries.
type Aggregator struct {
	docByURL   map[string]Document
	catValDocs map[string]map[string]map[string]bool // category -> value -> set(docURL)
	docCatVals map[string]map[string][]string        // docURL -> category -> ordered-unique values
	docSeen    map[string]map[string]map[string]bool  // docURL -> category -> set(value)
	docOrder   []string                               // docURLs with >=1 finding, first-seen order
}

// NewAggregator builds the indexes.
func NewAggregator(findings []Finding, docs []Document) *Aggregator {
	a := &Aggregator{
		docByURL:   make(map[string]Document, len(docs)),
		catValDocs: map[string]map[string]map[string]bool{},
		docCatVals: map[string]map[string][]string{},
		docSeen:    map[string]map[string]map[string]bool{},
	}
	for _, d := range docs {
		a.docByURL[d.URL] = d
	}
	docKnown := map[string]bool{}
	for _, f := range findings {
		if a.catValDocs[f.Category] == nil {
			a.catValDocs[f.Category] = map[string]map[string]bool{}
		}
		if a.catValDocs[f.Category][f.Value] == nil {
			a.catValDocs[f.Category][f.Value] = map[string]bool{}
		}
		a.catValDocs[f.Category][f.Value][f.DocURL] = true

		if a.docCatVals[f.DocURL] == nil {
			a.docCatVals[f.DocURL] = map[string][]string{}
			a.docSeen[f.DocURL] = map[string]map[string]bool{}
		}
		if a.docSeen[f.DocURL][f.Category] == nil {
			a.docSeen[f.DocURL][f.Category] = map[string]bool{}
		}
		if !a.docSeen[f.DocURL][f.Category][f.Value] {
			a.docSeen[f.DocURL][f.Category][f.Value] = true
			a.docCatVals[f.DocURL][f.Category] = append(a.docCatVals[f.DocURL][f.Category], f.Value)
		}
		if !docKnown[f.DocURL] {
			docKnown[f.DocURL] = true
			a.docOrder = append(a.docOrder, f.DocURL)
		}
	}
	return a
}

// Cats returns category -> distinct-value count (pdfreport _collect "cats").
func (a *Aggregator) Cats() map[string]int {
	out := map[string]int{}
	for cat, vals := range a.catValDocs {
		out[cat] = len(vals)
	}
	return out
}

// sortValCounts orders by document count desc, then value asc (stable, matching
// pdfreport's `ORDER BY d DESC, value`).
func sortValCounts(vc []ValCount) {
	sort.SliceStable(vc, func(i, j int) bool {
		if vc[i].Docs != vc[j].Docs {
			return vc[i].Docs > vc[j].Docs
		}
		return vc[i].Value < vc[j].Value
	})
}

// Summary returns every distinct value for a category with its distinct-doc
// count, sorted. No cap (matches aggregate.summary).
func (a *Aggregator) Summary(cat string) []ValCount {
	vals := a.catValDocs[cat]
	out := make([]ValCount, 0, len(vals))
	for v, docs := range vals {
		out = append(out, ValCount{Value: v, Docs: len(docs)})
	}
	sortValCounts(out)
	return out
}

// Top returns the top-n values for a category (pdfreport _collect "top", n=60).
func (a *Aggregator) Top(cat string, n int) []ValCount {
	all := a.Summary(cat)
	if n > 0 && len(all) > n {
		all = all[:n]
	}
	return all
}

// Correlation returns, per user value (up to topUsers), the distinct values in
// the given categories co-occurring in the SAME documents, sorted. Mirrors
// pdfreport's corr (cats=software/os/path) and aggregate.by_user (5 cats).
func (a *Aggregator) Correlation(cats []string, topUsers int) [][2]interface{} {
	users := a.Top("user", topUsers)
	out := make([][2]interface{}, 0, len(users))
	for _, u := range users {
		docs := a.catValDocs["user"][u.Value]
		rel := map[string]map[string]bool{}
		for docURL := range docs {
			for _, cat := range cats {
				for _, v := range a.docCatVals[docURL][cat] {
					if rel[cat] == nil {
						rel[cat] = map[string]bool{}
					}
					rel[cat][v] = true
				}
			}
		}
		relSorted := map[string][]string{}
		for cat, vs := range rel {
			list := make([]string, 0, len(vs))
			for v := range vs {
				list = append(list, v)
			}
			sort.Strings(list)
			relSorted[cat] = list
		}
		out = append(out, [2]interface{}{u.Value, relSorted})
	}
	return out
}

// ByDocument returns url -> {filetype, category -> values(first-seen)} for every
// document that has at least one finding (aggregate.by_document).
func (a *Aggregator) ByDocument() map[string]map[string]interface{} {
	out := map[string]map[string]interface{}{}
	for _, docURL := range a.docOrder {
		doc := map[string]interface{}{"filetype": a.docByURL[docURL].Filetype}
		for cat, vals := range a.docCatVals[docURL] {
			doc[cat] = vals
		}
		out[docURL] = doc
	}
	return out
}

// ByValue returns category -> value -> sorted source URLs (aggregate.by_value).
func (a *Aggregator) ByValue() map[string]map[string][]string {
	out := map[string]map[string][]string{}
	for cat, vals := range a.catValDocs {
		out[cat] = map[string][]string{}
		for v, docs := range vals {
			urls := make([]string, 0, len(docs))
			for u := range docs {
				urls = append(urls, u)
			}
			sort.Strings(urls)
			out[cat][v] = urls
		}
	}
	return out
}

// ByUser is the JSON by_user view: user -> category -> sorted values, for the
// five correlated categories (aggregate.correlation_by_user).
func (a *Aggregator) ByUser() map[string]map[string][]string {
	corr := a.Correlation([]string{"software", "os", "path", "printer", "company"}, len(a.catValDocs["user"]))
	out := map[string]map[string][]string{}
	for _, row := range corr {
		user := row[0].(string)
		out[user] = row[1].(map[string][]string)
	}
	return out
}

// SummaryAll is the JSON summary view: every category -> [{value, docs}] sorted.
func (a *Aggregator) SummaryAll() map[string][]ValCount {
	out := map[string][]ValCount{}
	for _, cat := range AllCategories {
		out[cat] = a.Summary(cat)
	}
	return out
}

// Years returns document year -> count from 'date' findings (year in 1990..2035).
func (a *Aggregator) Years() map[string]int {
	years := map[string]int{}
	for v, docs := range a.catValDocs["date"] {
		if len(v) < 4 {
			continue
		}
		y := v[:4]
		n, err := strconv.Atoi(y)
		if err != nil || n < 1990 || n > 2035 {
			continue
		}
		years[y] += len(docs)
	}
	return years
}

// netloc extracts the host[:port] of a URL (for the per-FQDN appendix grouping).
func netloc(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return "?"
	}
	return u.Host
}

// urlPath returns the decoded path(+query) of a URL for appendix display.
func urlPath(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "/"
	}
	p := u.Path
	if dec, derr := url.PathUnescape(p); derr == nil {
		p = dec
	}
	if p == "" {
		p = "/"
	}
	if u.RawQuery != "" {
		q := u.RawQuery
		if dec, derr := url.QueryUnescape(q); derr == nil {
			q = dec
		}
		p += "?" + q
	}
	return p
}

// fqdnOf returns the FQDN label used in the download layout (the host part).
func fqdnOf(rawURL string) string {
	h := netloc(rawURL)
	if i := strings.IndexByte(h, ':'); i >= 0 {
		return h[:i]
	}
	return h
}
