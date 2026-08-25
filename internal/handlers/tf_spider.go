package handlers

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// tf_spider.go — per-target finding parser for the "spider" module.
//
// Result shape (from internal/modules/spider/scanner.go — ScanResult /
// TargetResult / PageForm / PageComment):
//
//	{"results":[{
//	    "url":"https://example.com",
//	    "total_pages":42,"total_dirs":8,"total_files":30,
//	    "resources":[{...}],
//	    "emails":["a@example.com"],
//	    "links":["https://example.com/about"],
//	    "external_links":["https://cdn.other.com/x"],
//	    "js_files":["https://example.com/app.js"],
//	    "images":[...],"videos":[...],"audio":[...],
//	    "forms":[{"found_on":"https://example.com/","action":"https://example.com/login","method":"POST","fields":[...]}],
//	    "comments":[{"found_on":"https://example.com/","text":"TODO remove"}]
//	}]}
//
// Host key is results[].url (urlMatchesAsset). Every spider finding is a recon
// fact (SevRank -1, empty Severity):
//   - emails[]           -> CatEmailRecon (Title = the address)
//   - forms[]            -> CatWebContent (Title = "form @ <action>")
//   - js_files[]/links[] -> CatWebContent (Title = the url)
//   - comments[]         -> CatWebContent (Title = "HTML comment", Detail = text)
//   - a per-crawl summary -> CatWebContent (Title = "Crawled <total_pages> pages")
//
// Each list is capped at 100 rows so a large crawl can't spawn thousands of
// findings. scanID is part of the signature but ignored — the engine wires the
// scan link.
func parseSpiderTarget(resJSON, target string, scanDate time.Time, scanID string, emit func(targetRaw, time.Time)) {
	_ = scanID // engine owns the scan link; parser ignores scanID by contract.

	var res struct {
		Results []struct {
			URL        string   `json:"url"`
			TotalPages int      `json:"total_pages"`
			Emails     []string `json:"emails"`
			Links      []string `json:"links"`
			JSFiles    []string `json:"js_files"`
			Forms      []struct {
				FoundOn string `json:"found_on"`
				Action  string `json:"action"`
				Method  string `json:"method"`
			} `json:"forms"`
			Comments []struct {
				FoundOn string `json:"found_on"`
				Text    string `json:"text"`
			} `json:"comments"`
		} `json:"results"`
	}
	if err := json.Unmarshal([]byte(resJSON), &res); err != nil {
		return
	}

	const maxPerList = 100

	for _, tr := range res.Results {
		if !urlMatchesAsset(tr.URL, target) {
			continue
		}
		seed := strings.TrimSpace(tr.URL)

		// Per-crawl summary.
		emit(targetRaw{
			Module:   "spider",
			Category: CatWebContent,
			Title:    fmt.Sprintf("Crawled %d pages", tr.TotalPages),
			Locus:    seed,
			Severity: "",
			SevRank:  -1,
		}, scanDate)

		// Emails — recon facts.
		for i, e := range tr.Emails {
			if i >= maxPerList {
				break
			}
			e = strings.TrimSpace(e)
			if e == "" {
				continue
			}
			emit(targetRaw{
				Module:   "spider",
				Category: CatEmailRecon,
				Title:    e,
				Locus:    seed,
				Severity: "",
				SevRank:  -1,
			}, scanDate)
		}

		// Forms — attack surface.
		for i, f := range tr.Forms {
			if i >= maxPerList {
				break
			}
			action := strings.TrimSpace(f.Action)
			title := fmt.Sprintf("form @ %s", action)
			if action == "" {
				continue
			}
			locus := strings.TrimSpace(f.FoundOn)
			if locus == "" {
				locus = seed
			}
			detail := strings.TrimSpace(f.Method)
			emit(targetRaw{
				Module:   "spider",
				Category: CatWebContent,
				Title:    title,
				Detail:   detail,
				Locus:    locus,
				Severity: "",
				SevRank:  -1,
			}, scanDate)
		}

		// JS files — referenced scripts.
		for i, j := range tr.JSFiles {
			if i >= maxPerList {
				break
			}
			j = strings.TrimSpace(j)
			if j == "" {
				continue
			}
			emit(targetRaw{
				Module:   "spider",
				Category: CatWebContent,
				Title:    j,
				Locus:    seed,
				Severity: "",
				SevRank:  -1,
			}, scanDate)
		}

		// In-scope links.
		for i, l := range tr.Links {
			if i >= maxPerList {
				break
			}
			l = strings.TrimSpace(l)
			if l == "" {
				continue
			}
			emit(targetRaw{
				Module:   "spider",
				Category: CatWebContent,
				Title:    l,
				Locus:    seed,
				Severity: "",
				SevRank:  -1,
			}, scanDate)
		}

		// HTML comments — frequently leak internal notes.
		for i, cm := range tr.Comments {
			if i >= maxPerList {
				break
			}
			text := strings.TrimSpace(cm.Text)
			if text == "" {
				continue
			}
			locus := strings.TrimSpace(cm.FoundOn)
			if locus == "" {
				locus = seed
			}
			emit(targetRaw{
				Module:   "spider",
				Category: CatWebContent,
				Title:    "HTML comment",
				Detail:   text,
				Locus:    locus,
				Severity: "",
				SevRank:  -1,
			}, scanDate)
		}
	}
}
