package metacollector

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"scanner/internal/modules/shared"
)

// perDownloadTimeout bounds a single document fetch so a slow-but-alive body
// can't hang a worker forever (the scan ctx still aborts it earlier on cancel).
const perDownloadTimeout = 5 * time.Minute

var safeNameRe = regexp.MustCompile(`[^a-zA-Z0-9._-]`)

// safeName mirrors meta-collector's _safe: non [A-Za-z0-9._-] → '_', max 200.
func safeName(s string) string {
	s = safeNameRe.ReplaceAllString(s, "_")
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}

// downloadClient builds an http.Client that FOLLOWS redirects (unlike
// HTTPOptions.NewHTTPClient) and has no total timeout, so large documents
// stream fully; the per-request context + ResponseHeaderTimeout bound it.
func downloadClient(opts *shared.HTTPOptions) *http.Client {
	tr := &http.Transport{
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
		DialContext:           shared.BoundDialer(opts, 15*time.Second).DialContext,
		MaxIdleConns:          50,
		MaxIdleConnsPerHost:   10,
		IdleConnTimeout:       30 * time.Second,
		ResponseHeaderTimeout: 60 * time.Second,
	}
	if opts != nil {
		opts.ApplyTransport(tr) // proxy + register for idle-pool flush on cancel
	}
	return &http.Client{Transport: tr}
}

// hostSemaphores caps concurrent fetches per FQDN (politeness to the host
// serving the documents), on top of the global worker pool.
type hostSemaphores struct {
	mu    sync.Mutex
	m     map[string]chan struct{}
	limit int
}

func (h *hostSemaphores) get(fqdn string) chan struct{} {
	h.mu.Lock()
	defer h.mu.Unlock()
	s, ok := h.m[fqdn]
	if !ok {
		lim := h.limit
		if lim < 1 {
			lim = 1
		}
		s = make(chan struct{}, lim)
		h.m[fqdn] = s
	}
	return s
}

// downloadAll fetches every doc with status "found" through a bounded worker
// pool. onDone is called once per processed doc (success or failure) for
// progress accounting.
func downloadAll(ctx context.Context, cfg Config, docs []*Document, tmp string, onDone func()) {
	if len(docs) == 0 {
		return
	}
	client := downloadClient(cfg.HTTPOpts)
	maxBytes := int64(cfg.MaxFileMB) * 1024 * 1024
	ua := ""
	if cfg.HTTPOpts != nil {
		ua = cfg.HTTPOpts.PickUserAgent()
	}
	if ua == "" {
		ua = shared.EffectiveGlobalUserAgent()
	}

	workers := cfg.Concurrency
	if workers < 1 {
		workers = 1
	}
	hostSems := &hostSemaphores{m: map[string]chan struct{}{}, limit: cfg.PerHost}
	jobs := make(chan *Document)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for doc := range jobs {
				if ctx.Err() != nil {
					onDone()
					continue
				}
				sem := hostSems.get(doc.FQDN)
				select {
				case sem <- struct{}{}:
				case <-ctx.Done():
					onDone()
					continue
				}
				fetchOne(ctx, client, doc, tmp, maxBytes, ua)
				<-sem
				onDone()
			}
		}()
	}
	for _, d := range docs {
		if ctx.Err() != nil {
			break
		}
		select {
		case jobs <- d:
		case <-ctx.Done():
		}
	}
	close(jobs)
	wg.Wait()
}

// fetchOne downloads one document, streaming to a temp file while hashing, and
// aborts if it exceeds the size cap. On success it sets doc.Status/LocalPath/
// SHA256/Size; otherwise it records failed/skipped + an error.
func fetchOne(parent context.Context, client *http.Client, doc *Document, tmp string, maxBytes int64, ua string) {
	ctx, cancel := context.WithTimeout(parent, perDownloadTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, doc.URL, nil)
	if err != nil {
		doc.Status = "failed"
		doc.Error = truncErr(err.Error())
		return
	}
	req.Header.Set("User-Agent", ua)
	resp, err := client.Do(req)
	if err != nil {
		doc.Status = "failed"
		doc.Error = truncErr(err.Error())
		return
	}
	defer resp.Body.Close()
	doc.HTTPStatus = resp.StatusCode
	if resp.StatusCode != http.StatusOK {
		doc.Status = "failed"
		doc.Error = fmt.Sprintf("HTTP %d", resp.StatusCode)
		return
	}

	dir := filepath.Join(tmp, safeName(doc.FQDN))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		doc.Status = "failed"
		doc.Error = truncErr(err.Error())
		return
	}
	tmpf, err := os.CreateTemp(dir, "dl-*")
	if err != nil {
		doc.Status = "failed"
		doc.Error = truncErr(err.Error())
		return
	}
	tmpName := tmpf.Name()
	h := sha256.New()
	var size int64
	buf := make([]byte, 65536)
	for {
		n, rerr := resp.Body.Read(buf)
		if n > 0 {
			size += int64(n)
			if size > maxBytes {
				tmpf.Close()
				os.Remove(tmpName)
				doc.Status = "skipped"
				doc.Error = "exceeds max_file_mb"
				return
			}
			h.Write(buf[:n])
			if _, werr := tmpf.Write(buf[:n]); werr != nil {
				tmpf.Close()
				os.Remove(tmpName)
				doc.Status = "failed"
				doc.Error = truncErr(werr.Error())
				return
			}
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			tmpf.Close()
			os.Remove(tmpName)
			doc.Status = "failed"
			doc.Error = truncErr(rerr.Error())
			return
		}
	}
	tmpf.Close()
	digest := hex.EncodeToString(h.Sum(nil))
	ext := inferExt(doc.URL, resp.Header.Get("Content-Type"), doc.Filetype)
	final := filepath.Join(dir, digest[:16]+"."+ext)
	// Identical bytes across different URLs collapse to the same on-disk name
	// (rename overwrites), matching meta-collector's sha256-named store.
	if err := os.Rename(tmpName, final); err != nil {
		os.Remove(tmpName)
		doc.Status = "failed"
		doc.Error = truncErr(err.Error())
		return
	}
	doc.Status = "downloaded"
	doc.SHA256 = digest
	doc.Size = size
	doc.LocalPath = final
}

// inferExt mirrors meta-collector's _ext: URL path extension → dork filetype →
// content-type tail → "bin", each lowercased and clamped to 8 chars.
func inferExt(rawURL, contentType, filetype string) string {
	last := ""
	if u, err := url.Parse(rawURL); err == nil {
		p := u.Path
		if dec, derr := url.PathUnescape(p); derr == nil {
			p = dec
		}
		last = p
		if i := strings.LastIndex(p, "/"); i >= 0 {
			last = p[i+1:]
		}
	}
	if strings.Contains(last, ".") {
		return clampExt(strings.ToLower(last[strings.LastIndex(last, ".")+1:]))
	}
	if filetype != "" {
		return clampExt(strings.ToLower(filetype))
	}
	ct := contentType
	if i := strings.Index(ct, "/"); i >= 0 {
		ct = ct[i+1:]
	}
	if i := strings.Index(ct, ";"); i >= 0 {
		ct = ct[:i]
	}
	ct = strings.TrimSpace(ct)
	if ct == "" {
		ct = "bin"
	}
	return clampExt(strings.ToLower(ct))
}

func clampExt(e string) string {
	if len(e) > 8 {
		return e[:8]
	}
	return e
}

func truncErr(s string) string {
	if len(s) > 300 {
		return s[:300]
	}
	return s
}
