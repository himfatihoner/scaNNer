package shared

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"regexp"
	"strings"
)

// secretHeaderRe matches HTTP header lines that carry credentials so
// CaptureRequest can strip them before the raw dump is persisted.
// Audit fixed credential leak in leakscan/wpscan/adpentest results — the
// captured Authorization, X-Api-Key, Cookie, etc. ended up in scans.result
// JSON and got rendered verbatim in the UI.
var secretHeaderRe = regexp.MustCompile(`(?im)^(authorization|proxy-authorization|x-api-key|x-auth-token|api-key|cookie|set-cookie|x-amz-security-token|x-vault-token|x-csrf-token):\s*.*$`)

// redactSecretHeaders rewrites Authorization / Cookie / API-key header
// lines in a raw HTTP dump so the value never lands on disk.
func redactSecretHeaders(dump string) string {
	return secretHeaderRe.ReplaceAllStringFunc(dump, func(line string) string {
		if i := strings.Index(line, ":"); i > 0 {
			return line[:i] + ": [REDACTED]"
		}
		return line
	})
}

// RedactSecretHeaders is the exported entry point for modules that build
// their own raw HTTP dumps (e.g. via httputil.DumpRequestOut, which keeps
// the on-the-wire form) and need to strip Authorization / Cookie / API-key
// values before persisting the dump into scan results.
func RedactSecretHeaders(dump string) string {
	return redactSecretHeaders(dump)
}

// CapturedExchange holds the on-the-wire form of an HTTP request +
// response pair. Modules use it to attach to findings so a pentester
// can paste it straight into Burp Repeater / mitmproxy / curl.
type CapturedExchange struct {
	Method      string `json:"method,omitempty"`
	URL         string `json:"url,omitempty"`
	StatusCode  int    `json:"status_code,omitempty"`
	RawRequest  string `json:"raw_request,omitempty"`
	RawResponse string `json:"raw_response,omitempty"`
}

// MaxRawBody caps a single raw dump at 256 KB. Bigger payloads get
// truncated with a marker — Burp/mitmproxy don't need the rest, and
// SQLite scan rows blow up otherwise.
const MaxRawBody = 256 * 1024

// CaptureRequest renders an *http.Request as the bytes that would
// actually leave the wire. Body is buffered so the caller can still
// fire the request after capturing.
func CaptureRequest(req *http.Request) string {
	if req == nil {
		return ""
	}
	// httputil handles Host, headers, query string ordering correctly.
	// DumpRequestOut would route through the transport (we want the
	// pre-flight form). DumpRequest with body=true reads + restores body.
	dump, err := httputil.DumpRequest(req, true)
	if err != nil {
		return fmt.Sprintf("# capture failed: %v", err)
	}
	return truncRaw(redactSecretHeaders(string(dump)))
}

// CaptureRequestBytes returns the same dump but writes it into a
// pre-allocated buffer so callers that already have one avoid the
// extra alloc.
func CaptureRequestBytes(req *http.Request) []byte {
	if req == nil {
		return nil
	}
	dump, err := httputil.DumpRequest(req, true)
	if err != nil {
		return []byte(fmt.Sprintf("# capture failed: %v", err))
	}
	dump = []byte(redactSecretHeaders(string(dump)))
	if len(dump) > MaxRawBody {
		dump = append(dump[:MaxRawBody], []byte(fmt.Sprintf("\n... [truncated %d bytes]", len(dump)-MaxRawBody))...)
	}
	return dump
}

// CaptureResponse renders an *http.Response as the bytes the server
// returned (response line + headers + body). Reads body into the dump
// and then restores it on resp.Body so the caller can still consume.
func CaptureResponse(resp *http.Response) string {
	if resp == nil {
		return ""
	}
	// Read the body into memory so we can put it back AND emit it.
	var bodyBuf bytes.Buffer
	_, err := io.Copy(&bodyBuf, io.LimitReader(resp.Body, MaxRawBody+1))
	resp.Body.Close()
	bodyBytes := bodyBuf.Bytes()
	truncated := false
	if len(bodyBytes) > MaxRawBody {
		bodyBytes = bodyBytes[:MaxRawBody]
		truncated = true
	}
	// Restore body for downstream consumers.
	resp.Body = io.NopCloser(bytes.NewReader(bodyBytes))

	var b strings.Builder
	b.WriteString(fmt.Sprintf("HTTP/%d.%d %d %s\r\n",
		resp.ProtoMajor, resp.ProtoMinor, resp.StatusCode, http.StatusText(resp.StatusCode)))
	// Stable header order helps diff tools — sort by key.
	keys := make([]string, 0, len(resp.Header))
	for k := range resp.Header {
		keys = append(keys, k)
	}
	// stdlib bufio.NewWriter to keep stable formatting
	w := bufio.NewWriter(&b)
	for _, k := range keys {
		for _, v := range resp.Header[k] {
			fmt.Fprintf(w, "%s: %s\r\n", k, v)
		}
	}
	w.WriteString("\r\n")
	w.Write(bodyBytes)
	if truncated {
		fmt.Fprintf(w, "\n... [truncated, original >256 KB]")
	}
	_ = err
	w.Flush()
	return truncRaw(redactSecretHeaders(b.String()))
}

func truncRaw(s string) string {
	if len(s) <= MaxRawBody {
		return s
	}
	return s[:MaxRawBody] + fmt.Sprintf("\n... [truncated %d bytes]", len(s)-MaxRawBody)
}
