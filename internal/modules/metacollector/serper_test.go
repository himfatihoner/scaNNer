package metacollector

import (
	"errors"
	"testing"
)

func mkResults(urls ...string) []searchResult {
	out := make([]searchResult, 0, len(urls))
	for _, u := range urls {
		out = append(out, searchResult{URL: u})
	}
	return out
}

func TestPaginateShortPageStops(t *testing.T) {
	calls := 0
	out, err := paginateWith(300, 10, func(page int) ([]searchResult, error) {
		calls++
		return mkResults("a", "b", "c"), nil // short page (< 10)
	})
	if err != nil || len(out) != 3 || calls != 1 {
		t.Fatalf("short page: out=%d calls=%d err=%v", len(out), calls, err)
	}
}

func TestPaginateEmptyPageStops(t *testing.T) {
	out, _ := paginateWith(300, 10, func(page int) ([]searchResult, error) { return nil, nil })
	if len(out) != 0 {
		t.Fatalf("empty page: out=%d", len(out))
	}
}

func TestPaginateNoNewStops(t *testing.T) {
	calls := 0
	out, _ := paginateWith(300, 2, func(page int) ([]searchResult, error) {
		calls++
		return mkResults("u1", "u2"), nil // full page, but always the same URLs
	})
	if len(out) != 2 || calls != 2 { // page1 adds 2, page2 adds 0 new → stop
		t.Fatalf("no-new: out=%d calls=%d", len(out), calls)
	}
}

func TestPaginateCap(t *testing.T) {
	out, _ := paginateWith(2, 10, func(page int) ([]searchResult, error) {
		// full, always-fresh pages
		base := page * 10
		return mkResults(itoaURL(base), itoaURL(base+1), itoaURL(base+2), itoaURL(base+3), itoaURL(base+4),
			itoaURL(base+5), itoaURL(base+6), itoaURL(base+7), itoaURL(base+8), itoaURL(base+9)), nil
	})
	if len(out) != 2 {
		t.Fatalf("cap: out=%d, want 2", len(out))
	}
}

func TestPaginateErrorReturnsCollected(t *testing.T) {
	out, err := paginateWith(300, 2, func(page int) ([]searchResult, error) {
		if page == 1 {
			return mkResults("a", "b"), nil
		}
		return nil, errors.New("boom")
	})
	if err == nil || len(out) != 2 {
		t.Fatalf("error path: out=%d err=%v", len(out), err)
	}
}

func itoaURL(n int) string { return "https://x/" + string(rune('A'+n%26)) + "-" + itoa(n) }
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	if neg {
		b = append([]byte{'-'}, b...)
	}
	return string(b)
}

func TestClassifyHTTPError(t *testing.T) {
	if s, ok := classifyHTTPError(400, []byte(`{"message":"Not enough credits"}`)).(*serperStop); !ok || s.Kind != stopCredits {
		t.Errorf("credits not classified: %v", classifyHTTPError(400, []byte(`{"message":"Not enough credits"}`)))
	}
	if s, ok := classifyHTTPError(401, []byte(`{"message":"unauthorized"}`)).(*serperStop); !ok || s.Kind != stopAuth {
		t.Errorf("auth (401) not classified")
	}
	if s, ok := classifyHTTPError(403, []byte(`{}`)).(*serperStop); !ok || s.Kind != stopAuth {
		t.Errorf("auth (403) not classified")
	}
	if s, ok := classifyHTTPError(400, []byte(`{"message":"bad query"}`)).(*serperStop); !ok || s.Kind != stopBadRequest {
		t.Errorf("badrequest not classified")
	}
	// 429 and 5xx are retryable → NOT a *serperStop.
	if _, ok := classifyHTTPError(429, []byte(`{}`)).(*serperStop); ok {
		t.Errorf("429 should be retryable, not a stop")
	}
	if _, ok := classifyHTTPError(503, []byte(`{}`)).(*serperStop); ok {
		t.Errorf("503 should be retryable, not a stop")
	}
}

func TestRetryableStatus(t *testing.T) {
	for _, s := range []int{429, 500, 502, 503} {
		if !retryableStatus(s) {
			t.Errorf("status %d should be retryable", s)
		}
	}
	for _, s := range []int{400, 401, 403, 404} {
		if retryableStatus(s) {
			t.Errorf("status %d should NOT be retryable", s)
		}
	}
}
