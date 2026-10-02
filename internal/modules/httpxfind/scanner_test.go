package httpxfind

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"scanner/internal/modules/shared"
)

// testOpts builds a minimal, cancellable HTTPOptions for the engine.
func testOpts() *shared.HTTPOptions {
	return &shared.HTTPOptions{Ctx: context.Background(), Timeout: 2 * time.Second}
}

// serverPort extracts the numeric port an httptest.Server is listening on.
func serverPort(t *testing.T, ts *httptest.Server) int {
	t.Helper()
	_, portStr, err := net.SplitHostPort(strings.TrimPrefix(ts.URL, "http://"))
	if err != nil {
		t.Fatalf("parse server url %q: %v", ts.URL, err)
	}
	p, _ := strconv.Atoi(portStr)
	return p
}

// freeClosedPort grabs a port, closes it, and returns it — a port that is
// almost certainly refused (nothing listening) for the connect-miss path.
func freeClosedPort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	p := l.Addr().(*net.TCPAddr).Port
	l.Close()
	return p
}

// --- portPermuter ---------------------------------------------------------

// TestPortPermuterEmitsAllPortsOnce proves the O(1)-memory permuter still
// visits every port 1..65535 exactly once (and 0 / 65536 never leak).
func TestPortPermuterEmitsAllPortsOnce(t *testing.T) {
	p := newPortPermuter()
	seen := make([]bool, 65536) // index 1..65535
	count := 0
	for {
		port, ok := p.next()
		if !ok {
			break
		}
		if port < 1 || port > 65535 {
			t.Fatalf("permuter emitted out-of-range port %d", port)
		}
		if seen[port] {
			t.Fatalf("permuter emitted port %d twice", port)
		}
		seen[port] = true
		count++
	}
	if count != 65535 {
		t.Fatalf("permuter emitted %d ports, want 65535", count)
	}
	// next() past exhaustion must keep returning false.
	if _, ok := p.next(); ok {
		t.Fatal("permuter emitted a port past exhaustion")
	}
}

// --- addService caps ------------------------------------------------------

// TestAddServiceCapsCount proves the service-count cap stops retention and
// marks the result truncated.
func TestAddServiceCapsCount(t *testing.T) {
	r := &ScanResult{}
	for i := 0; i < maxServices+100; i++ {
		r.addService(ServiceResult{Host: "h", Port: i})
	}
	if len(r.Services) != maxServices {
		t.Fatalf("retained %d services, want cap %d", len(r.Services), maxServices)
	}
	if !r.Truncated {
		t.Fatal("expected Truncated=true once the count cap bit")
	}
}

// TestAddServiceCapsBytes proves that past the byte budget the heavy fields
// are stripped (metadata retained) and Truncated is set.
func TestAddServiceCapsBytes(t *testing.T) {
	r := &ScanResult{}
	big := strings.Repeat("x", 1<<20) // 1 MB body
	// Push just past the byte cap.
	for i := 0; i < (maxResultBodyBytes/(1<<20))+2; i++ {
		r.addService(ServiceResult{Host: "h", Port: i, ResponseBody: big})
	}
	if !r.Truncated {
		t.Fatal("expected Truncated=true once the byte cap bit")
	}
	// The last retained service must have had its heavy field stripped.
	last := r.Services[len(r.Services)-1]
	if last.ResponseBody != "" {
		t.Fatalf("expected body stripped past the byte cap, got %d bytes", len(last.ResponseBody))
	}
}

// --- engine: finds a live service (single + two-phase) --------------------

func TestScanWithPortsDirectFindsService(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "test-srv")
		fmt.Fprint(w, "<title>hello</title>")
	}))
	defer ts.Close()
	port := serverPort(t, ts)
	closed := freeClosedPort(t)

	// directHTTP=true → single-phase probe.
	res := ScanWithPorts([]string{"127.0.0.1"}, []int{port, closed}, 10, 0, true, testOpts(), nil, nil)
	if n := countPort(res, port); n != 1 {
		t.Fatalf("direct: want the live service on port %d found once, got %d (services=%d)", port, n, len(res.Services))
	}
	if countPort(res, closed) != 0 {
		t.Fatalf("direct: closed port %d should not be reported", closed)
	}
}

func TestScanWithPortsConnectFindsService(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ok")
	}))
	defer ts.Close()
	port := serverPort(t, ts)
	closed := freeClosedPort(t)

	// directHTTP=false → two-phase connect-then-probe.
	res := ScanWithPorts([]string{"127.0.0.1"}, []int{port, closed}, 10, 0, false, testOpts(), nil, nil)
	if n := countPort(res, port); n != 1 {
		t.Fatalf("connect: want the live service on port %d found once, got %d (services=%d)", port, n, len(res.Services))
	}
	if countPort(res, closed) != 0 {
		t.Fatalf("connect: closed port %d should not be reported", closed)
	}
}

func countPort(res *ScanResult, port int) int {
	n := 0
	for _, s := range res.Services {
		if s.Port == port {
			n++
		}
	}
	return n
}

// --- engine: directHTTP flag selects the phase (progress contract) --------

// TestDirectHTTPSelectsPhase proves the directHTTP flag chooses single-phase
// ("Direct HTTP sweep") vs two-phase connect ("Port sweep"/"open port(s)")
// by inspecting the progress message stream.
func TestDirectHTTPSelectsPhase(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer ts.Close()
	port := serverPort(t, ts)

	for _, tc := range []struct {
		name       string
		directHTTP bool
		wantSub    string
		notWant    string
	}{
		{"direct", true, "Direct HTTP sweep", "Port sweep"},
		{"connect", false, "open port(s)", "Direct HTTP sweep"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var mu sync.Mutex
			var msgs []string
			prog := func(done int, msg string) {
				mu.Lock()
				msgs = append(msgs, msg)
				mu.Unlock()
			}
			ScanWithPorts([]string{"127.0.0.1"}, []int{port}, 10, 0, tc.directHTTP, testOpts(), nil, prog)
			joined := strings.Join(msgs, "\n")
			if !strings.Contains(joined, tc.wantSub) {
				t.Fatalf("%s: expected a %q progress line, got:\n%s", tc.name, tc.wantSub, joined)
			}
			if strings.Contains(joined, tc.notWant) {
				t.Fatalf("%s: did not expect %q in the progress stream:\n%s", tc.name, tc.notWant, joined)
			}
		})
	}
}

// --- engine: fixed goroutine count (the whole point of the rewrite) -------

// TestFixedGoroutinePool proves the engine uses a bounded worker pool, not a
// goroutine-per-probe. A custom sweep of ~2000 (mostly closed) ports at
// concurrency 20 must keep the live goroutine delta far below the task count.
func TestFixedGoroutinePool(t *testing.T) {
	// Build a 2000-port custom list that is overwhelmingly closed (one free
	// port reserved as "closed" base; connect-refused is fast on loopback).
	base := freeClosedPort(t)
	ports := make([]int, 0, 2000)
	for i := 0; i < 2000; i++ {
		p := base + i
		if p > 65535 {
			break
		}
		ports = append(ports, p)
	}

	const concurrency = 20
	settle := func() {
		for i := 0; i < 5; i++ {
			runtime.GC()
			time.Sleep(10 * time.Millisecond)
		}
	}
	settle()
	baseline := runtime.NumGoroutine()

	var peak int32
	stop := make(chan struct{})
	var sampWG sync.WaitGroup
	sampWG.Add(1)
	go func() {
		defer sampWG.Done()
		for {
			select {
			case <-stop:
				return
			default:
				if g := int32(runtime.NumGoroutine()); g > atomic.LoadInt32(&peak) {
					atomic.StoreInt32(&peak, g)
				}
				time.Sleep(time.Millisecond)
			}
		}
	}()

	// Two-phase connect mode = the goroutine-per-probe danger path of the old
	// engine. rate<0 → unlimited so the sweep runs fast enough to sample.
	ScanWithPorts([]string{"127.0.0.1"}, ports, concurrency, -1, false, testOpts(), nil, nil)

	close(stop)
	sampWG.Wait()

	delta := int(atomic.LoadInt32(&peak)) - baseline
	// Workers(20) + feeder + heartbeat + a little slack. The OLD engine would
	// spike toward ~len(ports) here. Anything under ~5× concurrency proves the
	// pool is bounded and does not scale with the task count.
	if delta > 5*concurrency+20 {
		t.Fatalf("goroutine delta %d too high for a fixed pool of %d workers (peak=%d baseline=%d); engine is not bounded",
			delta, concurrency, peak, baseline)
	}
}

// --- engine: cancellation stops the sweep ---------------------------------

// TestCancelStopsSweep proves an already-cancelled context yields no probing
// and returns promptly (the worker pool drains without deadlock).
func TestCancelStopsSweep(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel up front
	opts := &shared.HTTPOptions{Ctx: ctx, Timeout: time.Second}

	ports := make([]int, 0, 5000)
	for i := 1; i <= 5000; i++ {
		ports = append(ports, i)
	}
	done := make(chan *ScanResult, 1)
	go func() {
		done <- ScanWithPorts([]string{"127.0.0.1"}, ports, 20, 0, true, opts, nil, nil)
	}()
	select {
	case res := <-done:
		if len(res.Services) != 0 {
			t.Fatalf("cancelled scan should find nothing, got %d services", len(res.Services))
		}
	case <-time.After(10 * time.Second):
		t.Fatal("cancelled scan did not return promptly — possible worker-pool deadlock")
	}
}
