package shared

import (
	"context"
	"net"
	"testing"
	"time"
)

// A real connect through BoundDialer must still SUCCEED while a throttle is
// installed (the ControlContext gate only delays, it must not break the dial).
func TestThrottledDialStillConnects(t *testing.T) {
	defer SetNetworkThrottle(0, 0)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()

	SetNetworkThrottle(0, 120*time.Millisecond) // 120ms per-connect delay
	start := time.Now()
	conn, err := BoundDialer(nil, 2*time.Second).DialContext(context.Background(), "tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("throttled dial failed (ControlContext broke the connect): %v", err)
	}
	conn.Close()
	if el := time.Since(start); el < 100*time.Millisecond {
		t.Fatalf("throttle delay not applied to real dial: %v", el)
	}
}

func TestNetworkThrottle(t *testing.T) {
	defer SetNetworkThrottle(0, 0)

	// No throttle installed → gate is instant.
	if err := throttleGate(context.Background()); err != nil {
		t.Fatalf("unthrottled gate errored: %v", err)
	}
	if NetworkThrottled() {
		t.Fatal("NetworkThrottled true with no throttle")
	}

	// Install: 30ms spacing + 15ms per-connection delay.
	SetNetworkThrottle(30*time.Millisecond, 15*time.Millisecond)
	if !NetworkThrottled() {
		t.Fatal("NetworkThrottled false after install")
	}
	start := time.Now()
	for i := 0; i < 4; i++ {
		if err := throttleGate(context.Background()); err != nil {
			t.Fatalf("gate %d errored: %v", i, err)
		}
	}
	// 4 gates spaced 30ms apart must take clearly longer than instant.
	if el := time.Since(start); el < 90*time.Millisecond {
		t.Fatalf("throttle did not slow 4 connects: %v", el)
	}

	// Exempt context bypasses the throttle immediately.
	s2 := time.Now()
	if err := throttleGate(WithoutThrottle(context.Background())); err != nil {
		t.Fatalf("exempt gate errored: %v", err)
	}
	if el := time.Since(s2); el > 10*time.Millisecond {
		t.Fatalf("WithoutThrottle did not bypass: %v", el)
	}

	// A throttled wait cancels promptly when the dial context is cancelled.
	SetNetworkThrottle(10*time.Second, 10*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	s3 := time.Now()
	if err := throttleGate(ctx); err == nil {
		t.Fatal("expected context error from a cancelled throttled wait")
	}
	if el := time.Since(s3); el > 500*time.Millisecond {
		t.Fatalf("throttle did not honor ctx cancel promptly: %v", el)
	}
}
