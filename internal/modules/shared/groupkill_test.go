//go:build unix

package shared

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestProcessGroupKill proves that cancelling a Command's context tears down the
// whole process tree, not just the direct child. The `sh` here forks a
// background grandchild (sleep) and waits on it — the same shape as
// `ip netns exec <ns> nmap`, where killing only the wrapper would orphan the
// tool. Regression guard for the "scan done but tool still running" bug.
func TestProcessGroupKill(t *testing.T) {
	pidFile := filepath.Join(t.TempDir(), "gc.pid")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cmd := Command(ctx, "sh", "-c", "sleep 30 & echo $! > "+pidFile+"; wait")
	if err := cmd.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}

	// Wait until the grandchild has recorded its pid and is running.
	var gpid int
	for i := 0; i < 200 && gpid == 0; i++ {
		if b, err := os.ReadFile(pidFile); err == nil {
			if p, err := strconv.Atoi(strings.TrimSpace(string(b))); err == nil {
				gpid = p
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	if gpid == 0 {
		t.Fatal("grandchild never started")
	}
	if err := syscall.Kill(gpid, 0); err != nil {
		t.Fatalf("grandchild %d not alive before cancel: %v", gpid, err)
	}

	cancel()
	_ = cmd.Wait()

	// The group kill should have reaped the grandchild promptly.
	dead := false
	for i := 0; i < 200; i++ {
		if err := syscall.Kill(gpid, 0); err != nil {
			dead = true // ESRCH: process gone
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !dead {
		_ = syscall.Kill(gpid, syscall.SIGKILL) // don't leak the test's own orphan
		t.Fatalf("grandchild pid %d survived context cancel — orphaned", gpid)
	}
}
