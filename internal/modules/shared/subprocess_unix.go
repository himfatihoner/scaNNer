//go:build unix

package shared

import (
	"os/exec"
	"syscall"
	"time"
)

// applyProcessGroupKill makes the spawned command a process-group leader
// (Setpgid) and replaces exec's default cancel — which SIGKILLs only the direct
// child — with one that SIGKILLs the entire process group. Because a child
// started with Setpgid becomes the leader of a new group and every process it
// forks (the `ip netns exec` target, a python wrapper's children, …) inherits
// that group, `kill(-pgid)` tears down the whole tool tree. Without it those
// grandchildren orphan and keep running after the scan finishes.
//
// WaitDelay bounds Wait() so a lingering grandchild that inherited a stdout/err
// pipe can't keep the reader (and thus the scan goroutine) blocked forever.
func applyProcessGroupKill(cmd *exec.Cmd) {
	if cmd == nil {
		return
	}
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Setpgid = true
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		// Negative PID targets the process group led by the child (Setpgid
		// above), so the tool and any of its descendants all receive SIGKILL.
		if err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL); err != nil {
			// Group gone already, or (defensively) fall back to the single pid.
			return cmd.Process.Kill()
		}
		return nil
	}
	cmd.WaitDelay = 5 * time.Second
}
