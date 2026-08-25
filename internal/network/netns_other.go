//go:build !linux

package network

import (
	"context"
	"errors"
	"os/exec"
)

// Stubs for non-Linux platforms. The killswitch isn't available since
// only the Linux kernel exposes network namespaces. Caller code keeps
// working — IsActive() returns false so subprocess helpers fall through
// to plain exec.CommandContext.

func Setup(targetIface string) error {
	return errors.New("network namespace killswitch is Linux-only")
}

func Teardown() error { return nil }

func Exec(ctx context.Context, name string, args ...string) *exec.Cmd {
	// Never actually called when IsActive() is false, but defined so
	// callers compile on every platform.
	return exec.CommandContext(ctx, name, args...)
}

func IsActive() bool { return false }

func HealthCheck(targetIface, expectedIP string) error {
	return errors.New("killswitch not supported on this platform")
}

func RequiresPrivilege() error {
	return errors.New("killswitch not supported on this platform")
}
