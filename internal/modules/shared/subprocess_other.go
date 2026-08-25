//go:build !unix

package shared

import "os/exec"

// applyProcessGroupKill is a no-op on non-unix platforms (the killswitch /
// netns path is Linux-only anyway). exec's default single-child cancel applies.
func applyProcessGroupKill(cmd *exec.Cmd) {}
