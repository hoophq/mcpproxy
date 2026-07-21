//go:build windows

package backend

import (
	"os"
	"os/exec"
)

// Windows has no signals, so both escalation steps terminate the process. A
// job object would be the equivalent of a process group, but stdio backends
// on Windows are a niche case; we settle for killing the direct child.
var (
	sigTerm os.Signal = os.Kill
	sigKill os.Signal = os.Kill
)

func setProcGroup(_ *exec.Cmd) {}

func signalGroup(cmd *exec.Cmd, sig os.Signal) error {
	if cmd == nil || cmd.Process == nil {
		return nil
	}
	return cmd.Process.Signal(sig)
}
