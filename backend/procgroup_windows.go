//go:build windows

package backend

import (
	"os"
	"os/exec"
)

// Windows has no signals, so both escalation steps terminate the process. A
// job object is the closest equivalent to a process group, but stdio backends
// on Windows are rare enough that killing the direct child suffices.
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
