//go:build unix

package backend

import (
	"os/exec"
	"syscall"
)

// Signals used during shutdown escalation, abstracted so the Windows build
// (which has no process groups or SIGTERM) can supply its own meaning.
const (
	sigTerm = syscall.SIGTERM
	sigKill = syscall.SIGKILL
)

// setProcGroup puts the child in a new process group whose id equals its pid.
// Everything it spawns inherits that group, which is what lets signalGroup
// reap the whole tree.
func setProcGroup(cmd *exec.Cmd) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Setpgid = true
}

// signalGroup sends sig to the child's entire process group. Signalling
// -pgid rather than the pid is the whole point: `npx foo` execs a shell that
// forks node, and killing only the shell would orphan the server.
func signalGroup(cmd *exec.Cmd, sig syscall.Signal) error {
	if cmd == nil || cmd.Process == nil {
		return nil
	}
	pid := cmd.Process.Pid
	// Setpgid made pgid == pid; fall back to the pid if the group is gone.
	if err := syscall.Kill(-pid, sig); err != nil {
		if err == syscall.ESRCH {
			return nil
		}
		return syscall.Kill(pid, sig)
	}
	return nil
}
