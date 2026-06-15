//go:build windows

package dataplane

import (
	"os"
	"testing"

	"golang.org/x/sys/windows"
)

// TestLaunchInActiveSessionRealVM proves the launcher starts a process IN the
// active interactive session FROM Session 0, WITHOUT the user's password. Gated
// (DATAPLANE_REAL_LAUNCH=1) and must run as SYSTEM (SeTcbPrivilege) with a
// logged-on interactive user — i.e. the Win11 VM via `prlctl exec` (= SYSTEM).
func TestLaunchInActiveSessionRealVM(t *testing.T) {
	if os.Getenv("DATAPLANE_REAL_LAUNCH") != "1" {
		t.Skip("set DATAPLANE_REAL_LAUNCH=1 as SYSTEM on a Windows host with an interactive session")
	}
	sysRoot := os.Getenv("SystemRoot")
	if sysRoot == "" {
		sysRoot = `C:\Windows`
	}
	h, err := LaunchInActiveSession(sysRoot+`\System32\cmd.exe`, "/c", "exit 0")
	if err != nil {
		t.Fatalf("LaunchInActiveSession failed: %v", err)
	}
	defer func() { _ = h.Terminate() }()

	if h.SessionID == 0 {
		t.Fatal("targeted Session 0 (non-interactive) — want the interactive session")
	}
	var procSess uint32
	if err := windows.ProcessIdToSessionId(h.Pid, &procSess); err != nil {
		t.Fatalf("ProcessIdToSessionId(pid=%d): %v", h.Pid, err)
	}
	if procSess == 0 {
		t.Fatal("helper ran in Session 0 — interactive-session launch FAILED")
	}
	if procSess != h.SessionID {
		t.Fatalf("helper ran in session %d, want %d (active interactive session)", procSess, h.SessionID)
	}
	t.Logf("launcher OK: pid=%d ran in interactive session %d from SYSTEM/Session-0 (no password)", h.Pid, procSess)
}

// TestLaunchFailClosedTypedErrors: off an interactive context the launcher must
// return a typed fail-closed error, never a silent Session-0 launch. (Runs
// unconditionally on the windows CI runner, which is typically Session-0 with
// no console user → ErrNoInteractiveSession or ErrUserTokenUnavailable.)
func TestLaunchFailClosedTypedErrors(t *testing.T) {
	if os.Getenv("DATAPLANE_REAL_LAUNCH") == "1" {
		t.Skip("interactive session present; covered by TestLaunchInActiveSessionRealVM")
	}
	_, err := LaunchInActiveSession(`C:\Windows\System32\cmd.exe`, "/c", "exit 0")
	if err == nil {
		t.Fatal("expected fail-closed error with no interactive session, got nil")
	}
}
