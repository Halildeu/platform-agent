//go:build windows

package ptyexec

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"platform-agent/internal/remotebridge/cmdline"
	"platform-agent/internal/remotebridge/dataplane"
)

// TestRunConPTYInSession is the ConPTY gold-proof: from SYSTEM (Session 0) it launches THIS binary as a
// ConPTY helper IN the interactive session (via the session-launcher), where conhost has a window station;
// the helper runs the allowlisted, NO-shell "hostname" in a pseudo-console and writes the CAPTURED output to
// a machine-wide file the SYSTEM test then reads + asserts. Ties together the allowlist/ExecPlan (slice-3a),
// the ConPTY wrapper (slice-3b), and the session-1 launcher.
//
// Gated (DATAPLANE_REAL_CONPTY=1) + must run as SYSTEM on a Windows desktop session (the Win11 VM via
// `prlctl exec`). A pseudo-console in headless Session-0 does NOT relay the child's stdout — it must run in
// an interactive session, which is exactly how the executor (slice-3c) will run it.
func TestRunConPTYInSession(t *testing.T) {
	if os.Getenv("DATAPLANE_REAL_CONPTY") != "1" {
		t.Skip("set DATAPLANE_REAL_CONPTY=1 as SYSTEM on a Windows desktop session")
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	pd := os.Getenv("ProgramData")
	if pd == "" {
		pd = `C:\ProgramData`
	}
	result := filepath.Join(pd, "dpconpty_out.bin")
	_ = os.Remove(result)

	h, err := dataplane.LaunchInActiveSession(self, conptyRunOutFlag+result)
	if err != nil {
		t.Fatalf("launch conpty helper in interactive session: %v", err)
	}
	defer func() { _ = h.Terminate() }()

	deadline := time.Now().Add(25 * time.Second)
	var data []byte
	for time.Now().Before(deadline) {
		if b, rerr := os.ReadFile(result); rerr == nil && len(b) > 0 {
			data = b
			break
		}
		time.Sleep(300 * time.Millisecond)
	}
	_ = os.Remove(result)
	if len(data) == 0 {
		t.Fatal("conpty helper wrote no output (ran in session 1)")
	}

	// The pseudo-console output is a terminal stream (VT/CSI + an OSC title interleaved with the rendered
	// text). Strip the escape sequences to recover the rendered text, then confirm the real machine hostname
	// is present — proves real no-shell execution + OUTPUT capture through the ConPTY.
	host, _ := os.Hostname()
	rendered := stripVT(string(data))
	if host == "" || !strings.Contains(rendered, host) {
		t.Fatalf("conpty rendered output does not contain the hostname %q; rendered=%q raw=%q", host, rendered, string(data))
	}
	t.Logf("CONPTY GOLD-PROOF OK: hostname via pseudo-console (no shell) in session 1 → captured %d bytes; rendered text contains the hostname", len(data))
}

// TestConPTYOutputCapNoHang proves the fail-fast cap path (Codex review): a tiny output cap on a
// LONG-RUNNING child must terminate the child and return PROMPTLY — never hang waiting on a process whose
// pipe we stopped draining. ping -n 20 runs ~19s; with a 4-byte cap the reader stops almost immediately (the
// conhost VT-init alone exceeds 4 bytes), so the cap path must kill ping and return in well under that.
// Runs directly (the cap triggers on the VT init, no child render needed → no session-1 launcher).
func TestConPTYOutputCapNoHang(t *testing.T) {
	if os.Getenv("DATAPLANE_REAL_CONPTY") != "1" {
		t.Skip("set DATAPLANE_REAL_CONPTY=1 on Windows for the real ConPTY cap proof")
	}
	const ping = `C:\Windows\System32\PING.EXE`
	cmdLine := cmdline.BuildCommandLine(ping, []string{"127.0.0.1", "-n", "20"})
	start := time.Now()
	out, _, err := runConPTYCapped(context.Background(), ping, cmdLine, 120, 30, 4)
	elapsed := time.Since(start)

	if !errors.Is(err, ErrConPTYOutputCap) {
		t.Fatalf("expected ErrConPTYOutputCap, got err=%v (%d bytes)", err, len(out))
	}
	if len(out) > 4 {
		t.Errorf("output not capped to 4: got %d bytes", len(out))
	}
	if elapsed > 10*time.Second { // ping -n 20 ≈ 19s; the cap MUST terminate it far sooner
		t.Fatalf("cap path did not fail-fast: %v (the long-running child was not terminated → near-hang)", elapsed)
	}
	t.Logf("CONPTY CAP NO-HANG OK: 4-byte cap on a ~19s child → ErrConPTYOutputCap in %v (%d bytes)", elapsed, len(out))
}

// stripVT removes ANSI/VT escape sequences (CSI "ESC[…<final>", OSC "ESC]…<BEL|ST>", and other "ESC<byte>")
// from a pseudo-console stream, leaving the rendered text — so a content assertion sees the command output,
// not the terminal control codes that interleave it.
func stripVT(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); {
		c := s[i]
		if c == 0x1b && i+1 < len(s) { // ESC
			switch s[i+1] {
			case '[': // CSI: ESC [ params/intermediates ... final byte 0x40-0x7e
				i += 2
				for i < len(s) && !(s[i] >= 0x40 && s[i] <= 0x7e) {
					i++
				}
				if i < len(s) {
					i++ // consume the final byte
				}
			case ']': // OSC: ESC ] ... terminated by BEL (0x07) or ST (ESC \)
				i += 2
				for i < len(s) && s[i] != 0x07 && !(s[i] == 0x1b && i+1 < len(s) && s[i+1] == '\\') {
					i++
				}
				if i < len(s) && s[i] == 0x07 {
					i++
				} else if i+1 < len(s) { // ST
					i += 2
				}
			default: // ESC <byte>
				i += 2
			}
			continue
		}
		b.WriteByte(c)
		i++
	}
	return b.String()
}
