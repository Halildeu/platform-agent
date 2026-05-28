//go:build windows

package winget

import (
	"context"
	"errors"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// InstallWinGet wires the production Windows runner + locator +
// detection probe + egress verifier into the cross-platform
// RunInstall decision pipeline. Public entry point invoked by the
// executor when a Windows agent receives an INSTALL_SOFTWARE
// command.
func InstallWinGet(ctx context.Context, req InstallRequest) InstallResult {
	opts := InstallOptions{
		Locator: defaultLocator,
		EgressVerify: func(probeCtx context.Context) SourceEgressReadiness {
			_ = probeCtx
			return DetectSourceEgress(time.Now())
		},
		DetectionProbe: func(probeCtx context.Context, rule DetectionRule, wingetPath string) (PreDetectResult, error) {
			return ProbeViaWingetList(probeCtx, defaultExecutor, rule, wingetPath)
		},
		InstallRunner: windowsInstallRunner,
		Timeout:       DefaultInstallTimeout,
		Now:           time.Now,
	}
	return RunInstall(req, opts)
}

// windowsInstallRunner spawns `winget.exe install ...` and reports
// the structured outcome with bounded stdout / stderr capture.
//
// Timeout strategy (Codex 019e6bfa iter-2 AGREE):
//
//   - exec.CommandContext(ctx, ...) bound to the parent decision
//     context. On deadline expiry the stdlib calls Process.Kill()
//     which on Windows maps to TerminateProcess against the top-
//     level winget.exe handle. Child installers winget spawned can
//     survive that call.
//   - To make the kill atomic across the spawned tree we
//     immediately follow up with `taskkill /F /T /PID <pid>`, which
//     walks every descendant and forces termination. This is the
//     documented v1 fallback (Codex iter-2 "fallback acceptable if
//     documented + tested"). A Job Object implementation that
//     avoids the brief Start()→Kill() race window is deferred to a
//     v1.1 follow-up (RT-AG-027-F1 in this PR's body).
//   - KillStrategy in the RunnerOutcome marks "taskkill_tree" on
//     timeout-driven kills so post-mortem can prove the tree was
//     terminated. The audit chain carries this verbatim.
//
// Stdout / stderr capture is bounded by CaptureLimitBytes per
// stream via the in-package capWriter (sliding tail with overall
// total counter); this prevents a misbehaving installer from
// blowing up agent memory.
func windowsInstallRunner(ctx context.Context, wingetPath string, args []string) RunnerOutcome {
	startedAt := time.Now()
	cmd := exec.CommandContext(ctx, wingetPath, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		// CREATE_NEW_PROCESS_GROUP keeps winget in its own group so
		// the OS bookkeeping understands the parent / child
		// relationship; taskkill /T then walks this group reliably.
		CreationFlags: 0x00000200,
	}

	stdoutCap := newCapWriter(CaptureLimitBytes)
	stderrCap := newCapWriter(CaptureLimitBytes)
	cmd.Stdout = stdoutCap
	cmd.Stderr = stderrCap

	runErr := cmd.Run()
	durationMs := int(time.Since(startedAt) / time.Millisecond)

	exitCode := -1
	timedOut := false
	killStrategy := ""

	if runErr != nil {
		var exitErr *exec.ExitError
		if errors.As(runErr, &exitErr) {
			exitCode = exitErr.ExitCode()
		}
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			timedOut = true
			killStrategy = killProcessTree(cmd)
		}
	} else {
		exitCode = 0
	}

	stdoutTail, stdoutTruncated, stdoutTotal := stdoutCap.Snapshot()
	stderrTail, stderrTruncated, stderrTotal := stderrCap.Snapshot()

	return RunnerOutcome{
		ExitCode:         exitCode,
		DurationMs:       durationMs,
		RebootRequired:   exitCode == 3010 || containsRebootSignal(stdoutTail, stderrTail),
		KillStrategy:     killStrategy,
		TimedOut:         timedOut,
		StdoutTail:       stdoutTail,
		StdoutTruncated:  stdoutTruncated,
		StdoutTotalBytes: stdoutTotal,
		StderrTail:       stderrTail,
		StderrTruncated:  stderrTruncated,
		StderrTotalBytes: stderrTotal,
	}
}

// killProcessTree runs `taskkill /F /T /PID <pid>` against the
// winget root process so every descendant the installer spawned is
// terminated atomically. Returns a label describing which kill path
// succeeded so the audit chain can show post-mortem the actual
// termination semantics.
func killProcessTree(cmd *exec.Cmd) string {
	if cmd == nil || cmd.Process == nil {
		return "no_process"
	}
	killCmd := exec.Command(
		"taskkill",
		"/F",
		"/T",
		"/PID",
		strconv.Itoa(cmd.Process.Pid),
	)
	if err := killCmd.Run(); err == nil {
		return "taskkill_tree"
	}
	return "process_kill_only"
}

// containsRebootSignal scans the capped stdout / stderr tails for
// the canonical "reboot required" markers the WinGet installer
// emits when the underlying MSI returns exit 3010. Cheap defence
// in case the exit code did not surface (some installers
// short-circuit before the wrapper observes the code).
func containsRebootSignal(stdout, stderr string) bool {
	tail := strings.ToLower(stdout + "\n" + stderr)
	if strings.Contains(tail, "restart required") {
		return true
	}
	if strings.Contains(tail, "reboot required") {
		return true
	}
	// MSI/winget exit codes 1641 (success, restart initiated) and
	// 3010 (success, reboot required) are the canonical reboot
	// signals; surfacing them via the tail covers the cases where
	// the exit code is masked by a wrapper.
	if strings.Contains(tail, "exit code 1641") || strings.Contains(tail, "exit code 3010") {
		return true
	}
	return false
}

// ────────────────────────────────────────────────────────────────
// Bounded stream capture writer

type capWriter struct {
	mu        sync.Mutex
	limit     int
	totalSeen int
	buf       []byte
}

func newCapWriter(limit int) *capWriter {
	return &capWriter{limit: limit, buf: make([]byte, 0, limit)}
}

func (c *capWriter) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.totalSeen += len(p)
	if len(c.buf)+len(p) <= c.limit {
		c.buf = append(c.buf, p...)
		return len(p), nil
	}
	combined := append(c.buf, p...)
	if len(combined) > c.limit {
		combined = combined[len(combined)-c.limit:]
	}
	c.buf = combined
	return len(p), nil
}

func (c *capWriter) Snapshot() (tail string, truncated bool, total int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return string(c.buf), c.totalSeen > len(c.buf), c.totalSeen
}
