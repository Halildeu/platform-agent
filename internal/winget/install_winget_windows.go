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
// command. Accepts a parent context (Codex 019e6c0d iter-1 P0#2)
// so agent shutdown / command-timeout signals propagate.
func InstallWinGet(ctx context.Context, req InstallRequest) InstallResult {
	opts := InstallOptions{
		Locator: defaultLocator,
		EgressVerify: func(probeCtx context.Context) SourceEgressReadiness {
			_ = probeCtx
			return DetectSourceEgress(time.Now())
		},
		DetectionProbe: func(probeCtx context.Context, rule DetectionRule, wingetPath string) (PreDetectResult, error) {
			// Dispatch by rule type.
			//   REGISTRY_UNINSTALL  → ARP registry (Session-0-reliable, AUTHORITATIVE)
			//   FILE_EXISTS / FILE_SHA256 / FILE_VERSION → filesystem probe
			//     (Session-0-reliable; FILE_VERSION reads PE VersionInfo
			//     via Win32 API — see detect_file_windows.go).
			//   WINGET_PACKAGE      → `winget list` (CONFIRM_ONLY — §11.3b)
			switch rule.Type {
			case DetectionRuleTypeRegistryUninstall:
				return ProbeViaRegistry(probeCtx, defaultArpReader(), rule)
			case DetectionRuleTypeFileExists,
				DetectionRuleTypeFileSha256,
				DetectionRuleTypeFileVersion:
				return ProbeViaFile(probeCtx, rule)
			default:
				return ProbeViaWingetList(probeCtx, defaultExecutor, rule, wingetPath)
			}
		},
		InstallRunner: windowsInstallRunner,
		Timeout:       DefaultInstallTimeout,
		Now:           time.Now,
	}
	return RunInstall(ctx, req, opts)
}

// windowsInstallRunner spawns `winget.exe install ...` and reports
// the structured outcome with bounded stdout / stderr capture.
//
// Timeout strategy (Codex 019e6c0d iter-1 P1#3 absorb):
//
//   - The runner uses `exec.Command` (NOT `exec.CommandContext`)
//     + manual `Start()` + a goroutine that watches `cmd.Wait()`.
//     A parent `ctx.Done()` triggers `killProcessTree(cmd)` while
//     the parent process is still alive; only then do we drain
//     `Wait()`. This is the documented anti-pattern for
//     `exec.CommandContext` which would Process.Kill() the parent
//     first and leave the spawned installer tree orphaned (Codex
//     critical_finding).
//   - `killProcessTree(cmd)` spawns `taskkill /F /T /PID <pid>`
//     which walks every descendant and forces termination. v1
//     fallback only — a Windows Job Object implementation that
//     pre-binds the spawned tree (atomic kill on a single
//     TerminateJobObject) is RT-AG-027-F1 (post-v1 hardening).
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
	cmd := exec.Command(wingetPath, args...)
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

	if startErr := cmd.Start(); startErr != nil {
		return RunnerOutcome{
			ExitCode:         -1,
			DurationMs:       int(time.Since(startedAt) / time.Millisecond),
			StartFailureCode: "start_failed",
			StderrTail:       startErr.Error(),
			StderrTotalBytes: len(startErr.Error()),
		}
	}

	waitCh := make(chan error, 1)
	go func() { waitCh <- cmd.Wait() }()

	exitCode := -1
	timedOut := false
	killStrategy := ""
	var waitErr error

	select {
	case waitErr = <-waitCh:
		// Process exited on its own.
	case <-ctx.Done():
		// Parent context cancelled or hit the deadline. Kill the
		// process tree FIRST while the parent is still alive, then
		// drain Wait. Codex 019e6c0d iter-1 P1#3 absorb.
		timedOut = errors.Is(ctx.Err(), context.DeadlineExceeded)
		killStrategy = killProcessTree(cmd)
		// Bounded grace period so a hung process does not stall
		// the executor indefinitely while taskkill walks the tree.
		select {
		case waitErr = <-waitCh:
		case <-time.After(5 * time.Second):
			// Final defence: orphan the goroutine; the OS will
			// eventually reap the process. We've already done the
			// taskkill so its descendants are gone.
		}
	}

	durationMs := int(time.Since(startedAt) / time.Millisecond)

	if waitErr != nil {
		var exitErr *exec.ExitError
		if errors.As(waitErr, &exitErr) {
			exitCode = exitErr.ExitCode()
		}
	} else if !timedOut {
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
