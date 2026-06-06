//go:build windows

package winget

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"syscall"
	"time"
)

// UninstallWinGet wires the production Windows runner + locator +
// absence-aware probe into the cross-platform RunUninstall pipeline.
// Public entry point invoked by the executor when a Windows agent
// receives an UNINSTALL_SOFTWARE command.
//
// Codex plan-time iter-2 AGREE thread `019e8de2`. v1 authoritative-only
// detector tier; WINGET_PACKAGE is gated at the top of RunUninstall
// with FAILED_UNSUPPORTED_VERIFICATION (defense in depth — backend
// Phase 1b follow-up gate already rejects at propose/approve).
func UninstallWinGet(ctx context.Context, req UninstallRequest) UninstallResult {
	opts := UninstallOptions{
		Locator:         LocateExecutable,
		Probe:           windowsUninstallProbe,
		UninstallRunner: windowsUninstallRunner,
		Timeout:         DefaultUninstallTimeout,
		Now:             time.Now,
	}
	return RunUninstall(ctx, req, opts)
}

// windowsUninstallProbe is the absence-aware wrapper around AG-027
// authoritative detectors (registry + file). Maps PreDetectResult to
// ProbeState so the destructive decision tree can distinguish ABSENT
// from PRESENT_MISMATCH from AMBIGUOUS/ERROR (Codex 019e8de2 iter-1
// absorb: PreDetectResult.Satisfied=false is too coarse).
//
//   - REGISTRY_UNINSTALL: ProbeViaRegistry → MATCHED if Satisfied,
//     ABSENT on clean miss, AMBIGUOUS on ErrRegistryAmbiguous,
//     ERROR on any other error.
//   - FILE_EXISTS: ProbeViaFile → MATCHED if Satisfied, ABSENT
//     otherwise (a missing file is the canonical absence signal).
//   - FILE_SHA256: ProbeViaFile → MATCHED if Satisfied,
//     PRESENT_MISMATCH if the file exists but hash differs,
//     ABSENT if the file is missing.
//   - FILE_VERSION: ProbeViaFile → MATCHED if Satisfied,
//     PRESENT_MISMATCH if the file exists but predicate fails,
//     ABSENT if the file is missing.
//   - WINGET_PACKAGE / other: UNSUPPORTED (v1).
func windowsUninstallProbe(ctx context.Context, rule DetectionRule, wingetPath string) UninstallProbeResult {
	_ = wingetPath
	authority := DetectionReliabilityAuthoritative
	switch rule.Type {
	case DetectionRuleTypeRegistryUninstall:
		pre, err := ProbeViaRegistry(ctx, defaultArpReader(), rule)
		evidence := registryEvidence(pre)
		if err != nil {
			if errors.Is(err, ErrRegistryAmbiguous) {
				return UninstallProbeResult{
					State:           ProbeStateAmbiguous,
					Authority:       authority,
					RuleType:        rule.Type,
					DetectionMethod: DetectionMethodRegistryUninstall,
					ReasonCode:      UninstallReasonPreProbeAmbiguous,
					SafeEvidence:    evidence,
				}
			}
			return UninstallProbeResult{
				State:           ProbeStateError,
				Authority:       authority,
				RuleType:        rule.Type,
				DetectionMethod: DetectionMethodRegistryUninstall,
				ReasonCode:      UninstallReasonProbeError,
				SafeEvidence:    evidence,
			}
		}
		state := ProbeStateAbsent
		if pre.Satisfied {
			state = ProbeStateMatched
		}
		return UninstallProbeResult{
			State:           state,
			Authority:       authority,
			RuleType:        rule.Type,
			DetectionMethod: DetectionMethodRegistryUninstall,
			SafeEvidence:    evidence,
		}
	case DetectionRuleTypeFileExists:
		pre, err := ProbeViaFile(ctx, rule)
		evidence := fileEvidence(pre)
		if err != nil {
			// File probe errors are uninterpretable (I/O failure, permission
			// denied). Fail-closed; backend audit row will reflect
			// VERIFY_INCONCLUSIVE via downstream mapping.
			return UninstallProbeResult{
				State:           ProbeStateError,
				Authority:       authority,
				RuleType:        rule.Type,
				DetectionMethod: DetectionMethodFileExists,
				ReasonCode:      UninstallReasonProbeError,
				SafeEvidence:    evidence,
			}
		}
		state := ProbeStateAbsent
		if pre.Satisfied {
			state = ProbeStateMatched
		}
		return UninstallProbeResult{
			State:           state,
			Authority:       authority,
			RuleType:        rule.Type,
			DetectionMethod: DetectionMethodFileExists,
			SafeEvidence:    evidence,
		}
	case DetectionRuleTypeFileSha256, DetectionRuleTypeFileVersion:
		method := DetectionMethodFileSha256
		if rule.Type == DetectionRuleTypeFileVersion {
			method = DetectionMethodFileVersion
		}
		// ProbeViaFile collapses "file missing" and "file present but
		// predicate fails" both to Satisfied=false + nil error
		// (probeFileSha256 / probeFileVersion early-return on
		// os.IsNotExist). The uninstall decision tree needs to
		// distinguish ABSENT (file missing → SUCCEEDED_VERIFIED post-
		// mutation) from PRESENT_MISMATCH (file still there with drifted
		// hash/version → PARTIAL_RESIDUE). Pre-check with os.Stat here
		// is cheap (single syscall) and authoritative under Session-0.
		fileExists := true
		if _, statErr := os.Stat(rule.Path); statErr != nil {
			if os.IsNotExist(statErr) {
				fileExists = false
			} else {
				return UninstallProbeResult{
					State:           ProbeStateError,
					Authority:       authority,
					RuleType:        rule.Type,
					DetectionMethod: method,
					ReasonCode:      UninstallReasonProbeError,
				}
			}
		}
		pre, err := ProbeViaFile(ctx, rule)
		evidence := fileEvidence(pre)
		if err != nil {
			return UninstallProbeResult{
				State:           ProbeStateError,
				Authority:       authority,
				RuleType:        rule.Type,
				DetectionMethod: method,
				ReasonCode:      UninstallReasonProbeError,
				SafeEvidence:    evidence,
			}
		}
		if !fileExists {
			return UninstallProbeResult{
				State:           ProbeStateAbsent,
				Authority:       authority,
				RuleType:        rule.Type,
				DetectionMethod: method,
				SafeEvidence:    evidence,
			}
		}
		// File present — Satisfied=true → MATCHED; Satisfied=false →
		// PRESENT_MISMATCH (file exists but hash/version drifted).
		state := ProbeStatePresentMismatch
		if pre.Satisfied {
			state = ProbeStateMatched
		}
		return UninstallProbeResult{
			State:           state,
			Authority:       authority,
			RuleType:        rule.Type,
			DetectionMethod: method,
			SafeEvidence:    evidence,
		}
	default:
		// WINGET_PACKAGE / unknown — UNSUPPORTED (v1 gate at
		// RunUninstall top-level rejects this before we ever get here;
		// defense in depth).
		return UninstallProbeResult{
			State:      ProbeStateUnsupported,
			Authority:  DetectionReliabilityConfirmOnly,
			RuleType:   rule.Type,
			ReasonCode: UninstallReasonDetectionRuleUnsupportedV1,
		}
	}
}

// registryEvidence projects ProbeViaRegistry hits onto the bounded
// scalar safeEvidence map (backend allow-list:
// matchedPackageId / matchedVersion / matchedProductCode /
// matchedDisplayName / matchedPublisher / candidateCount).
func registryEvidence(pre PreDetectResult) map[string]interface{} {
	if pre.MatchedPackageID == "" && pre.MatchedVersion == "" {
		return nil
	}
	ev := make(map[string]interface{}, 3)
	if pre.MatchedPackageID != "" {
		ev["matchedPackageId"] = pre.MatchedPackageID
	}
	if pre.MatchedVersion != "" {
		ev["matchedVersion"] = pre.MatchedVersion
	}
	return ev
}

// fileEvidence projects ProbeViaFile hits onto the bounded scalar
// safeEvidence map. FILE_VERSION probe records matchedVersion; FILE_SHA256
// records nothing identifying (hash itself is forensic in stdoutSummary
// not in audit safeEvidence).
func fileEvidence(pre PreDetectResult) map[string]interface{} {
	if pre.MatchedPackageID == "" && pre.MatchedVersion == "" {
		return nil
	}
	ev := make(map[string]interface{}, 2)
	if pre.MatchedPackageID != "" {
		ev["matchedPackageId"] = pre.MatchedPackageID
	}
	if pre.MatchedVersion != "" {
		ev["matchedVersion"] = pre.MatchedVersion
	}
	return ev
}

// windowsUninstallRunner spawns `winget.exe uninstall ...` and reports
// the structured outcome with bounded stdout / stderr capture.
//
// Mirrors `windowsInstallRunner` timeout strategy (Codex 019e6c0d iter-1
// P1#3 absorb): exec.Command + manual Start + Wait goroutine; on
// ctx.Done() taskkill /F /T /PID FIRST while parent is alive, then drain
// Wait under a 5s grace. CREATE_NEW_PROCESS_GROUP so taskkill /T walks
// the spawned MSI/installer descendants reliably.
//
// MSI uninstall paths can take longer than installs (repair / custom-
// action / network wait) — the 30-min budget is set at the
// RunUninstall layer (DefaultUninstallTimeout).
func windowsUninstallRunner(ctx context.Context, wingetPath string, args []string) RunnerOutcome {
	startedAt := time.Now()
	cmd := exec.Command(wingetPath, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: 0x00000200, // CREATE_NEW_PROCESS_GROUP
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
		// Parent context cancelled or hit deadline. Kill tree FIRST,
		// then drain Wait under a grace period (Codex iter-1 P1#3).
		timedOut = errors.Is(ctx.Err(), context.DeadlineExceeded)
		killStrategy = killProcessTree(cmd)
		select {
		case waitErr = <-waitCh:
		case <-time.After(5 * time.Second):
			// Orphan goroutine; taskkill /T already walked descendants.
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
