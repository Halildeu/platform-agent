//go:build windows

package inventory

import (
	"context"
	"errors"
	"strings"
	"time"

	winreg "golang.org/x/sys/windows/registry"
)

// AG-030 Windows pending-reboot probe.
//
// The probe opens each canonical reboot-marker location, distinguishes
// "key missing" (definitive false) from "access denied / type
// mismatch / driver unavailable" (probe error). Raw registry values
// (PendingFileRenameOperations entries, computer names) never reach
// the wire — only the derived bool.

// pendingRebootProber wraps the per-source helpers so tests can
// inject a stub via a future Probe interface (AG-030 v1 keeps it
// concrete; future v2 can add a seam if SCCM ClientSDK probing
// lands).
type pendingRebootProber struct{}

// ProbePendingReboot is the public production entry point. The
// non-Windows stub in pending_reboot_other.go satisfies the same
// signature so callers compile cross-platform.
func ProbePendingReboot(ctx context.Context, now func() time.Time) PendingRebootResult {
	if ctx == nil {
		// Codex 019e749c post-impl P0#1: nil context guard. The
		// non-Windows stub tolerates nil, but the Windows live path
		// dereferences ctx.Err() and would panic. Treat nil as
		// background context so a careless caller (test, manual
		// invocation) does not crash the agent service.
		ctx = context.Background()
	}
	if now == nil {
		now = time.Now
	}
	start := now()
	result := PendingRebootResult{
		SchemaVersion: PendingRebootSchemaVersion,
		Supported:     true,
	}

	p := pendingRebootProber{}

	type probeFn func(ctx context.Context, result *PendingRebootResult)
	probes := []probeFn{
		p.checkCBS,
		p.checkWindowsUpdate,
		p.checkPendingFileRenameOperations,
		p.checkComputerNameChange,
		p.checkUpdateExeVolatile,
		p.checkNetlogonJoinPending,
	}

	for _, probe := range probes {
		if err := ctx.Err(); err != nil {
			// Context cancellation between sources — flag as
			// probe error so probeComplete=false; do not fabricate
			// a false negative.
			result.ProbeErrors = append(result.ProbeErrors,
				PendingRebootProbeError{
					Code:    PendingRebootErrInternal,
					Summary: "probe context cancelled",
				})
			break
		}
		probe(ctx, &result)
	}

	derivePendingRebootSummary(&result)
	result.ProbeDurationMs = pendingRebootElapsedMs(start, now)
	return result
}

// checkCBS detects the Component-Based Servicing reboot-pending
// marker. The subkey is present if and only if a reboot is required
// to complete a CBS operation (Windows Update, optional component,
// driver install). Access uses WOW64_64KEY so a 32-bit agent binary
// reads the 64-bit hive view (Codex 019e749c iter-1 P0#6 absorb).
func (pendingRebootProber) checkCBS(_ context.Context, result *PendingRebootResult) {
	const path = `SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending`
	exists, err := keyExistsWow64(winreg.LOCAL_MACHINE, path)
	if err != nil {
		result.ProbeErrors = append(result.ProbeErrors, PendingRebootProbeError{
			Source:  PendingRebootSourceCBS,
			Code:    PendingRebootErrAccessDenied,
			Summary: "CBS reboot-pending key probe failed",
		})
		return
	}
	result.Signals.CBSRebootPending = exists
}

// checkWindowsUpdate detects the Windows Update reboot-required
// marker.
func (pendingRebootProber) checkWindowsUpdate(_ context.Context, result *PendingRebootResult) {
	const path = `SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired`
	exists, err := keyExistsWow64(winreg.LOCAL_MACHINE, path)
	if err != nil {
		result.ProbeErrors = append(result.ProbeErrors, PendingRebootProbeError{
			Source:  PendingRebootSourceWindowsUpdate,
			Code:    PendingRebootErrAccessDenied,
			Summary: "Windows Update reboot-required key probe failed",
		})
		return
	}
	result.Signals.WindowsUpdateRebootRequired = exists
}

// checkPendingFileRenameOperations checks the MULTI_SZ that the
// Session Manager replays on next boot. "Value present but empty"
// is treated as definitive false (Codex 019e749c iter-1 P0#4
// absorb); type-mismatch is a probe error. SYSTEM hive paths are
// not subject to the SOFTWARE WOW64 redirection.
func (pendingRebootProber) checkPendingFileRenameOperations(_ context.Context, result *PendingRebootResult) {
	const path = `SYSTEM\CurrentControlSet\Control\Session Manager`
	k, err := winreg.OpenKey(winreg.LOCAL_MACHINE, path, winreg.QUERY_VALUE)
	if err != nil {
		if errors.Is(err, winreg.ErrNotExist) {
			// Should never happen on a sane Windows install, but
			// treat as definitive false (no rename queue) rather
			// than fail the probe.
			return
		}
		result.ProbeErrors = append(result.ProbeErrors, PendingRebootProbeError{
			Source:  PendingRebootSourcePendingFileRenameOperations,
			Code:    PendingRebootErrAccessDenied,
			Summary: "Session Manager key probe failed",
		})
		return
	}
	defer k.Close()

	values, _, err := k.GetStringsValue("PendingFileRenameOperations")
	if errors.Is(err, winreg.ErrNotExist) {
		// Missing value = no rename queue. Definitive false.
		return
	}
	if err != nil {
		result.ProbeErrors = append(result.ProbeErrors, PendingRebootProbeError{
			Source:  PendingRebootSourcePendingFileRenameOperations,
			Code:    PendingRebootErrValueTypeMismatch,
			Summary: "PendingFileRenameOperations is not a REG_MULTI_SZ",
		})
		return
	}
	if hasNonEmptyEntry(values) {
		result.Signals.PendingFileRenameOperations = true
	}
}

// checkComputerNameChange compares the active computer name against
// the pending computer name. The comparison is case-insensitive +
// trim-normalized (Codex 019e749c iter-1 P0#5 absorb). Raw computer
// names are NOT surfaced — only the bool.
func (pendingRebootProber) checkComputerNameChange(_ context.Context, result *PendingRebootResult) {
	active, errActive := readComputerName("ActiveComputerName")
	pending, errPending := readComputerName("ComputerName")
	if errActive != nil || errPending != nil {
		result.ProbeErrors = append(result.ProbeErrors, PendingRebootProbeError{
			Source:  PendingRebootSourceComputerNameChange,
			Code:    PendingRebootErrAccessDenied,
			Summary: "ComputerName / ActiveComputerName probe failed",
		})
		return
	}
	if !equalComputerName(active, pending) {
		result.Signals.ComputerNameChangePending = true
	}
}

// checkUpdateExeVolatile is an additional canonical marker
// enterprise reboot detectors check. The value is a DWORD inside
// the volatile key (cleared on reboot). Codex 019e749c post-impl
// P0#4 absorb: the marker is a `Flags` DWORD value, not just
// subkey existence — a present-but-zero `Flags` value means "no
// reboot pending"; non-zero means pending. Subkey-only check was
// incorrect.
func (pendingRebootProber) checkUpdateExeVolatile(_ context.Context, result *PendingRebootResult) {
	const path = `SOFTWARE\Microsoft\Updates\UpdateExeVolatile`
	k, err := winreg.OpenKey(winreg.LOCAL_MACHINE, path, winreg.QUERY_VALUE|winreg.WOW64_64KEY)
	if err != nil {
		if errors.Is(err, winreg.ErrNotExist) {
			// No volatile update marker; definitive false.
			return
		}
		result.ProbeErrors = append(result.ProbeErrors, PendingRebootProbeError{
			Source:  PendingRebootSourceUpdateExeVolatile,
			Code:    PendingRebootErrAccessDenied,
			Summary: "UpdateExeVolatile key probe failed",
		})
		return
	}
	defer k.Close()

	flags, _, err := k.GetIntegerValue("Flags")
	if errors.Is(err, winreg.ErrNotExist) {
		// Key exists, but no Flags DWORD: not a positive reboot
		// signal.
		return
	}
	if err != nil {
		result.ProbeErrors = append(result.ProbeErrors, PendingRebootProbeError{
			Source:  PendingRebootSourceUpdateExeVolatile,
			Code:    PendingRebootErrValueTypeMismatch,
			Summary: "UpdateExeVolatile Flags is not a REG_DWORD",
		})
		return
	}
	if flags != 0 {
		result.Signals.UpdateExeVolatile = true
	}
}

// checkNetlogonJoinPending detects an in-flight domain join via the
// Netlogon JoinDomain / AvoidSpnSet markers.
func (pendingRebootProber) checkNetlogonJoinPending(_ context.Context, result *PendingRebootResult) {
	const path = `SYSTEM\CurrentControlSet\Services\Netlogon`
	k, err := winreg.OpenKey(winreg.LOCAL_MACHINE, path, winreg.QUERY_VALUE)
	if err != nil {
		if errors.Is(err, winreg.ErrNotExist) {
			return
		}
		result.ProbeErrors = append(result.ProbeErrors, PendingRebootProbeError{
			Source:  PendingRebootSourceNetlogonJoinPending,
			Code:    PendingRebootErrAccessDenied,
			Summary: "Netlogon services key probe failed",
		})
		return
	}
	defer k.Close()

	for _, value := range []string{"JoinDomain", "AvoidSpnSet"} {
		_, _, err := k.GetValue(value, nil)
		if err == nil {
			result.Signals.NetlogonJoinPending = true
			return
		}
		if errors.Is(err, winreg.ErrNotExist) {
			continue
		}
		// Any other error path: surface a probe error and stop.
		result.ProbeErrors = append(result.ProbeErrors, PendingRebootProbeError{
			Source:  PendingRebootSourceNetlogonJoinPending,
			Code:    PendingRebootErrAccessDenied,
			Summary: "Netlogon value probe failed",
		})
		return
	}
}

// ────────────────────────────────────────────────────────────────
// Helpers

// keyExistsWow64 opens a HKLM subkey under the 64-bit registry view
// (WOW64_64KEY). Returns:
//   - (true, nil) if the key opens
//   - (false, nil) if the key is missing (ErrNotExist)
//   - (false, err) on any other failure (access denied, registry
//     hive unavailable, etc.) — the caller surfaces this as a probe
//     error so probeComplete=false.
func keyExistsWow64(root winreg.Key, path string) (bool, error) {
	k, err := winreg.OpenKey(root, path, winreg.QUERY_VALUE|winreg.WOW64_64KEY)
	if err == nil {
		k.Close()
		return true, nil
	}
	if errors.Is(err, winreg.ErrNotExist) {
		return false, nil
	}
	return false, err
}

// hasNonEmptyEntry returns true if the slice contains at least one
// non-blank entry. Entries are trimmed before the check so a
// single whitespace string does not flip the signal to true.
func hasNonEmptyEntry(values []string) bool {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return true
		}
	}
	return false
}

// readComputerName opens HKLM\SYSTEM\CurrentControlSet\Control\
// ComputerName\<sub> and reads the ComputerName REG_SZ value.
// SYSTEM hive paths are NOT subject to the SOFTWARE WOW64 redirect,
// so no WOW64_64KEY flag is needed.
func readComputerName(sub string) (string, error) {
	path := `SYSTEM\CurrentControlSet\Control\ComputerName\` + sub
	k, err := winreg.OpenKey(winreg.LOCAL_MACHINE, path, winreg.QUERY_VALUE)
	if err != nil {
		return "", err
	}
	defer k.Close()
	v, _, err := k.GetStringValue("ComputerName")
	if err != nil {
		return "", err
	}
	return v, nil
}

// equalComputerName performs the case-insensitive + trim-normalized
// comparison documented in §6.2.B of COMMAND-CONTRACT.md. Returns
// true when the two names are functionally the same.
func equalComputerName(a, b string) bool {
	return strings.EqualFold(strings.TrimSpace(a), strings.TrimSpace(b))
}
