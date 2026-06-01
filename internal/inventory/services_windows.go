//go:build windows

package inventory

import (
	"context"
	"errors"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

// ProbeServices is the Windows SCM + registry implementation. Codex
// 019e8302 iter-2 implementation note absorb: no PowerShell — direct
// `svc/mgr` SCM enumeration + `HKLM\SYSTEM\CurrentControlSet\Services\
// <name>\DelayedAutoStart` registry read for AUTO_DELAYED disambiguation.
//
// Codex 019e8302 iter-3 P1 #3 absorb: ProbeServices owns its own
// ServicesProbeTimeout bounded context so SCM enumeration cannot block
// the heartbeat / inventory loop beyond the contract. Caller deadlines
// still narrow the effective deadline via context.WithTimeout
// propagation.
func ProbeServices(ctx context.Context, now func() time.Time) ServicesResult {
	if now == nil {
		now = time.Now
	}
	startedAt := now()

	// Bounded context — Codex 019e8302 iter-3 P1 #3 absorb.
	probeCtx, cancel := context.WithTimeout(ctx, ServicesProbeTimeout)
	defer cancel()

	var probeErrors []ServicesProbeError
	entries := make([]ServiceEntry, 0, len(CanonicalServiceAllowlist))

	scmManager, err := mgr.Connect()
	if err != nil {
		// SCM unreachable globally — entire probe fails closed.
		// Codex 019e8302 iter-2 #2 absorb: don't all-UNKNOWN every
		// service (would imply "services exist but query failed");
		// emit empty services + SCM_UNAVAILABLE error so the consumer
		// sees the global failure shape.
		return orchestrateServicesProbe(
			probeCtx,
			now,
			true, // supported (Windows present), probe incomplete
			[]ServiceEntry{},
			[]ServicesProbeError{{
				Code:    ServicesErrSCMUnavailable,
				Summary: "Service Control Manager connection failed",
			}},
			startedAt,
		)
	}
	defer scmManager.Disconnect()

	for _, name := range CanonicalServiceAllowlist {
		select {
		case <-probeCtx.Done():
			probeErrors = append(probeErrors, ServicesProbeError{
				Code:        ServicesErrNoEvidence,
				ServiceName: name,
				Summary:     "Probe deadline exceeded mid-enumeration",
			})
			continue
		default:
		}
		entry, perServiceErr := probeOneService(scmManager, name)
		if perServiceErr != nil {
			probeErrors = append(probeErrors, *perServiceErr)
		}
		entries = append(entries, entry)
	}

	return orchestrateServicesProbe(
		probeCtx, now, true, entries, probeErrors, startedAt,
	)
}

// probeOneService reads the SCM service config + registry DelayedAutoStart
// for a single allowlisted service. Returns (entry, optional-probe-error).
// The entry is always populated (Name + Present + State + StartupMode) so
// the wire shape carries every allowlist member; per-service failures
// emit a typed probe-error WITHOUT corrupting the entry list.
func probeOneService(
	scmManager *mgr.Mgr, name string,
) (ServiceEntry, *ServicesProbeError) {
	entry := ServiceEntry{
		Name:        name,
		Present:     false,
		State:       ServiceStateUnknown,
		StartupMode: StartupModeUnknown,
	}

	service, err := scmManager.OpenService(name)
	if err != nil {
		// ERROR_SERVICE_DOES_NOT_EXIST is the "service not installed"
		// case (Codex 019e8302 iter-2 #4 absorb): emit Present=false,
		// no probe error (this is the canonical absent-from-SCM shape).
		if isServiceNotFound(err) {
			return entry, nil
		}
		// Any other OpenService error is a real per-service query
		// failure (access denied / RPC error / etc.) → present=true
		// assumed (service exists but unreadable), state/startup
		// UNKNOWN, typed probe error emitted.
		entry.Present = true
		return entry, &ServicesProbeError{
			Code:        ServicesErrServiceQueryFailed,
			ServiceName: name,
			Summary:     "Service open failed",
		}
	}
	defer service.Close()
	entry.Present = true

	// Service config (StartType + recovery actions etc.).
	// Codex 019e8302 iter-3 P1 #2 absorb: config + query errors emit
	// SERVICE_QUERY_FAILED probe error AND leave UNKNOWN values, so
	// ProbeComplete fails closed instead of false-true.
	var emitErr *ServicesProbeError
	config, configErr := service.Config()
	if configErr != nil {
		entry.StartupMode = StartupModeUnknown
		emitErr = &ServicesProbeError{
			Code:        ServicesErrServiceQueryFailed,
			ServiceName: name,
			Summary:     "Service config read failed",
		}
	} else {
		entry.StartupMode = mapStartupMode(name, config.StartType)
	}

	// Runtime state.
	status, statusErr := service.Query()
	if statusErr != nil {
		// Already emitting config error; this is a second failure on
		// the same service. Keep the first error code (don't multiply
		// probe errors per-service); state stays UNKNOWN.
		if emitErr == nil {
			emitErr = &ServicesProbeError{
				Code:        ServicesErrServiceQueryFailed,
				ServiceName: name,
				Summary:     "Service status read failed",
			}
		}
	} else {
		entry.State = mapServiceState(status.State)
	}

	return entry, emitErr
}

// mapServiceState converts a Win32 SERVICE_STATUS_PROCESS state code into
// the bounded wire enum. Codex 019e8302 iter-2 #4 absorb: paused / pending
// transitions are deliberately UNKNOWN (not collapsed into STOPPED) — v1
// honesty over false certainty.
func mapServiceState(state svc.State) ServiceState {
	switch state {
	case svc.Running:
		return ServiceStateRunning
	case svc.Stopped:
		return ServiceStateStopped
	default:
		return ServiceStateUnknown
	}
}

// mapStartupMode reads SCM StartType + (when StartType==AUTO) the
// registry DelayedAutoStart flag to disambiguate AUTO vs AUTO_DELAYED.
// Codex 019e8302 iter-2 #3 absorb:
//   - StartType=2 (SERVICE_AUTO_START) + DelayedAutoStart=1 → AUTO_DELAYED
//   - StartType=2 + DelayedAutoStart=0 or absent → AUTO
//   - StartType=3 → MANUAL; 4 → DISABLED; other → UNKNOWN
func mapStartupMode(serviceName string, startType uint32) StartupMode {
	switch startType {
	case uint32(mgr.StartAutomatic):
		if isDelayedAutoStart(serviceName) {
			return StartupModeAutoDelayed
		}
		return StartupModeAuto
	case uint32(mgr.StartManual):
		return StartupModeManual
	case uint32(mgr.StartDisabled):
		return StartupModeDisabled
	default:
		return StartupModeUnknown
	}
}

// isDelayedAutoStart reads HKLM\SYSTEM\CurrentControlSet\Services\<name>\
// DelayedAutoStart. Absent / unreadable / 0 → false; 1 → true. Per
// Microsoft service convention.
func isDelayedAutoStart(serviceName string) bool {
	keyPath := `SYSTEM\CurrentControlSet\Services\` + serviceName
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, keyPath, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	defer k.Close()
	val, _, err := k.GetIntegerValue("DelayedAutoStart")
	if err != nil {
		// ERROR_FILE_NOT_FOUND → DelayedAutoStart absent → not delayed.
		return false
	}
	return val == 1
}

// isServiceNotFound reports whether the OpenService error is the well-
// known "service does not exist" code (ERROR_SERVICE_DOES_NOT_EXIST =
// 0x424 = 1060). Codex 019e8302 iter-3 nit absorb: use numeric errno
// instead of locale-dependent string match. errors.Is walks the wrapped
// error chain and matches against the constant from
// golang.org/x/sys/windows.
func isServiceNotFound(err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST)
}
