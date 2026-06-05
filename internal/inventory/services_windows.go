//go:build windows

package inventory

import (
	"context"
	"errors"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

// servicesQueryAccess is the MINIMAL, read-only per-service SCM access mask
// the probe requests on each OpenService. It is deliberately NOT
// windows.SERVICE_ALL_ACCESS (which mgr.Mgr.OpenService hard-codes).
//
// AG-039 fix (Codex 019e950c iter-1 absorb): SERVICE_ALL_ACCESS bundles
// STANDARD_RIGHTS_REQUIRED (DELETE | WRITE_DAC | WRITE_OWNER) plus
// SERVICE_CHANGE_CONFIG / SERVICE_STOP / SERVICE_START / SERVICE_PAUSE_CONTINUE
// — write/control rights that a protected/hardened service DACL (Microsoft
// Defender's WinDefend, Windows Firewall's MpsSvc) denies even to LocalSystem.
// OpenService then returns ERROR_ACCESS_DENIED, the per-service path emits
// SERVICE_QUERY_FAILED, ProbeComplete flips false, and the endpoint-admin
// "Hizmetler" table is hidden — the symptom this fix removes.
//
// The probe only ever READS state:
//   - SERVICE_QUERY_STATUS → service.Query()  (run-state)
//   - SERVICE_QUERY_CONFIG → service.Config() (StartType → StartupMode,
//     including the DISABLED ops signal and DelayedAutoStart disambiguation)
//
// Both are read-only rights a protected service grants to LocalSystem, so
// WinDefend/MpsSvc open successfully and the probe completes. SERVICE_QUERY_CONFIG
// is retained (NOT dropped to QUERY_STATUS-only): DISABLED detection derives
// from Config().StartType, so dropping it would re-introduce a config-read
// SERVICE_QUERY_FAILED and keep ProbeComplete=false. We do NOT silently swallow
// a config-read failure (that would weaken the fail-closed evidence contract,
// Codex 019e950c iter-1 #3); the correct posture is to request the access the
// read genuinely needs.
const servicesQueryAccess = windows.SERVICE_QUERY_STATUS | windows.SERVICE_QUERY_CONFIG

// scmConnectAccess is the MINIMAL Service Control Manager access needed to
// open service handles by name. mgr.Connect hard-codes SC_MANAGER_ALL_ACCESS
// (admin-only, over-broad for a read-only probe); SC_MANAGER_CONNECT is
// sufficient for OpenService and is the least-privilege right
// (Codex 019e950c iter-1 #5 absorb).
const scmConnectAccess = windows.SC_MANAGER_CONNECT

// connectSCMReadOnly opens a least-privilege (SC_MANAGER_CONNECT) handle to
// the local Service Control Manager. It replaces mgr.Connect, which requests
// SC_MANAGER_ALL_ACCESS. The probe never enumerates or mutates the SCM
// database — it only opens named services for query — so SC_MANAGER_CONNECT
// is the minimal sufficient right. The returned *mgr.Mgr drives
// scmManager.Disconnect() exactly as a mgr.Connect() result would (Handle is
// the only field; exported in x/sys/windows/svc/mgr).
func connectSCMReadOnly() (*mgr.Mgr, error) {
	h, err := windows.OpenSCManager(nil, nil, scmConnectAccess)
	if err != nil {
		return nil, err
	}
	return &mgr.Mgr{Handle: h}, nil
}

// openServiceQueryOnly opens a single service handle with the minimal
// read-only servicesQueryAccess mask. mgr.Mgr.OpenService cannot be used
// because it hard-codes SERVICE_ALL_ACCESS (see servicesQueryAccess); we
// replicate its trivial body with the narrower mask. The returned
// *mgr.Service drives service.Config()/Query()/Close() exactly as a
// mgr.OpenService result would (Name + Handle are the only fields; both
// exported in x/sys/windows/svc/mgr).
func openServiceQueryOnly(scmManager *mgr.Mgr, name string) (*mgr.Service, error) {
	namePtr, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return nil, err
	}
	h, err := windows.OpenService(scmManager.Handle, namePtr, servicesQueryAccess)
	if err != nil {
		return nil, err
	}
	return &mgr.Service{Name: name, Handle: h}, nil
}

// probeAggregate is the channel payload from the SCM/registry worker.
type probeAggregate struct {
	entries     []ServiceEntry
	probeErrors []ServicesProbeError
}

// ProbeServices is the Windows SCM + registry implementation. Codex
// 019e8302 iter-2 implementation note absorb: no PowerShell — direct
// `svc/mgr` SCM enumeration + `mgr.Config.DelayedAutoStart` field for
// AUTO_DELAYED disambiguation (Codex iter-4 non-blocker absorb:
// registry-read fallback secondary, primary uses the Win32
// SERVICE_DELAYED_AUTO_START_INFO field already surfaced by x/sys/windows/svc/mgr).
//
// Codex 019e8302 iter-3 P1 #3 + iter-4 P1 absorb: ProbeServices owns
// its own ServicesProbeTimeout bounded context AND runs the blocking
// SCM/registry work in a background goroutine so the contract is
// actually enforced (Win32 svc.mgr / OpenService / Config / Query
// calls do NOT accept context). A timeout-fired result returns
// supported=true + empty services + NO_EVIDENCE probe error +
// probeComplete=false. The orphan goroutine is allowed to drain its
// own SCM work and exit naturally; we never hold references that
// would leak.
func ProbeServices(ctx context.Context, now func() time.Time) ServicesResult {
	if now == nil {
		now = time.Now
	}
	startedAt := now()

	// Bounded context — Codex 019e8302 iter-3 P1 #3 absorb.
	probeCtx, cancel := context.WithTimeout(ctx, ServicesProbeTimeout)
	defer cancel()

	done := make(chan probeAggregate, 1)
	go func() {
		done <- runServicesProbeBlocking()
	}()

	select {
	case agg := <-done:
		return orchestrateServicesProbe(
			probeCtx, now, true, agg.entries, agg.probeErrors, startedAt,
		)
	case <-probeCtx.Done():
		// Timeout / caller cancel — Codex iter-4 P1 absorb: the worker
		// may still be blocked in mgr.Connect()/OpenService(); we
		// abandon it (goroutine drains itself) and return fail-closed
		// no-evidence shape rather than waiting indefinitely.
		return orchestrateServicesProbe(
			probeCtx, now, true,
			[]ServiceEntry{},
			[]ServicesProbeError{{
				Code:    ServicesErrNoEvidence,
				Summary: "Service probe deadline exceeded",
			}},
			startedAt,
		)
	}
}

// runServicesProbeBlocking is the synchronous SCM/registry enumeration
// body. Returns the (entries, probeErrors) aggregate so the caller can
// flow it through the deterministic post-projection. The Windows SCM
// API does NOT accept a context.Context, so this function blocks
// natively — the timeout is enforced at the ProbeServices select
// boundary above (Codex iter-4 P1 absorb).
func runServicesProbeBlocking() probeAggregate {
	scmManager, err := connectSCMReadOnly()
	if err != nil {
		// SCM unreachable globally — entire probe fails closed.
		// Codex 019e8302 iter-2 #2 absorb: don't all-UNKNOWN every
		// service (would imply "services exist but query failed");
		// emit empty services + SCM_UNAVAILABLE error so the consumer
		// sees the global failure shape.
		return probeAggregate{
			entries: []ServiceEntry{},
			probeErrors: []ServicesProbeError{{
				Code:    ServicesErrSCMUnavailable,
				Summary: "Service Control Manager connection failed",
			}},
		}
	}
	defer scmManager.Disconnect()

	entries := make([]ServiceEntry, 0, len(CanonicalServiceAllowlist))
	var probeErrors []ServicesProbeError
	for _, name := range CanonicalServiceAllowlist {
		entry, perServiceErr := probeOneService(scmManager, name)
		if perServiceErr != nil {
			probeErrors = append(probeErrors, *perServiceErr)
		}
		entries = append(entries, entry)
	}
	return probeAggregate{entries: entries, probeErrors: probeErrors}
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

	service, err := openServiceQueryOnly(scmManager, name)
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
	//
	// Codex iter-4 non-blocker absorb: mgr.Config.DelayedAutoStart
	// is the authoritative SERVICE_DELAYED_AUTO_START_INFO field
	// from the Win32 SCM API. We pass it directly to mapStartupMode
	// rather than reading the HKLM\...\<name>\DelayedAutoStart
	// registry key (which can be unreadable even when SCM has the
	// flag set, leading to a false AUTO instead of AUTO_DELAYED).
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
		entry.StartupMode = mapStartupMode(config.StartType, config.DelayedAutoStart)
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

// mapStartupMode maps SCM StartType + DelayedAutoStart to the wire
// enum. Codex 019e8302 iter-2 #3 + iter-4 non-blocker absorb:
//   - StartType=2 (SERVICE_AUTO_START) + DelayedAutoStart=true → AUTO_DELAYED
//   - StartType=2 + DelayedAutoStart=false → AUTO
//   - StartType=3 → MANUAL; 4 → DISABLED; other → UNKNOWN
//
// DelayedAutoStart is the authoritative Win32
// SERVICE_DELAYED_AUTO_START_INFO field surfaced by mgr.Config;
// reading the HKLM\...\DelayedAutoStart registry key would be a
// secondary fallback and can disagree with SCM (registry-unreadable
// would falsely report AUTO).
func mapStartupMode(startType uint32, delayedAutoStart bool) StartupMode {
	switch startType {
	case uint32(mgr.StartAutomatic):
		if delayedAutoStart {
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
