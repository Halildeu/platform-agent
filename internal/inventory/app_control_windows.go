//go:build windows

package inventory

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

// AG-041 Windows implementation — registry + bounded filesystem reads
// per Codex 019e83ce iter-2 finalisation. NO PowerShell, NO CIM/WMI,
// NO event log, NO process enumeration, NO `Get-AppLockerPolicy`.
//
// Sub-probes (all bounded, fail-closed):
//   1. WDAC facet  — registry scalars under HKLM\SYSTEM CI + filesystem
//                    metadata (CIPolicies\Active dir read + SIPolicy.p7b
//                    stat). Mode UNKNOWN dominant per iter-1 P0 #2.
//   2. AppLocker facet — registry DWORDs under HKLM\SOFTWARE\Policies\
//                        Microsoft\Windows\SrpV2\<collection>\
//                        EnforcementMode + AppIDSvc SCM query.
//
// Each sub-probe is independent; one facet failing flips that facet's
// queryable flag but does NOT abort the other. Decision-critical reads
// (CI\Policy / CI\Config primary keys; SrpV2 root) flip probeComplete
// to false when they fail.

// wdacCiConfigPath is the candidate registry path the agent attempts.
// Codex 019e83ce iter-1 P0 #2 + iter-2 absorb: there is NO confirmed
// universal canonical scalar for AUDIT/ENFORCE without WMI/CIM. v1
// implementation leaves ExplicitAudit/ExplicitEnforce at nil (Mode
// derivation yields UNKNOWN dominant). When a future version-confirmed
// scalar is identified, this is where it would be read.
const (
	wdacCiPolicyKeyPath = `SYSTEM\CurrentControlSet\Control\CI\Policy`
	wdacCiConfigKeyPath = `SYSTEM\CurrentControlSet\Control\CI\Config`
	wdacDeviceGuardPath = `SYSTEM\CurrentControlSet\Control\DeviceGuard`

	// Filesystem locations — read directly (no policy file content).
	wdacCipPoliciesActiveDir = `C:\Windows\System32\CodeIntegrity\CIPolicies\Active`
	wdacLegacySipolicyPath   = `C:\Windows\System32\CodeIntegrity\SIPolicy.p7b`

	// AppLocker SrpV2 root + per-collection EnforcementMode value name.
	appLockerSrpV2Root        = `SOFTWARE\Policies\Microsoft\Windows\SrpV2`
	appLockerEnforcementMode  = "EnforcementMode"
	appLockerAppIdSvcName     = "AppIDSvc"
)

var appLockerCollections = []struct {
	name    string
	keyPath string
}{
	{"Exe", appLockerSrpV2Root + `\Exe`},
	{"Dll", appLockerSrpV2Root + `\Dll`},
	{"Script", appLockerSrpV2Root + `\Script`},
	{"Msi", appLockerSrpV2Root + `\Msi`},
	{"Appx", appLockerSrpV2Root + `\Appx`},
}

// probeAppControlImpl is the Windows entry-point. Caller (ProbeAppControl
// in app_control.go) wraps it for SchemaVersion + ProbeDurationMs +
// ProbeErrors-nil-to-empty post-processing.
func probeAppControlImpl(ctx context.Context, now func() time.Time) AppControlResult {
	result := AppControlResult{
		Supported:   true,
		ProbeErrors: []AppControlProbeError{},
	}

	// Codex 019e83ce iter-3 P1 #5 absorb: the context is bounded with
	// AppControlProbeTimeout but registry / filesystem / SCM Win32 APIs
	// are synchronous and do NOT honour `ctx.Done()`. The timeout is
	// best-effort: a hung Win32 call will still complete on its own;
	// the context only short-circuits derivations between calls.
	// Documented as a known limitation; tightening to a goroutine +
	// select-based hard kill is a separate follow-up. v1 acceptable
	// because registry/filesystem reads are sub-millisecond in
	// practice and we have aggressive cap-16 probe-error bounding.
	ctx, cancel := context.WithTimeout(ctx, AppControlProbeTimeout)
	defer cancel()

	// Run sub-probes in sequence (registry is fast; concurrent reads
	// gain little vs. the complexity of synchronising the result struct).
	wdacEvidence, wdacErrs := probeWdacFacet(ctx)
	appLockerProbe, appLockerErrs := probeAppLockerFacet(ctx)

	// WDAC facet projection
	result.WdacQueryable = wdacEvidence.Queryable
	result.WdacMode = DeriveWdacMode(wdacEvidence)
	result.WdacBootEnforcementPresent = wdacEvidence.BootEnforcementPresent
	result.WdacActiveCipPolicyCount = wdacEvidence.ActiveCipPolicyCount
	result.WdacLegacySipolicyPresent = wdacEvidence.LegacySipolicyPresent
	result.WdacMultiPolicyMode = wdacEvidence.MultiPolicyMode

	// AppLocker facet projection
	result.AppLockerQueryable = appLockerProbe.Queryable
	result.AppLockerExeRule = appLockerProbe.ExeRule
	result.AppLockerDllRule = appLockerProbe.DllRule
	result.AppLockerScriptRule = appLockerProbe.ScriptRule
	result.AppLockerMsiRule = appLockerProbe.MsiRule
	result.AppLockerAppxRule = appLockerProbe.AppxRule
	result.AppLockerAppIdSvcState = appLockerProbe.AppIdSvcState
	result.AppLockerAppIdSvcStartup = appLockerProbe.AppIdSvcStartup
	result.AppLockerAppIdSvcPresent = appLockerProbe.AppIdSvcPresent

	// Aggregate probe errors with cap + truncation marker.
	for _, e := range wdacErrs {
		result.ProbeErrors = AppendProbeError(result.ProbeErrors, e)
	}
	for _, e := range appLockerErrs {
		result.ProbeErrors = AppendProbeError(result.ProbeErrors, e)
	}

	// ProbeComplete = both facets queryable AND no decision-critical
	// read failed. A facet returning UNKNOWN scalars while queryable=true
	// counts as "evidence collected" — completeness is about whether the
	// PROBE attempted everything, not whether the operator policy is
	// well-defined.
	result.ProbeComplete = wdacEvidence.Queryable &&
		!wdacEvidence.DecisionCriticalReadFailed &&
		appLockerProbe.Queryable &&
		!appLockerProbe.DecisionCriticalReadFailed

	_ = now // duration is captured by the orchestrator; kept here for signature parity
	return result
}

// probeWdacFacet attempts registry + filesystem reads, populating the
// internal WdacEvidence struct. Returns evidence + bounded probe errors.
func probeWdacFacet(ctx context.Context) (WdacEvidence, []AppControlProbeError) {
	var errs []AppControlProbeError
	ev := WdacEvidence{Queryable: true}

	// CI\Policy primary key — decision-critical; failure flips
	// DecisionCriticalReadFailed.
	policyKey, err := registry.OpenKey(registry.LOCAL_MACHINE, wdacCiPolicyKeyPath, registry.QUERY_VALUE|registry.READ)
	if err != nil {
		if !errors.Is(err, registry.ErrNotExist) {
			ev.DecisionCriticalReadFailed = true
			errs = append(errs, AppControlProbeError{
				Code:    AppControlErrRegistryDenied,
				Source:  errSourcePtr(AppControlProbeErrSourceWdac),
				Summary: appControlSummaryPtr(boundAppControlSummary("CI\\Policy registry key unreadable: " + err.Error())),
			})
		}
	} else {
		_ = policyKey.Close()
	}

	// CI\Config primary key — decision-critical; failure flips
	// DecisionCriticalReadFailed.
	configKey, err := registry.OpenKey(registry.LOCAL_MACHINE, wdacCiConfigKeyPath, registry.QUERY_VALUE|registry.READ)
	if err != nil {
		if !errors.Is(err, registry.ErrNotExist) {
			ev.DecisionCriticalReadFailed = true
			errs = append(errs, AppControlProbeError{
				Code:    AppControlErrRegistryDenied,
				Source:  errSourcePtr(AppControlProbeErrSourceWdac),
				Summary: appControlSummaryPtr(boundAppControlSummary("CI\\Config registry key unreadable: " + err.Error())),
			})
		}
	} else {
		_ = configKey.Close()
	}

	// DeviceGuard\AvailableSecurityProperties — REG_MULTI_SZ capability
	// evidence (Codex 019e83ce iter-3 P0 #2 absorb: switched from
	// GetIntegerValue, which would have always failed with
	// ErrUnexpectedType and falsely emitted BootEnforcementPresent=false).
	// Non-empty array → capability is exposed.
	dgKey, err := registry.OpenKey(registry.LOCAL_MACHINE, wdacDeviceGuardPath, registry.QUERY_VALUE|registry.READ)
	if err == nil {
		vals, _, valErr := dgKey.GetStringsValue("AvailableSecurityProperties")
		_ = dgKey.Close()
		if valErr == nil {
			t := len(vals) > 0
			ev.BootEnforcementPresent = &t
		}
		// valErr (incl. ErrUnexpectedType / ErrNotExist on value) → keep
		// BootEnforcementPresent=nil (explicit unknown). Codex iter-3 P0
		// #2: do NOT emit `false` on read failure — that would be
		// false-negative evidence.
	} else if !errors.Is(err, registry.ErrNotExist) {
		errs = append(errs, AppControlProbeError{
			Code:    AppControlErrWdacScalarUnreadable,
			Source:  errSourcePtr(AppControlProbeErrSourceWdac),
			Summary: appControlSummaryPtr(boundAppControlSummary("DeviceGuard scalar unreadable: " + err.Error())),
		})
	}

	// MultiPolicyMode — Codex 019e83ce iter-3 P1 #6 absorb: proxy from
	// BootEnforcementPresent REMOVED. Without a confirmed dedicated
	// scalar, MultiPolicyMode stays `nil` (explicit unknown) rather
	// than mirroring capability evidence. Future iter that identifies
	// a real multi-policy scalar can populate this without contract
	// changes.
	// ev.MultiPolicyMode = nil  // (implicit zero value)

	// Filesystem evidence: CIPolicies\Active directory + SIPolicy.p7b
	// stat. Bounded — no file names, GUIDs, hashes leak to the wire.
	cipCount, cipErr := probeCipPoliciesActiveCount(ctx)
	ev.ActiveCipPolicyCount = cipCount
	if cipErr != nil {
		errs = append(errs, AppControlProbeError{
			Code:    AppControlErrCipPoliciesDirUnreadable,
			Source:  errSourcePtr(AppControlProbeErrSourceFilesystem),
			Summary: appControlSummaryPtr(boundAppControlSummary(cipErr.Error())),
		})
	}

	legacyPresent, legacyErr := probeSipolicyPresence()
	ev.LegacySipolicyPresent = legacyPresent
	if legacyErr != nil {
		errs = append(errs, AppControlProbeError{
			Code:    AppControlErrFilesystemDenied,
			Source:  errSourcePtr(AppControlProbeErrSourceFilesystem),
			Summary: appControlSummaryPtr(boundAppControlSummary(legacyErr.Error())),
		})
	}

	return ev, errs
}

func probeCipPoliciesActiveCount(_ context.Context) (*int, error) {
	entries, err := os.ReadDir(wdacCipPoliciesActiveDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			zero := 0
			return &zero, nil
		}
		return nil, fmt.Errorf("CIPolicies\\Active dir read failed: %w", err)
	}
	count := 0
	for _, ent := range entries {
		if ent.IsDir() {
			continue
		}
		// Codex 019e83ce iter-3 risk-area #1 absorb: EqualFold for case-
		// insensitive .cip / .CIP / .Cip match (Windows filesystem is
		// case-insensitive by default; defensive).
		if strings.EqualFold(filepath.Ext(ent.Name()), ".cip") {
			count++
		}
	}
	return &count, nil
}

func probeSipolicyPresence() (*bool, error) {
	info, err := os.Stat(wdacLegacySipolicyPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			f := false
			return &f, nil
		}
		return nil, fmt.Errorf("SIPolicy.p7b stat failed: %w", err)
	}
	present := info.Size() > 0
	return &present, nil
}

// appLockerProbeResult is the internal aggregation; projected into
// AppControlResult by the caller.
type appLockerProbeResult struct {
	Queryable                  bool
	DecisionCriticalReadFailed bool
	ExeRule                    AppLockerEnforcementMode
	DllRule                    AppLockerEnforcementMode
	ScriptRule                 AppLockerEnforcementMode
	MsiRule                    AppLockerEnforcementMode
	AppxRule                   AppLockerEnforcementMode
	AppIdSvcState              ServiceState
	AppIdSvcStartup            StartupMode
	AppIdSvcPresent            *bool
}

func probeAppLockerFacet(ctx context.Context) (appLockerProbeResult, []AppControlProbeError) {
	var errs []AppControlProbeError
	r := appLockerProbeResult{
		Queryable:       true,
		ExeRule:         AppLockerUnknown,
		DllRule:         AppLockerUnknown,
		ScriptRule:      AppLockerUnknown,
		MsiRule:         AppLockerUnknown,
		AppxRule:        AppLockerUnknown,
		AppIdSvcState:   ServiceStateUnknown,
		AppIdSvcStartup: StartupModeUnknown,
	}

	// SrpV2 root — decision-critical for "AppLocker present at all".
	rootKey, err := registry.OpenKey(registry.LOCAL_MACHINE, appLockerSrpV2Root, registry.QUERY_VALUE|registry.READ)
	if err != nil {
		if errors.Is(err, registry.ErrNotExist) {
			// SrpV2 root absent → all collections NOT_CONFIGURED.
			// Queryable stays true; this IS a legitimate read result.
			r.ExeRule = AppLockerNotConfigured
			r.DllRule = AppLockerNotConfigured
			r.ScriptRule = AppLockerNotConfigured
			r.MsiRule = AppLockerNotConfigured
			r.AppxRule = AppLockerNotConfigured
		} else {
			r.DecisionCriticalReadFailed = true
			errs = append(errs, AppControlProbeError{
				Code:    AppControlErrRegistryDenied,
				Source:  errSourcePtr(AppControlProbeErrSourceAppLocker),
				Summary: appControlSummaryPtr(boundAppControlSummary("SrpV2 root unreadable: " + err.Error())),
			})
		}
	} else {
		_ = rootKey.Close()

		// Per-collection read (Codex iter-1 P1 #5 + iter-3 P1 #4 strict
		// mapping + REGISTRY_DENIED vs APPLOCKER_KEY_UNREADABLE
		// distinction).
		for _, c := range appLockerCollections {
			res, readErr := readAppLockerCollectionMode(c.keyPath)
			switch c.name {
			case "Exe":
				r.ExeRule = res.Mode
			case "Dll":
				r.DllRule = res.Mode
			case "Script":
				r.ScriptRule = res.Mode
			case "Msi":
				r.MsiRule = res.Mode
			case "Appx":
				r.AppxRule = res.Mode
			}
			if res.ErrorCode != "" {
				summary := c.name
				if readErr != nil {
					summary = c.name + ": " + readErr.Error()
				}
				errs = append(errs, AppControlProbeError{
					Code:    res.ErrorCode,
					Source:  errSourcePtr(AppControlProbeErrSourceAppLocker),
					Summary: appControlSummaryPtr(boundAppControlSummary(summary)),
				})
			}
		}
	}

	// AppIDSvc SCM query — reuses the AG-039 service-state helper
	// pattern (no PowerShell). Service not present = AppIdSvcPresent=false +
	// state/startup UNKNOWN.
	state, startup, present, svcErr := queryAppIdSvcWindows(ctx)
	r.AppIdSvcState = state
	r.AppIdSvcStartup = startup
	r.AppIdSvcPresent = present
	if svcErr != nil {
		errs = append(errs, AppControlProbeError{
			Code:    AppControlErrAppIdSvcQueryFailed,
			Source:  errSourcePtr(AppControlProbeErrSourceAppLocker),
			Summary: appControlSummaryPtr(boundAppControlSummary(svcErr.Error())),
		})
	}

	return r, errs
}

// readAppLockerCollectionMode dispatches the registry read to the pure
// MapAppLockerDword helper (cross-platform-testable). Codex 019e83ce
// iter-3 P1 #4 absorb: error-code emission now distinguishes
// REGISTRY_DENIED (permission-denied) from APPLOCKER_KEY_UNREADABLE
// (wrong-type / unexpected-DWORD / corrupt). Returns the strict
// AppLockerReadResult so the caller can attach the appropriate
// probe-error code.
func readAppLockerCollectionMode(keyPath string) (AppLockerReadResult, error) {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, keyPath, registry.QUERY_VALUE|registry.READ)
	if err != nil {
		if errors.Is(err, registry.ErrNotExist) {
			return MapAppLockerDword(AppLockerReadKeyAbsent, 0), nil
		}
		if errors.Is(err, syscall.ERROR_ACCESS_DENIED) {
			return MapAppLockerDword(AppLockerReadPermissionDenied, 0), err
		}
		return MapAppLockerDword(AppLockerReadOtherFailure, 0), fmt.Errorf("key open failed: %w", err)
	}
	defer key.Close()

	val, valType, err := key.GetIntegerValue(appLockerEnforcementMode)
	if err != nil {
		if errors.Is(err, registry.ErrNotExist) {
			return MapAppLockerDword(AppLockerReadKeyAbsent, 0), nil
		}
		if errors.Is(err, syscall.ERROR_ACCESS_DENIED) {
			return MapAppLockerDword(AppLockerReadPermissionDenied, 0), err
		}
		return MapAppLockerDword(AppLockerReadOtherFailure, 0), fmt.Errorf("EnforcementMode read failed: %w", err)
	}
	if valType != registry.DWORD {
		return MapAppLockerDword(AppLockerReadWrongType, 0), fmt.Errorf("EnforcementMode wrong type: %d", valType)
	}
	return MapAppLockerDword(AppLockerReadDwordValue, val), nil
}

// queryAppIdSvcWindows reuses the SCM client established by AG-039
// services_windows.go. Returns shared ServiceState + StartupMode enums.
//
// Codex 019e83ce iter-3 P0 #3 absorb: error handling MUST distinguish
// "service-not-found" from "permission denied / RPC failure". AG-039
// uses `isServiceNotFound` (services_windows.go); we reuse the same
// helper here so the OpenService error chain is mapped identically:
//   - ERROR_SERVICE_DOES_NOT_EXIST → AppIdSvcPresent=false +
//     state/startup UNKNOWN + no probe error (legitimate observation)
//   - any other OpenService error → AppIdSvcPresent=nil (explicit
//     unknown — NOT false; we can't assert absence on permission denied)
//     + typed APP_ID_SVC_QUERY_FAILED error
//   - s.Query() / s.Config() failure on a present service → state /
//     startup stay UNKNOWN + typed error
func queryAppIdSvcWindows(_ context.Context) (ServiceState, StartupMode, *bool, error) {
	m, err := mgr.Connect()
	if err != nil {
		return ServiceStateUnknown, StartupModeUnknown, nil, fmt.Errorf("SCM connect failed: %w", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(appLockerAppIdSvcName)
	if err != nil {
		if isServiceNotFound(err) {
			notPresent := false
			return ServiceStateUnknown, StartupModeUnknown, &notPresent, nil
		}
		// Permission denied / RPC failure / other error — present-ness
		// undetermined. Return nil pointer + typed error so the
		// orchestrator emits APP_ID_SVC_QUERY_FAILED.
		return ServiceStateUnknown, StartupModeUnknown, nil, fmt.Errorf("OpenService(AppIDSvc) failed: %w", err)
	}
	defer s.Close()

	present := true
	state := ServiceStateUnknown
	startup := StartupModeUnknown
	var queryErr, configErr error

	if status, err := s.Query(); err == nil {
		switch status.State {
		case svc.Running:
			state = ServiceStateRunning
		case svc.Stopped:
			state = ServiceStateStopped
		}
	} else {
		queryErr = err
	}

	if cfg, err := s.Config(); err == nil {
		switch cfg.StartType {
		case mgr.StartAutomatic:
			if cfg.DelayedAutoStart {
				startup = StartupModeAutoDelayed
			} else {
				startup = StartupModeAuto
			}
		case mgr.StartManual:
			startup = StartupModeManual
		case mgr.StartDisabled:
			startup = StartupModeDisabled
		}
	} else {
		configErr = err
	}

	if queryErr != nil || configErr != nil {
		return state, startup, &present, fmt.Errorf("AppIDSvc query partial failure: query=%v config=%v", queryErr, configErr)
	}
	return state, startup, &present, nil
}

// boundSummary trims to ≤200 chars + strips CR/LF.
func boundAppControlSummary(s string) string {
	const cap = 200
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '\r' || s[i] == '\n' {
			out = append(out, ' ')
			continue
		}
		out = append(out, s[i])
	}
	if len(out) > cap {
		out = out[:cap]
	}
	return string(out)
}
