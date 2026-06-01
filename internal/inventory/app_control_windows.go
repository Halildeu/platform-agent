//go:build windows

package inventory

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
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
				Summary: appControlSummaryPtr(boundSummary("CI\\Policy registry key unreadable: " + err.Error())),
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
				Summary: appControlSummaryPtr(boundSummary("CI\\Config registry key unreadable: " + err.Error())),
			})
		}
	} else {
		_ = configKey.Close()
	}

	// DeviceGuard\AvailableSecurityProperties bit — capability evidence
	// only (Codex iter-1 P1 #4 absorb: rename from "bootEnforcement").
	dgKey, err := registry.OpenKey(registry.LOCAL_MACHINE, wdacDeviceGuardPath, registry.QUERY_VALUE|registry.READ)
	if err == nil {
		// Read AvailableSecurityProperties REG_MULTI_SZ; presence of
		// any non-zero element implies the capability is exposed.
		// Failure → keep BootEnforcementPresent=nil (unknown evidence,
		// NOT a decision-critical failure).
		_, _, valErr := dgKey.GetIntegerValue("AvailableSecurityProperties")
		_ = dgKey.Close()
		if valErr == nil {
			t := true
			ev.BootEnforcementPresent = &t
		} else {
			f := false
			ev.BootEnforcementPresent = &f
		}
	} else if !errors.Is(err, registry.ErrNotExist) {
		errs = append(errs, AppControlProbeError{
			Code:    AppControlErrWdacScalarUnreadable,
			Source:  errSourcePtr(AppControlProbeErrSourceWdac),
			Summary: appControlSummaryPtr(boundSummary("DeviceGuard scalar unreadable: " + err.Error())),
		})
	}

	// Multi-policy mode bit — Windows 10 1903+ capability flag. Set
	// from BootEnforcementPresent for v1 (proxy). Future iter MAY
	// disambiguate via the explicit
	// `CI\Config\DeployedSupported` scalar if it lands in the
	// implementation-confirmed set.
	if ev.BootEnforcementPresent != nil {
		v := *ev.BootEnforcementPresent
		ev.MultiPolicyMode = &v
	}

	// Filesystem evidence: CIPolicies\Active directory + SIPolicy.p7b
	// stat. Bounded — no file names, GUIDs, hashes leak to the wire.
	cipCount, cipErr := probeCipPoliciesActiveCount(ctx)
	ev.ActiveCipPolicyCount = cipCount
	if cipErr != nil {
		errs = append(errs, AppControlProbeError{
			Code:    AppControlErrCipPoliciesDirUnreadable,
			Source:  errSourcePtr(AppControlProbeErrSourceFilesystem),
			Summary: appControlSummaryPtr(boundSummary(cipErr.Error())),
		})
	}

	legacyPresent, legacyErr := probeSipolicyPresence()
	ev.LegacySipolicyPresent = legacyPresent
	if legacyErr != nil {
		errs = append(errs, AppControlProbeError{
			Code:    AppControlErrFilesystemDenied,
			Source:  errSourcePtr(AppControlProbeErrSourceFilesystem),
			Summary: appControlSummaryPtr(boundSummary(legacyErr.Error())),
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
		if filepath.Ext(ent.Name()) == ".cip" {
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
				Summary: appControlSummaryPtr(boundSummary("SrpV2 root unreadable: " + err.Error())),
			})
		}
	} else {
		_ = rootKey.Close()

		// Per-collection read (Codex iter-1 P1 #5 strict mapping).
		for _, c := range appLockerCollections {
			mode, readErr := readAppLockerCollectionMode(c.keyPath)
			switch c.name {
			case "Exe":
				r.ExeRule = mode
			case "Dll":
				r.DllRule = mode
			case "Script":
				r.ScriptRule = mode
			case "Msi":
				r.MsiRule = mode
			case "Appx":
				r.AppxRule = mode
			}
			if readErr != nil {
				errs = append(errs, AppControlProbeError{
					Code:    AppControlErrAppLockerKeyUnreadable,
					Source:  errSourcePtr(AppControlProbeErrSourceAppLocker),
					Summary: appControlSummaryPtr(boundSummary(c.name + ": " + readErr.Error())),
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
			Summary: appControlSummaryPtr(boundSummary(svcErr.Error())),
		})
	}

	return r, errs
}

// readAppLockerCollectionMode applies the Codex 019e83ce iter-1 P1 #5
// strict mapping: missing/0 → NOT_CONFIGURED, 1 → AUDIT_ONLY, 2 →
// ENFORCE, other → UNKNOWN + typed error.
func readAppLockerCollectionMode(keyPath string) (AppLockerEnforcementMode, error) {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, keyPath, registry.QUERY_VALUE|registry.READ)
	if err != nil {
		if errors.Is(err, registry.ErrNotExist) {
			return AppLockerNotConfigured, nil
		}
		return AppLockerUnknown, fmt.Errorf("key open failed: %w", err)
	}
	defer key.Close()

	val, valType, err := key.GetIntegerValue(appLockerEnforcementMode)
	if err != nil {
		if errors.Is(err, registry.ErrNotExist) {
			return AppLockerNotConfigured, nil
		}
		return AppLockerUnknown, fmt.Errorf("EnforcementMode read failed: %w", err)
	}
	if valType != registry.DWORD {
		return AppLockerUnknown, fmt.Errorf("EnforcementMode wrong type: %d", valType)
	}
	switch val {
	case 0:
		return AppLockerNotConfigured, nil
	case 1:
		return AppLockerAuditOnly, nil
	case 2:
		return AppLockerEnforce, nil
	default:
		return AppLockerUnknown, fmt.Errorf("EnforcementMode unexpected DWORD: %d", val)
	}
}

// queryAppIdSvcWindows reuses the SCM client established by AG-039
// services_windows.go. Returns shared ServiceState + StartupMode enums.
func queryAppIdSvcWindows(_ context.Context) (ServiceState, StartupMode, *bool, error) {
	m, err := mgr.Connect()
	if err != nil {
		return ServiceStateUnknown, StartupModeUnknown, nil, fmt.Errorf("SCM connect failed: %w", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(appLockerAppIdSvcName)
	if err != nil {
		// AppIDSvc not present — legitimate observation, not an error.
		notPresent := false
		return ServiceStateUnknown, StartupModeUnknown, &notPresent, nil
	}
	defer s.Close()

	present := true
	state := ServiceStateUnknown
	startup := StartupModeUnknown

	if status, err := s.Query(); err == nil {
		switch status.State {
		case svc.Running:
			state = ServiceStateRunning
		case svc.Stopped:
			state = ServiceStateStopped
		}
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
	}

	return state, startup, &present, nil
}

// boundSummary trims to ≤200 chars + strips CR/LF.
func boundSummary(s string) string {
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
