package inventory

import (
	"context"
	"sort"
	"time"
)

// AG-039 — Critical Services Inventory (Faz 22.5 P1 ops visibility).
//
// Read-only Windows service-state probe over a HARD-CODED v1 allowlist of
// security/operational services. Reports {Name, Present, State, StartupMode}
// per allowlisted service for ops alerting "which device has WinDefend STOPPED
// / DISABLED?" type queries (without operator-defined allowlists; Codex
// 019e8302 iter-2 #1 absorb — tenant-configurable list deferred to v2).
//
// HARD BOUNDARY — read-only: probes SCM (`x/sys/windows/svc/mgr`) for state +
// queries `HKLM\SYSTEM\CurrentControlSet\Services\<name>\DelayedAutoStart`
// registry for the AUTO_DELAYED disambiguation (Codex iter-2 #3 absorb;
// installer configures EndpointAgent as delayed-auto and the regression
// visibility is critical). NO PowerShell — lower attack surface (Codex
// iter-2 implementation note).
//
// REDACTION CONTRACT — the wire `ServicesResult` carries ONLY:
//   - SchemaVersion (pinned 1)
//   - Supported (bool, false on non-Windows)
//   - ProbeComplete (bool, derived)
//   - Services[] each {Name (from allowlist), Present (bool), State (5-state
//     enum), StartupMode (5-state enum)} — NO raw description / command line /
//     account / SID / display name
//   - ProbeErrors[] each {Code (bounded enum), ServiceName? (allowlist-only),
//     Summary? (bounded static phrasing ≤200 chars CRLF-stripped)}
//   - ProbeDurationMs (int)
//
// FAIL-CLOSED EVIDENCE: supported=false (non-Windows) and probeComplete=false
// (any SCM/registry probe error) are persisted AS evidence — consumers MUST
// NOT render an incomplete probe as "all services healthy".

const ServicesSchemaVersion = 1

// CanonicalServiceAllowlist is the v1 hard-coded list of services this probe
// reports state for. Each entry MUST be the SCM canonical service name (NOT
// display name) so the redaction surface stays bounded and stable. Codex
// 019e8302 iter-2 #2 absorb: EndpointAgent canonical name (installer
// ServiceName="EndpointAgent"); TermService deferred to AG-040 (RDP/exposure).
var CanonicalServiceAllowlist = []string{
	"WinDefend",     // Microsoft Defender Antivirus service
	"wuauserv",      // Windows Update
	"BITS",          // Background Intelligent Transfer Service
	"EventLog",      // Windows Event Log
	"EndpointAgent", // Our agent service (canonical name from install.ps1 ServiceName)
	"MpsSvc",        // Windows Firewall
}

// ServicesProbeTimeout bounds the SCM enumeration + per-service registry
// read. A slow SCM yields ProbeComplete=false rather than blocking the
// inventory collection.
const ServicesProbeTimeout = 5 * time.Second

// ServiceState wire enum is SHARED with hotfix_posture.go (AG-037 ships
// the same 4-state enum for wuauserv/BITS service state; AG-039 reuses
// it for the broader 6-service allowlist). UNKNOWN is the fail-closed
// "could not read" sentinel — used both when the service is present-but-
// query-failed AND for v1 paused/pending transitions we explicitly do
// NOT promise to disambiguate (Codex 019e8302 iter-2 #4 absorb:
// pending/paused → UNKNOWN, not STOPPED).
//
// Defined once in hotfix_posture.go with:
//   ServiceStateRunning | ServiceStateStopped | ServiceStateDisabled |
//   ServiceStateUnknown

// StartupMode is the wire enum for Windows service startup configuration.
// AUTO_DELAYED is separate from AUTO so a regression in EndpointAgent's
// delayed-start posture is visible (Codex 019e8302 iter-2 #3 absorb).
type StartupMode string

const (
	StartupModeAuto         StartupMode = "AUTO"
	StartupModeAutoDelayed  StartupMode = "AUTO_DELAYED"
	StartupModeManual       StartupMode = "MANUAL"
	StartupModeDisabled     StartupMode = "DISABLED"
	StartupModeUnknown      StartupMode = "UNKNOWN"
)

// ServiceEntry is the per-allowlisted-service wire facet.
//
// Present=true: the service exists in SCM (we can read its config).
// Present=false: the service is NOT installed on this device (e.g. on an
// older Windows where MpsSvc not deployed); State + StartupMode are
// UNKNOWN/UNKNOWN. This is NOT collapsed into "query failed"; Codex
// 019e8302 iter-2 #4 absorb (Present field added to disambiguate
// absent-from-SCM vs query-failure).
type ServiceEntry struct {
	Name        string       `json:"name"`
	Present     bool         `json:"present"`
	State       ServiceState `json:"state"`
	StartupMode StartupMode  `json:"startupMode"`
}

// ServicesProbeError is the wire facet for typed probe errors. ServiceName
// is allowlist-only so emitting it is not a PII leak (Codex iter-2 #3
// suggestion absorb).
type ServicesProbeError struct {
	Code        string `json:"code"`
	ServiceName string `json:"serviceName,omitempty"`
	Summary     string `json:"summary,omitempty"`
}

// ServicesResult is the AG-039 v1 wire shape. Carried under
// COLLECT_INVENTORY result at `details.inventory.services` (opt-in via
// CollectOptions.IncludeServices, default false, omitempty so the absence
// of the field is the no-op default and does not bloat the wire).
type ServicesResult struct {
	SchemaVersion   int                  `json:"schemaVersion"`
	Supported       bool                 `json:"supported"`
	ProbeComplete   bool                 `json:"probeComplete"`
	Services        []ServiceEntry       `json:"services,omitempty"`
	ProbeErrors     []ServicesProbeError `json:"probeErrors,omitempty"`
	ProbeDurationMs int                  `json:"probeDurationMs"`
}

// Bounded probe-error code enum. Backend strict-allowlist will reject any
// code NOT in this set (defense-in-depth against future regressions).
const (
	ServicesErrUnsupportedPlatform = "UNSUPPORTED_PLATFORM"
	ServicesErrSCMUnavailable      = "SCM_UNAVAILABLE"
	ServicesErrServiceNotFound     = "SERVICE_NOT_FOUND"
	ServicesErrServiceQueryFailed  = "SERVICE_QUERY_FAILED"
	ServicesErrRegistryQueryFailed = "REGISTRY_QUERY_FAILED"
	ServicesErrNoEvidence          = "NO_EVIDENCE"
)

// ProbeServices is the platform-dispatch entry. Implementations live in
// services_windows.go (real SCM/registry path) and services_other.go
// (non-Windows fail-closed stub).
//
// The `ctx` is honored for cooperative cancellation; per-call SCM/registry
// reads do NOT block beyond ServicesProbeTimeout. `now` is injectable so
// tests can fix the wall-clock for deterministic ProbeDurationMs.

// deriveServicesSummary applies the cross-platform invariants AFTER the
// platform-specific probe has populated Services + ProbeErrors:
//
//   - ProbeComplete fail-closed: true only when (Supported AND no probe
//     errors AND services list has exactly the allowlist length).
//   - Services list canonical sort (alphabetic by Name) so the backend
//     hash projection is deterministic across SCM enumeration order
//     differences between Windows builds.
//
// Codex 019e8302 iter-2 #6 absorb (canonical projection order).
func deriveServicesSummary(result *ServicesResult) {
	// Canonical sort: backend hash projection determinism.
	sort.SliceStable(result.Services, func(i, j int) bool {
		return result.Services[i].Name < result.Services[j].Name
	})
	if result.Services == nil {
		result.Services = []ServiceEntry{}
	}
	if result.ProbeErrors == nil {
		result.ProbeErrors = []ServicesProbeError{}
	}
	result.ProbeComplete = result.Supported &&
		len(result.ProbeErrors) == 0 &&
		len(result.Services) == len(CanonicalServiceAllowlist)
}

func servicesElapsedMs(start time.Time, now func() time.Time) int {
	if now == nil {
		now = time.Now
	}
	return int(now().Sub(start) / time.Millisecond)
}

// orchestrateServicesProbe is the pure-Go core that the platform-specific
// dispatcher delegates to. It is exported so the Linux CI host can unit-
// test the canonical sort / ProbeComplete derivation / cap enforcement
// without a real Windows SCM (Codex 019e76c5 build-tag absorb — same
// pattern as diagnostics.go).
func orchestrateServicesProbe(
	_ context.Context,
	now func() time.Time,
	supported bool,
	rawEntries []ServiceEntry,
	rawErrors []ServicesProbeError,
	startedAt time.Time,
) ServicesResult {
	result := ServicesResult{
		SchemaVersion:   ServicesSchemaVersion,
		Supported:       supported,
		Services:        rawEntries,
		ProbeErrors:     rawErrors,
		ProbeDurationMs: servicesElapsedMs(startedAt, now),
	}
	deriveServicesSummary(&result)
	return result
}
