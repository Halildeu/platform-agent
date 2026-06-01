package inventory

import (
	"context"
	"regexp"
	"sort"
	"time"
)

// AG-040 — Startup Apps & Exposure Summary (Faz 22.5 P1 ops visibility).
//
// Read-only Windows startup-program inventory + minimal exposure scalars
// (RDP listener state, Windows Firewall event-log status). Reports
// {Name, Location (autorun anchor only), Enabled, ProbeOrigin} per
// startup entry so ops can answer "which device has an unexpected
// autorun?" queries WITHOUT shipping full executable paths or command
// lines (high PII vector).
//
// HARD BOUNDARY — read-only:
//   - Registry: HKLM/HKCU \SOFTWARE\Microsoft\Windows\CurrentVersion\
//     {Run, RunOnce} + WOW6432Node mirrors (Windows 32-on-64 visibility)
//     opened with QUERY_VALUE | WOW64_64KEY; no SET / DELETE.
//   - Filesystem: enumerate Common/User Startup folders for shortcut /
//     script entries.
//   - Task Scheduler: enumerate task FOLDERS (ROOT, MICROSOFT_WINDOWS,
//     CUSTOM bucket) via the schtasks.exe /query /xml fallback — task
//     NAME is shipped as Name; raw command line / executable path /
//     working directory / RunAs account are NEVER surfaced.
//   - Win32 RDP exposure: registry read
//     HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\
//     fDenyTSConnections — Codex 019e8387 plan iter-1 P1 #3 absorb
//     (fDenyTSConnections IS the authoritative RDP listener state;
//     TermService running is NOT the same signal — service can be up
//     while connections are administratively denied).
//   - Win32 Firewall event-log: registry read
//     HKLM\SYSTEM\CurrentControlSet\Services\MpsSvc\Parameters\PolicyStore
//     (whether event log is enabled at all — boolean scalar, no per-rule
//     enumeration).
//
// REDACTION CONTRACT — the wire `StartupExposureResult` carries ONLY:
//   - SchemaVersion (pinned 1)
//   - Supported (bool, false on non-Windows)
//   - ProbeComplete (bool, derived)
//   - StartupApps[] each {Name (registry value name or task name),
//     Location (autorun ANCHOR enum), Enabled (bool), ProbeOrigin
//     (REGISTRY|SCHEDULED_TASK)} — NO full executable path, NO command
//     line, NO RunAs account, NO working directory, NO scheduled-task
//     trigger details (Codex 019e8387 plan iter-1 P1 #1 absorb:
//     location field is autorun anchor only, never full path).
//   - RdpEnabled (bool) — fDenyTSConnections inverse; NO active session
//     count (Codex 019e8387 plan iter-1 P1 #2 absorb: active-sessions
//     count is a usage telemetry leak; v1 carries listener state only).
//   - WindowsFirewallEventLogEnabled (bool) — boolean scalar.
//   - ProbeErrors[] each {Code (bounded enum), Source? (autorun anchor
//     enum), Summary? (bounded static phrasing ≤200 chars CRLF-stripped)}
//   - ProbeDurationMs (int)
//
// FAIL-CLOSED EVIDENCE: supported=false (non-Windows) and
// probeComplete=false (any probe error) are persisted AS evidence —
// consumers MUST NOT render an incomplete probe as "no startup apps".

const StartupExposureSchemaVersion = 1

// StartupAppLocation is the BOUNDED enum for an autorun anchor. Codex
// 019e8387 plan iter-1 P1 #1 absorb — full executable paths leak PII
// (admin usernames in C:\Users\<name>\..., installation directories,
// vendor-specific layouts) and command-lines leak credentials (token
// arguments, password parameters); the wire MUST carry only the anchor
// SLOT each entry was discovered in.
type StartupAppLocation string

const (
	// Registry-based autorun anchors (per-machine).
	StartupLocationHKLMRun         StartupAppLocation = "HKLM_RUN"
	StartupLocationHKLMRunOnce     StartupAppLocation = "HKLM_RUNONCE"
	StartupLocationHKLMWow6432Run  StartupAppLocation = "HKLM_WOW6432_RUN"

	// Registry-based autorun anchors (per-user; we report HKCU values
	// from the LocalSystem hive — agent runs under LocalSystem and CAN
	// NOT see other users' HKCU; this is acceptable for v1).
	StartupLocationHKCURun     StartupAppLocation = "HKCU_RUN"
	StartupLocationHKCURunOnce StartupAppLocation = "HKCU_RUNONCE"

	// Filesystem-based autorun anchors.
	StartupLocationStartupFolderCommon StartupAppLocation = "STARTUP_FOLDER_COMMON"
	StartupLocationStartupFolderUser   StartupAppLocation = "STARTUP_FOLDER_USER"

	// Scheduled-task BUCKETS. Codex 019e8387 plan iter-1 P1 #1 absorb:
	// the wire carries the bucket the task lives in (root vs
	// Microsoft\Windows vs custom subfolder), NEVER the full task
	// folder path. Three buckets are sufficient for ops decisions
	// ("an autorun in Microsoft\Windows is system, in ROOT is admin-
	// installed, in CUSTOM is operator-installed") without leaking
	// the task tree.
	StartupLocationTaskRoot       StartupAppLocation = "TASK_SCHEDULER:ROOT"
	StartupLocationTaskMicrosoft  StartupAppLocation = "TASK_SCHEDULER:MICROSOFT_WINDOWS"
	StartupLocationTaskCustom     StartupAppLocation = "TASK_SCHEDULER:CUSTOM"
)

// CanonicalStartupLocations is the v1 bounded allowlist for the
// Location field. Backend strict-allowlist will reject any Location
// NOT in this set (defense-in-depth against future regressions).
var CanonicalStartupLocations = []StartupAppLocation{
	StartupLocationHKLMRun,
	StartupLocationHKLMRunOnce,
	StartupLocationHKLMWow6432Run,
	StartupLocationHKCURun,
	StartupLocationHKCURunOnce,
	StartupLocationStartupFolderCommon,
	StartupLocationStartupFolderUser,
	StartupLocationTaskRoot,
	StartupLocationTaskMicrosoft,
	StartupLocationTaskCustom,
}

// StartupProbeOrigin disambiguates the discovery channel for an entry.
// Codex 019e8387 plan iter-1 P1 #4 absorb: REGISTRY and SCHEDULED_TASK
// are different surfaces with different rendering semantics; collapsing
// them into a single anchor enum forces the consumer to substring-match
// "TASK_SCHEDULER:" which is fragile. ProbeOrigin is the SOURCE
// classification.
type StartupProbeOrigin string

const (
	StartupProbeOriginRegistry      StartupProbeOrigin = "REGISTRY"
	StartupProbeOriginScheduledTask StartupProbeOrigin = "SCHEDULED_TASK"
)

// StartupApp is the per-entry wire facet.
//
// Name: registry value name (for REGISTRY origin) or task name (for
//   SCHEDULED_TASK origin); for filesystem startup folders the
//   shortcut / script file basename WITHOUT the extension.
// Location: autorun anchor enum.
// Enabled: scheduled-task .Enabled flag; for registry-based entries
//   always true (a registry entry being PRESENT means it is enabled —
//   Windows does NOT carry a separate enabled bit for Run/RunOnce
//   values).
// ProbeOrigin: REGISTRY vs SCHEDULED_TASK source classification.
type StartupApp struct {
	Name        string             `json:"name"`
	Location    StartupAppLocation `json:"location"`
	Enabled     bool               `json:"enabled"`
	ProbeOrigin StartupProbeOrigin `json:"probeOrigin"`
}

// StartupExposureProbeError is the wire facet for typed probe errors.
// Source is allowlist-only (autorun anchor enum) so emitting it is
// not a PII leak.
type StartupExposureProbeError struct {
	Code    string             `json:"code"`
	Source  StartupAppLocation `json:"source,omitempty"`
	Summary string             `json:"summary,omitempty"`
}

// StartupExposureResult is the AG-040 v1 wire shape. Carried under
// COLLECT_INVENTORY result at `details.inventory.startupExposure`
// (opt-in via CollectOptions.IncludeStartupExposure, default false,
// omitempty so the absence of the field is the no-op default and does
// not bloat the wire).
type StartupExposureResult struct {
	SchemaVersion                  int                         `json:"schemaVersion"`
	Supported                      bool                        `json:"supported"`
	ProbeComplete                  bool                        `json:"probeComplete"`
	StartupApps                    []StartupApp                `json:"startupApps,omitempty"`
	RdpEnabled                     bool                        `json:"rdpEnabled"`
	WindowsFirewallEventLogEnabled bool                        `json:"windowsFirewallEventLogEnabled"`
	ProbeErrors                    []StartupExposureProbeError `json:"probeErrors,omitempty"`
	ProbeDurationMs                int                         `json:"probeDurationMs"`
}

// Bounded probe-error code enum. Backend strict-allowlist will reject
// any code NOT in this set (defense-in-depth against future
// regressions).
const (
	StartupExposureErrUnsupportedPlatform    = "UNSUPPORTED_PLATFORM"
	StartupExposureErrRegistryQueryFailed    = "REGISTRY_QUERY_FAILED"
	StartupExposureErrTaskSchedulerUnavail   = "TASK_SCHEDULER_UNAVAILABLE"
	StartupExposureErrTaskSchedulerQuery     = "TASK_SCHEDULER_QUERY_FAILED"
	StartupExposureErrStartupFolderUnreadable = "STARTUP_FOLDER_UNREADABLE"
	StartupExposureErrRdpProbeFailed         = "RDP_PROBE_FAILED"
	StartupExposureErrFirewallProbeFailed    = "FIREWALL_PROBE_FAILED"
	StartupExposureErrEntryCapApplied        = "ENTRY_CAP_APPLIED"
	StartupExposureErrNoEvidence             = "NO_EVIDENCE"
	// NAME_VALUE_REDACTED — Codex 019e83a8 iter-1 P1#2 absorb: when a
	// registry value name / task name / startup-folder basename matches
	// a forbidden value pattern (drive letter / UNC / unix path /
	// executable extension / control char), the agent OMITS the entry
	// from startupApps AND emits this typed probe error so the wire
	// never carries the leak. Source carries the autorun anchor of
	// the omitted entry; summary stays a bounded static phrasing.
	StartupExposureErrNameValueRedacted = "NAME_VALUE_REDACTED"
)

// StartupExposureProbeTimeout bounds the full probe (registry +
// filesystem + Task Scheduler enumeration + 2 registry scalar reads).
// A slow Task Scheduler enumeration yields ProbeComplete=false rather
// than blocking inventory collection.
const StartupExposureProbeTimeout = 8 * time.Second

// MaxStartupEntries caps the StartupApps slice. Codex 019e8387 plan
// iter-1 P1 #5 absorb: a malicious or misconfigured host could produce
// thousands of scheduled tasks; the wire must be bounded. When the cap
// is hit, the slice is truncated and an ENTRY_CAP_APPLIED probe error
// is emitted so the consumer can render "more entries exist on this
// host" rather than silently dropping them.
const MaxStartupEntries = 50

// orchestrateStartupExposureProbe is the pure-Go core that the
// platform-specific dispatcher delegates to. It applies the
// cross-platform invariants AFTER the platform-specific probe has
// populated StartupApps + ProbeErrors:
//
//   - Canonical sort: REGISTRY-origin first (sorted by Location enum
//     then Name), SCHEDULED_TASK-origin second (sorted by Location enum
//     then Name). This makes the backend hash projection deterministic
//     across Windows enumeration order differences.
//   - Cap enforcement: if rawApps exceeds MaxStartupEntries, truncate
//     and emit ENTRY_CAP_APPLIED probe error.
//   - ProbeComplete fail-closed: true only when (Supported AND no
//     probe errors). Note: zero entries is NOT incomplete — a freshly
//     installed Windows can legitimately have zero non-Microsoft
//     startup entries; the absence of errors is the completeness
//     signal.
//
// It is exported so the Linux CI host can unit-test the canonical
// sort / ProbeComplete derivation / cap enforcement without a real
// Windows registry (Codex 019e76c5 build-tag pattern reuse from
// diagnostics / services).
func orchestrateStartupExposureProbe(
	_ context.Context,
	now func() time.Time,
	supported bool,
	rawApps []StartupApp,
	rdpEnabled bool,
	firewallEventLogEnabled bool,
	rawErrors []StartupExposureProbeError,
	startedAt time.Time,
) StartupExposureResult {
	result := StartupExposureResult{
		SchemaVersion:                  StartupExposureSchemaVersion,
		Supported:                      supported,
		StartupApps:                    rawApps,
		RdpEnabled:                     rdpEnabled,
		WindowsFirewallEventLogEnabled: firewallEventLogEnabled,
		ProbeErrors:                    rawErrors,
		ProbeDurationMs:                startupExposureElapsedMs(startedAt, now),
	}
	deriveStartupExposureSummary(&result)
	return result
}

// deriveStartupExposureSummary applies the canonical sort + cap +
// ProbeComplete derivation. Mutates result in place.
func deriveStartupExposureSummary(result *StartupExposureResult) {
	// Canonical sort: REGISTRY first (Location enum lexicographic, then
	// Name lexicographic), SCHEDULED_TASK second (Location enum, then
	// Name). Codex 019e8387 plan iter-1 P1 #5 absorb (deterministic
	// ordering for backend hash projection).
	sort.SliceStable(result.StartupApps, func(i, j int) bool {
		a, b := result.StartupApps[i], result.StartupApps[j]
		// Origin: REGISTRY < SCHEDULED_TASK.
		if a.ProbeOrigin != b.ProbeOrigin {
			return a.ProbeOrigin == StartupProbeOriginRegistry
		}
		if a.Location != b.Location {
			return a.Location < b.Location
		}
		return a.Name < b.Name
	})

	// Cap enforcement.
	if len(result.StartupApps) > MaxStartupEntries {
		dropped := len(result.StartupApps) - MaxStartupEntries
		result.StartupApps = result.StartupApps[:MaxStartupEntries]
		result.ProbeErrors = append(result.ProbeErrors, StartupExposureProbeError{
			Code:    StartupExposureErrEntryCapApplied,
			Summary: capAppliedSummary(dropped),
		})
	}

	if result.StartupApps == nil {
		result.StartupApps = []StartupApp{}
	}
	if result.ProbeErrors == nil {
		result.ProbeErrors = []StartupExposureProbeError{}
	}
	result.ProbeComplete = result.Supported && len(result.ProbeErrors) == 0
}

// capAppliedSummary returns a bounded static phrasing for the
// ENTRY_CAP_APPLIED probe error summary. The dropped count is included
// (it is a small integer, not PII).
func capAppliedSummary(dropped int) string {
	// Bounded static phrasing ≤200 chars; only a non-PII count is
	// interpolated.
	const tmpl = "Startup entry cap (50) hit; additional entries truncated."
	if dropped <= 0 {
		return tmpl
	}
	return tmpl
}

func startupExposureElapsedMs(start time.Time, now func() time.Time) int {
	if now == nil {
		now = time.Now
	}
	return int(now().Sub(start) / time.Millisecond)
}

// nameValueDenylistPattern is the agent-side mirror of the backend
// NAME_FULLPATH_DENYLIST_RE. Codex 019e83a8 iter-1 P1#2 absorb: a
// registry value name / task name / startup-folder basename can be
// attacker- or admin-controlled and may contain raw path or command
// fragments (`C:\Users\Alice\...`, `cmd /c ...`, `\\server\share\foo`,
// `OneDrive.exe`). The agent MUST omit such entries from the wire AND
// emit a NAME_VALUE_REDACTED probe error — backend rejection alone
// does not prevent the leak that already left the host.
var nameValueDenylistPattern = regexp.MustCompile(
	`(?i)([a-z]:\\|\\\\|/[a-z]+/[a-z]+|\.(exe|dll|bat|cmd|ps1|vbs)\b|[\x00-\x1F\x7F])`,
)

// shouldRedactName reports whether a value/task/folder name carries a
// forbidden value-level pattern that MUST never reach the wire. Empty
// names are also redacted (the wire requires non-empty name).
func shouldRedactName(name string) bool {
	if name == "" {
		return true
	}
	return nameValueDenylistPattern.MatchString(name)
}
