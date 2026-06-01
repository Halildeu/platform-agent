package inventory

import "time"

// AG-037 — Windows Update / Hotfix Posture (Faz 22.5 quick-wins).
//
// Read-only probe surfacing the installed hotfix inventory, pending
// Windows-update queue counts, and Windows Update agent health. The
// probe NEVER triggers a Windows Update detect/install, never schedules
// a reboot, and never mutates service or policy state — it answers
// these questions only:
//
//   - "Which KB hotfixes are currently installed on this host?"
//   - "How many updates are pending (by category/severity) and how
//      truncated is the snapshot?"
//   - "Is the Windows Update Agent healthy enough that the above counts
//      are trustworthy (WUA service / BITS / last detect+install / auto
//      update policy)?"
//
// HARD BOUNDARIES (locked in the Codex 019e8167 plan-time consensus —
// REVISE absorbed: typed enums over composite bools, source attribution,
// pending item list with allowlist fields, error-code set widened):
//
//   - **Read-only.** No `Install-WindowsUpdate`, no `wuauclt /detectnow`,
//     no `sconfig` reboot trigger, no service start/stop/enable/disable,
//     no policy mutation. WUA COM `IUpdateSearcher.Search` and
//     `IUpdateHistoryEntry` enumeration only; registry + service reads
//     are queries.
//
//   - **Opt-in via includeHotfixPosture payload bit.** Default
//     COLLECT_INVENTORY does NOT call this probe. AG-025H lightweight
//     guard pattern: `hotfixPosture` is `omitempty` on the snapshot
//     and is only populated when the command-payload explicitly
//     requests it.
//
//   - **Allowlist projection.** Per-hotfix wire fields are EXACTLY
//     `{kbId, installedOn, description}`; per-pending-item EXACTLY
//     `{kbIds, primaryCategory, severity}`. Raw stdout/stderr,
//     PowerShell verbose, account names, command lines, product codes,
//     MSI GUIDs, supersedence chains, raw update titles (post-v1), and
//     install-source client app IDs NEVER reach the wire.
//
//   - **`*time.Time` for parseable-but-absent timestamps.** A
//     non-parseable WUA `InstalledOn` becomes `nil` (not zero, not raw
//     string). Backend treats `nil` as "unknown date for this hotfix"
//     and renders accordingly.
//
//   - **Typed service-state enum.** `WuaServiceState`/`BitsServiceState`
//     distinguishes `RUNNING|STOPPED|DISABLED|UNKNOWN` (a `*bool`
//     conflates Stopped vs Disabled — different operator workflows).
//
//   - **Source attribution.** Each section (installed/pending/health)
//     reports the canonical source it actually queried; a `Get-HotFix`
//     fallback for installed-only is explicit on the wire so the
//     reviewer can tell COM-failed paths apart from authoritative reads.
//
//   - **Caps + truncation flag.** Installed list capped at
//     `MaxInstalledHotfixes=512` (deterministic order: `installedOn
//     DESC`, ties broken by `kbId`); pending item list capped at
//     `MaxPendingUpdates=20` (deterministic order: severity rank then
//     primaryCategory then first kbId). Pre-truncation counts surfaced
//     so backend can render "showing N of TOTAL".
//
//   - **Supported false ≠ no updates.** Non-Windows runtime returns
//     `supported=false`, `probeComplete=false`, with a single
//     `UNSUPPORTED_PLATFORM` probe error. Caller cannot infer "no
//     updates pending" from an unsupported stub.

// HotfixPostureSchemaVersion is bumped on non-additive schema changes to
// HotfixPostureResult. v1 ships as 1.
const HotfixPostureSchemaVersion = 1

// MaxInstalledHotfixes is the hard cap for the on-wire
// `installedHotfixes` list. Pre-truncation count is surfaced in
// `installedCount`; `installedTruncated=true` when overflow occurs.
const MaxInstalledHotfixes = 512

// MaxPendingUpdates is the hard cap for the on-wire `pendingUpdates`
// list. Pre-truncation count is surfaced in `pendingTotalCount`;
// `pendingTruncated=true` when overflow occurs.
const MaxPendingUpdates = 20

// HotfixPostureSource enumerates the canonical query sources AG-037 v1
// can attribute on the wire. Adding a new source is a non-breaking
// schema change.
type HotfixPostureSource string

const (
	// HotfixPostureSourceNone — section was not queried (e.g. probe
	// short-circuited after WUA COM failure for pending updates).
	HotfixPostureSourceNone HotfixPostureSource = "none"

	// HotfixPostureSourceWUA — Windows Update Agent COM
	// (`Microsoft.Update.Session.CreateUpdateSearcher.Search /
	// QueryHistory`). Authoritative for installed history + pending
	// queue + agent health.
	HotfixPostureSourceWUA HotfixPostureSource = "wua"

	// HotfixPostureSourceGetHotfix — PowerShell `Get-HotFix` fallback.
	// Reliable only for the **installed-from-Windows-Update** subset
	// (does NOT include `Install-Module`, MSI-installed patches, or
	// AppX) — explicitly NOT a substitute for WUA QueryHistory.
	HotfixPostureSourceGetHotfix HotfixPostureSource = "getHotfix"

	// HotfixPostureSourceRegistry — `HKLM\\SOFTWARE\\Microsoft\\Windows\
	// \\CurrentVersion\\WindowsUpdate\\Auto Update\\Results\\(Detect|
	// Install)` for `LastSuccessTime` timestamps, and the AU policy
	// keys for `auOptions` / `NoAutoUpdate`.
	HotfixPostureSourceRegistry HotfixPostureSource = "registry"

	// HotfixPostureSourceService — Service Control Manager
	// `QueryServiceStatusEx` for `wuauserv` + `bits` Running/Stopped/
	// Disabled mapping. We do NOT enumerate dependent services.
	HotfixPostureSourceService HotfixPostureSource = "service"

	// HotfixPostureSourceUnknown — source attribution dropped because
	// the field was derived from a mixed/composite query path (rare).
	HotfixPostureSourceUnknown HotfixPostureSource = "unknown"
)

// HotfixPostureProbeErrorCode is the typed error enum AG-037 ships on
// `probeErrors`. Widened from the draft per Codex 019e8167 must-fix #8
// to cover the pinned-PowerShell-runner failure modes specifically.
type HotfixPostureProbeErrorCode string

const (
	HotfixPostureUnsupportedPlatform   HotfixPostureProbeErrorCode = "UNSUPPORTED_PLATFORM"
	HotfixPostureAccessDenied          HotfixPostureProbeErrorCode = "ACCESS_DENIED"
	HotfixPostureCOMFailed             HotfixPostureProbeErrorCode = "COM_FAILED"
	HotfixPostureWSUSUnreachable       HotfixPostureProbeErrorCode = "WSUS_UNREACHABLE"
	HotfixPosturePowerShellMissing     HotfixPostureProbeErrorCode = "POWERSHELL_MISSING"
	HotfixPosturePowerShellTimeout     HotfixPostureProbeErrorCode = "POWERSHELL_TIMEOUT"
	HotfixPosturePowerShellFailed      HotfixPostureProbeErrorCode = "POWERSHELL_FAILED"
	HotfixPosturePowerShellEmptyOutput HotfixPostureProbeErrorCode = "POWERSHELL_EMPTY_OUTPUT"
	HotfixPosturePowerShellParseError  HotfixPostureProbeErrorCode = "POWERSHELL_PARSE_ERROR"
	HotfixPostureRegistryUnavailable   HotfixPostureProbeErrorCode = "REGISTRY_UNAVAILABLE"
	HotfixPostureServiceQueryFailed    HotfixPostureProbeErrorCode = "SERVICE_QUERY_FAILED"
	HotfixPostureNoEvidence            HotfixPostureProbeErrorCode = "NO_EVIDENCE"
)

// HotfixPostureProbeError describes one section-level failure. Multiple
// sections (installed/pending/health) may each contribute an error; the
// overall `probeComplete` flips to `false` if ANY error is present, but
// the remaining sections still surface what they could collect (partial
// fail-closed semantics).
type HotfixPostureProbeError struct {
	// Source is the section / canonical source that failed. Never
	// `none`.
	Source HotfixPostureSource `json:"source"`

	// Code is the typed failure class.
	Code HotfixPostureProbeErrorCode `json:"code"`

	// Summary is an OPTIONAL bounded operator-readable description.
	// Implementations MUST NOT include raw stdout/stderr, account
	// names, command lines, or other identifier-leaking text. Cap is
	// enforced at the sanitiser; this struct field is the contract
	// shape only.
	Summary string `json:"summary,omitempty"`
}

// ServiceState is the typed three-way state for Windows services
// AG-037 cares about (`wuauserv`, `bits`). The `*bool` "running" shape
// conflates Stopped vs Disabled (Codex 019e8167 must-fix #4) — those
// have different operator workflows, so we ship the enum.
type ServiceState string

const (
	ServiceStateRunning  ServiceState = "RUNNING"
	ServiceStateStopped  ServiceState = "STOPPED"
	ServiceStateDisabled ServiceState = "DISABLED"
	ServiceStateUnknown  ServiceState = "UNKNOWN"
)

// HotfixPostureCategory enumerates the canonical update category bucket
// AG-037 normalises Microsoft Update Category GUIDs into. We do NOT
// ship raw GUIDs on the wire. Mapping is implemented in `*_windows.go`.
type HotfixPostureCategory string

const (
	HotfixPostureCategorySecurity      HotfixPostureCategory = "SECURITY"
	HotfixPostureCategoryDefinition    HotfixPostureCategory = "DEFINITION"
	HotfixPostureCategoryCritical      HotfixPostureCategory = "CRITICAL"
	HotfixPostureCategoryImportant     HotfixPostureCategory = "IMPORTANT"
	HotfixPostureCategoryOptional      HotfixPostureCategory = "OPTIONAL"
	HotfixPostureCategoryDriver        HotfixPostureCategory = "DRIVER"
	HotfixPostureCategoryFeaturePack   HotfixPostureCategory = "FEATURE_PACK"
	HotfixPostureCategoryServicePack   HotfixPostureCategory = "SERVICE_PACK"
	HotfixPostureCategoryUpdateRollup  HotfixPostureCategory = "UPDATE_ROLLUP"
	HotfixPostureCategoryTools         HotfixPostureCategory = "TOOLS"
	HotfixPostureCategoryUncategorized HotfixPostureCategory = "UNCATEGORIZED"
)

// HotfixPostureSeverity is the orthogonal severity axis (MSRC). Codex
// 019e8167 must-fix #3: separate from category — `Security` is the
// category bucket; `Critical/Important/Moderate/Low` is the severity
// rating, and an update can be `(Security, Important)` simultaneously.
type HotfixPostureSeverity string

const (
	HotfixPostureSeverityCritical    HotfixPostureSeverity = "CRITICAL"
	HotfixPostureSeverityImportant   HotfixPostureSeverity = "IMPORTANT"
	HotfixPostureSeverityModerate    HotfixPostureSeverity = "MODERATE"
	HotfixPostureSeverityLow         HotfixPostureSeverity = "LOW"
	HotfixPostureSeverityUnspecified HotfixPostureSeverity = "UNSPECIFIED"
)

// InstalledHotfix is one row in the on-wire `installedHotfixes` list.
// Whitelist projection — exactly these three fields. No product code,
// MSI GUID, supersedence chain, install client app ID, or account name
// is ever surfaced.
type InstalledHotfix struct {
	// KbId is the canonical KB identifier (e.g. `KB5034122`). Stable
	// across reboots, deduplicable. Required.
	KbId string `json:"kbId"`

	// InstalledOn is the UTC install timestamp. `nil` when the source
	// did not provide a parseable date (e.g. a Get-HotFix row with
	// localised non-RFC-3339 text). Codex 019e8167 must-fix #1.
	InstalledOn *time.Time `json:"installedOn,omitempty"`

	// Description is OPTIONAL bounded display text (e.g. "Security
	// Update for Microsoft Windows"). Truncated at the sanitiser; this
	// struct only defines the contract shape.
	Description string `json:"description,omitempty"`
}

// PendingUpdateItem is one row in the on-wire `pendingUpdates` list.
// Whitelist projection per Codex 019e8167 must-fix #2 — we ship the
// `kbIds` correlation handle + the (category, severity) classification
// only. v1 deliberately does NOT carry the raw update Title because the
// vendor-supplied title is operator-visible noise and a leak vector.
type PendingUpdateItem struct {
	// KbIds is the set of KB identifiers this pending update advertises
	// (typically 1; vendor superseding updates can list multiple).
	// Empty array is permitted when WUA returns no `KBArticleIDs`.
	KbIds []string `json:"kbIds"`

	// PrimaryCategory is the canonical category bucket (see
	// `HotfixPostureCategory`). Updates with multiple categories are
	// reduced via deterministic precedence (security > definition >
	// critical > important > driver > rollup > feature pack > service
	// pack > optional > tools > uncategorized).
	PrimaryCategory HotfixPostureCategory `json:"primaryCategory"`

	// Severity is the MSRC severity rating (see `HotfixPostureSeverity`),
	// `UNSPECIFIED` for non-security updates that lack an MSRC rating.
	Severity HotfixPostureSeverity `json:"severity"`
}

// PendingUpdateCategoryCount is the rollup count for a given category.
// Surfaced even when the per-item list is truncated, so the operator
// can still see "47 SECURITY updates pending" even if only the first 20
// items survived the cap.
type PendingUpdateCategoryCount struct {
	Category HotfixPostureCategory `json:"category"`
	Count    int                   `json:"count"`
}

// WindowsUpdateAgentHealth captures the WUA / BITS / policy health
// snapshot that contextualises the install / pending lists.
//
// Codex 019e8167 must-fix #4 + #5: service state is a typed enum (not
// `*bool`); auto-update is split into policy-effective + the registry
// notification level rather than a single composite bool.
type WindowsUpdateAgentHealth struct {
	// WuaServiceState — `wuauserv` SCM state.
	WuaServiceState ServiceState `json:"wuaServiceState"`

	// BitsServiceState — `bits` SCM state (transport for WUA).
	BitsServiceState ServiceState `json:"bitsServiceState"`

	// LastDetectAt — registry `LastSuccessTime` for the last
	// successful detect attempt. UTC; `nil` when the registry path is
	// absent (e.g. domain-joined endpoint with policy override).
	LastDetectAt *time.Time `json:"lastDetectAt,omitempty"`

	// LastInstallAt — registry `LastSuccessTime` for the last
	// successful install. UTC; `nil` if absent.
	LastInstallAt *time.Time `json:"lastInstallAt,omitempty"`

	// AutoUpdatePolicyEnabled — `*bool` reflecting the `NoAutoUpdate`
	// AU policy registry value (false=auto-update permitted by policy,
	// true=disabled). `nil` when registry is unavailable or the key is
	// missing (default-by-OS).
	AutoUpdatePolicyEnabled *bool `json:"autoUpdatePolicyEnabled,omitempty"`

	// AutoUpdateEffectiveEnabled — composite: policy permits AND
	// service is RUNNING. `nil` when either side could not be
	// determined.
	AutoUpdateEffectiveEnabled *bool `json:"autoUpdateEffectiveEnabled,omitempty"`

	// NotificationLevel — `auOptions` registry value as the canonical
	// string (e.g. `"1=DISABLED"`, `"2=NOTIFY_BEFORE_DOWNLOAD"`,
	// `"3=NOTIFY_BEFORE_INSTALL"`, `"4=SCHEDULED_INSTALL"`). Empty when
	// registry is unavailable.
	NotificationLevel string `json:"notificationLevel,omitempty"`
}

// HotfixPostureResult is the on-wire AG-037 v1 payload block. The
// snapshot envelope folds the deviceId / collectedAt / probeDurationMs
// metadata around this contract block; the result itself is what gets
// validated against the cross-repo contract schema.
type HotfixPostureResult struct {
	// SchemaVersion = `HotfixPostureSchemaVersion`.
	SchemaVersion int `json:"schemaVersion"`

	// Supported is `false` on non-Windows runtimes.
	Supported bool `json:"supported"`

	// ProbeComplete is `false` when ANY section reported an error. Use
	// this gate to render "evidence incomplete" rather than letting a
	// partial snapshot read as "fully patched".
	ProbeComplete bool `json:"probeComplete"`

	// CollectedAt is the moment this snapshot was assembled, UTC.
	CollectedAt time.Time `json:"collectedAt"`

	// ProbeDurationMs is the wall-clock duration of the entire probe
	// (Codex 019e8167 must-fix #6, mirrors AG-030..033/036/038).
	ProbeDurationMs int64 `json:"probeDurationMs"`

	// InstalledSourceUsed — which canonical source produced the
	// installed list (WUA QueryHistory primary, Get-HotFix fallback).
	InstalledSourceUsed HotfixPostureSource `json:"installedSourceUsed"`

	// InstalledHotfixes is the (possibly capped) list. See
	// `MaxInstalledHotfixes`.
	InstalledHotfixes []InstalledHotfix `json:"installedHotfixes,omitempty"`

	// InstalledCount is the PRE-TRUNCATION total. So if
	// `installedTruncated=true`, `installedCount > len(installedHotfixes)`.
	InstalledCount int `json:"installedCount"`

	// InstalledTruncated — `true` when the cap was hit.
	InstalledTruncated bool `json:"installedTruncated,omitempty"`

	// PendingSourceUsed — which canonical source produced the pending
	// list (WUA Search; no fallback).
	PendingSourceUsed HotfixPostureSource `json:"pendingSourceUsed"`

	// PendingUpdates is the (possibly capped) per-item list (see
	// `MaxPendingUpdates`). May be empty when `pendingTotalCount > 0`
	// only if the cap was hit (`pendingTruncated=true`); otherwise
	// empty means "no pending updates".
	PendingUpdates []PendingUpdateItem `json:"pendingUpdates,omitempty"`

	// PendingByCategory is the category rollup. Surfaced even when
	// `pendingTruncated=true` so the operator can see the full
	// distribution.
	PendingByCategory []PendingUpdateCategoryCount `json:"pendingByCategory,omitempty"`

	// PendingTotalCount is the PRE-TRUNCATION total.
	PendingTotalCount int `json:"pendingTotalCount"`

	// PendingTruncated — `true` when the per-item cap was hit.
	PendingTruncated bool `json:"pendingTruncated,omitempty"`

	// HealthSourceUsed — composite source attribution; typically
	// `service` (SCM) + `registry` (timestamps + policy). Single
	// reported value is the dominant authority; per-field nil flags
	// the partial paths.
	HealthSourceUsed HotfixPostureSource `json:"healthSourceUsed"`

	// AgentHealth — WUA/BITS state + timestamps + AU policy. Always
	// present in the struct; individual fields may be nil.
	AgentHealth WindowsUpdateAgentHealth `json:"agentHealth"`

	// ProbeErrors is the typed error list. Empty when probe ran clean;
	// any entry flips `probeComplete=false`.
	ProbeErrors []HotfixPostureProbeError `json:"probeErrors,omitempty"`
}
