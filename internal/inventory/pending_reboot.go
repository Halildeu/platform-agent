package inventory

import "time"

// AG-030 — Pending Reboot Detection (Faz 22.5.2 posture quartet).
//
// Read-only registry-based probe for the canonical Windows reboot
// markers that vendor / SCCM / enterprise script practice considers
// authoritative. The probe never triggers a reboot, never asks the
// user, never mutates state — it answers a single question:
// "would a reboot now clear pending OS-level state?".
//
// HARD BOUNDARIES (locked in the plan-time Codex consensus):
//
//   - **Read-only.** No reboot, no service restart, no kernel ops.
//     Registry reads only; raw values do not leak to the wire.
//
//   - **Opt-in via includePendingReboot payload bit.** Default
//     COLLECT_INVENTORY does NOT call this probe. AG-025H lightweight
//     guard pattern: `pendingReboot` is `omitempty` on the snapshot
//     and is only populated when the command-payload explicitly
//     requests it.
//
//   - **Signal-level explicit struct.** The wire contract surfaces
//     each canonical marker as a typed bool so backend/UI/policy
//     can distinguish "missing key = false" (no reboot pending from
//     that source) from "access denied = probe error" (incomplete
//     evidence).
//
//   - **Supported false ≠ pendingReboot false.** Non-Windows runtime
//     returns `supported=false`, `probeComplete=false`, with a
//     PendingRebootProbeError carrying the UNSUPPORTED_PLATFORM code.
//     Caller cannot infer "no reboot needed" from an unsupported
//     stub; they get explicit incomplete-evidence signaling.
//
//   - **No raw value leakage.** ComputerName comparison reports a
//     pending change as a bool only; raw computer names never reach
//     the wire (they're stable host identifiers, not credentials,
//     but the agent's posture inventory is not the right place to
//     leak them either). PendingFileRenameOperations entry count is
//     not surfaced — only the bool that the MULTI_SZ is non-empty.

// PendingRebootSchemaVersion is bumped on non-additive schema changes
// to PendingRebootResult. v1 ships as 1.
const PendingRebootSchemaVersion = 1

// PendingRebootSource enumerates the canonical Windows reboot
// markers AG-030 v1 detects. Adding a new source is a non-breaking
// schema change (additive field on PendingRebootSignals + new
// PendingRebootSource constant); shipping a source rename or removal
// is a schema bump.
type PendingRebootSource string

const (
	PendingRebootSourceCBS                         PendingRebootSource = "CBS_REBOOT_PENDING"
	PendingRebootSourceWindowsUpdate               PendingRebootSource = "WINDOWS_UPDATE_REBOOT_REQUIRED"
	PendingRebootSourcePendingFileRenameOperations PendingRebootSource = "PENDING_FILE_RENAME_OPERATIONS"
	PendingRebootSourceComputerNameChange          PendingRebootSource = "COMPUTER_NAME_CHANGE_PENDING"
	PendingRebootSourceUpdateExeVolatile           PendingRebootSource = "UPDATE_EXE_VOLATILE"
	PendingRebootSourceNetlogonJoinPending         PendingRebootSource = "NETLOGON_JOIN_PENDING"
)

// PendingRebootSignals is the explicit-bool struct backend / UI /
// policy consume. Each field corresponds to one PendingRebootSource;
// a probe-error on that source leaves the field false AND adds an
// entry to PendingRebootResult.ProbeErrors so the consumer can tell
// "absent" from "incomplete".
//
// All six fields ship without `omitempty` (Codex 019e749c post-impl
// P0#2): the contract is that every signal key is present in the
// wire payload regardless of value, so backend/UI cannot mis-read
// "key missing" as "false". `false` is a positive answer ("this
// source did not fire"), not absence of evidence.
type PendingRebootSignals struct {
	CBSRebootPending            bool `json:"cbsRebootPending"`
	WindowsUpdateRebootRequired bool `json:"windowsUpdateRebootRequired"`
	PendingFileRenameOperations bool `json:"pendingFileRenameOperations"`
	ComputerNameChangePending   bool `json:"computerNameChangePending"`
	UpdateExeVolatile           bool `json:"updateExeVolatile"`
	NetlogonJoinPending         bool `json:"netlogonJoinPending"`
}

// PendingRebootProbeError carries a structured probe-level failure
// reason. Code is a stable enum string (no free-text fingerprints).
// Summary is a short operator-facing reason ("access denied",
// "value type mismatch", "registry hive unavailable") with no raw
// registry value or PII.
type PendingRebootProbeError struct {
	Source  PendingRebootSource `json:"source,omitempty"`
	Code    string              `json:"code"`
	Summary string              `json:"summary,omitempty"`
}

// PendingRebootProbeError codes — stable enum, expand by PR.
const (
	PendingRebootErrUnsupportedPlatform  = "UNSUPPORTED_PLATFORM"
	PendingRebootErrAccessDenied         = "ACCESS_DENIED"
	PendingRebootErrRegistryUnavailable  = "REGISTRY_UNAVAILABLE"
	PendingRebootErrValueTypeMismatch    = "VALUE_TYPE_MISMATCH"
	PendingRebootErrInternal             = "PROBE_INTERNAL"
)

// PendingRebootResult is the wire-safe outcome. Snapshot includes
// it via `*PendingRebootResult json:"pendingReboot,omitempty"`; the
// pointer is nil when the caller did not request the probe.
//
// Boolean precedence rule (Codex 019e749c iter-1 P0#3 absorb):
//
//   - `pendingReboot` is the OR of all populated signals. It is
//     `true` if and only if at least one PendingRebootSignals bool
//     is `true`.
//   - `probeComplete` is `true` when every source the probe attempted
//     produced a definitive bool (either explicit true or "missing
//     key = false"). A single PendingRebootProbeError flips it to
//     `false`.
//   - On non-Windows runtimes: `supported=false`, `probeComplete=false`,
//     `pendingReboot=false` (no positive evidence), and a single
//     UNSUPPORTED_PLATFORM error entry. Caller MUST treat
//     `probeComplete=false` as "evidence incomplete" — not "no
//     reboot needed".
type PendingRebootResult struct {
	SchemaVersion   int                       `json:"schemaVersion"`
	Supported       bool                      `json:"supported"`
	PendingReboot   bool                      `json:"pendingReboot"`
	ProbeComplete   bool                      `json:"probeComplete"`
	Signals         PendingRebootSignals      `json:"signals"`
	Sources         []PendingRebootSource     `json:"sources,omitempty"`
	ProbeErrors     []PendingRebootProbeError `json:"probeErrors,omitempty"`
	ProbeDurationMs int                       `json:"probeDurationMs"`
}

// derivePendingRebootSummary fills the derived fields
// (PendingReboot, ProbeComplete, Sources) from the per-source
// Signals + ProbeErrors. The Windows runner builds the input
// fields; this helper is the single source of truth for the
// summary rules so the unsupported stub and the live Windows path
// stay aligned.
func derivePendingRebootSummary(result *PendingRebootResult) {
	signals := result.Signals
	sources := result.Sources[:0]

	if signals.CBSRebootPending {
		sources = append(sources, PendingRebootSourceCBS)
	}
	if signals.WindowsUpdateRebootRequired {
		sources = append(sources, PendingRebootSourceWindowsUpdate)
	}
	if signals.PendingFileRenameOperations {
		sources = append(sources, PendingRebootSourcePendingFileRenameOperations)
	}
	if signals.ComputerNameChangePending {
		sources = append(sources, PendingRebootSourceComputerNameChange)
	}
	if signals.UpdateExeVolatile {
		sources = append(sources, PendingRebootSourceUpdateExeVolatile)
	}
	if signals.NetlogonJoinPending {
		sources = append(sources, PendingRebootSourceNetlogonJoinPending)
	}
	result.Sources = sources
	result.PendingReboot = len(sources) > 0
	result.ProbeComplete = len(result.ProbeErrors) == 0
}

// pendingRebootElapsedMs is the monotonic-duration helper. Exported
// only inside the package so tests can inject a deterministic clock.
func pendingRebootElapsedMs(start time.Time, now func() time.Time) int {
	if now == nil {
		now = time.Now
	}
	return int(now().Sub(start) / time.Millisecond)
}
