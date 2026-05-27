// Package software exposes a read-only Windows installed-software inventory
// for AG-025. It enumerates HKLM (and HKLM\WOW6432Node) Uninstall registry
// hives via the native golang.org/x/sys/windows/registry binding — no shell
// out, no PowerShell wrapper.
//
// Boundary discipline (verbatim from spawn brief HIGH 1/2/3):
//
//  1. HKCU under LocalSystem (S-1-5-18) is NOT a human user — default scope
//     is HKLM only. If callers ever extend scope to HKCU they must label the
//     installSource as HKCU_AGENT_CONTEXT to make the misleading scope
//     explicit; per-user inventory of real interactive users requires
//     enumerating loaded HKEY_USERS\<SID> hives and is a separate ticket.
//
//  2. The full UninstallString never leaves the agent process: it can carry
//     license keys, user paths and vendor tokens, and it is too easy to
//     re-purpose as a raw uninstall primitive. The wire payload exposes only
//     a presence bool plus, for MSI packages, the SHA-256 hash of the MSI
//     ProductCode GUID — never the raw GUID, never the raw command.
//
//  3. This package never installs, uninstalls, repairs, downloads, or
//     elevates anything. It is enumerate-and-report only. Anything that
//     mutates installed state must live behind BE-020 (Approved Software
//     Catalog) plus a dedicated agent install adapter (AG-027 and later).
package software

import "time"

// SchemaVersion is bumped when a non-additive change ships. Existing
// consumers can pin to the version and additive fields are tolerated.
const SchemaVersion = 1

// SourceHKLM64 / SourceHKLM32 / SourceHKCUAgentContext are the only
// permitted values for InstalledApp.InstallSource. The HKCU_AGENT_CONTEXT
// label is reserved for future scope expansion and is never emitted by the
// default collector — it exists so the schema can distinguish "real HKLM
// install" from "HKCU under LocalSystem hive" if a later agent code path
// ever opts into HKCU enumeration.
const (
	SourceHKLM64           = "HKLM"
	SourceHKLM32           = "HKLM_WOW6432"
	SourceHKCUAgentContext = "HKCU_AGENT_CONTEXT"
)

// DefaultMaxApps caps the number of InstalledApp entries returned in a
// single snapshot. The cap is a defence-in-depth knob against runaway
// payloads (1000+ apps is normal on dev laptops; the cap protects backend
// JSONB ingest against pathological hosts). The collector reports the cap
// as Truncated when it hits the limit so the backend can flag the host.
const DefaultMaxApps = 5000

// DefaultMaxPayloadBytes is the soft cap on the JSON-serialised Apps slice
// (note: applied after sanitisation, before non-Apps fields are added).
// Encoding stops early and the snapshot is marked Truncated when this is
// exceeded.
const DefaultMaxPayloadBytes = 1 * 1024 * 1024

// InstalledApp is the wire-safe representation of a single installed
// product. Field rules:
//
//   - displayName is required for inclusion. Entries without it are
//     dropped during parsing (Windows uses placeholder Uninstall keys for
//     KB hotfixes and updates that have no human-readable name).
//   - uninstallStringPresent reports whether the registry carried a
//     non-empty UninstallString OR QuietUninstallString without leaking the
//     value. Callers who need the actual command must use a privileged,
//     scoped, audited code path that does not live in this package.
//   - msiProductCodeHash is the SHA-256 hash of the MSI ProductCode GUID,
//     emitted only for MSI-installed apps (subkey name matches
//     "{########-####-####-####-############}"). The raw GUID is never
//     emitted because GUIDs can be reversed against public MSI metadata
//     databases that expose vendor inventories.
type InstalledApp struct {
	DisplayName            string `json:"displayName"`
	DisplayVersion         string `json:"displayVersion,omitempty"`
	Publisher              string `json:"publisher,omitempty"`
	InstallDate            string `json:"installDate,omitempty"`
	EstimatedSizeKB        int    `json:"estimatedSizeKb,omitempty"`
	Architecture           string `json:"architecture,omitempty"`
	InstallSource          string `json:"installSource"`
	UninstallStringPresent bool   `json:"uninstallStringPresent"`
	MSIProductCodeHash     string `json:"msiProductCodeHash,omitempty"`
}

// SoftwareSnapshot is the package-level result the diagnose subcommand
// dumps to stdout and the inventory wiring summarises into the backend
// payload. On non-Windows the snapshot has Supported=false and Reason set
// so callers can branch without inspecting OS family separately.
type SoftwareSnapshot struct {
	Supported     bool           `json:"supported"`
	Reason        string         `json:"reason,omitempty"`
	SchemaVersion int            `json:"schemaVersion"`
	Apps          []InstalledApp `json:"apps,omitempty"`
	AppCount      int            `json:"appCount"`
	TotalSizeKB   int            `json:"totalSizeKb,omitempty"`
	Truncated     bool           `json:"truncated,omitempty"`
	ProbeErrors   []string       `json:"probeErrors,omitempty"`
	CollectedAt   time.Time      `json:"collectedAt"`
}

// Summary is the aggregate the COLLECT_INVENTORY payload embeds when the
// caller explicitly opts into the full software block via
// includeSoftware=true (AG-025H). It NEVER ships on heartbeat / auto-enroll
// payloads — the AG-025H lightweight default leaves Snapshot.Software nil
// so the wire payload omits the software field entirely. Two shapes share
// the struct when it IS attached:
//
//   - Apps == nil (legacy "summary only"): rollup figures from the
//     underlying SoftwareSnapshot without shipping the per-app metadata.
//     This shape is reserved for explicit summary-only requests; it is
//     not the heartbeat default any more.
//   - Apps populated ("include full list"): the COLLECT_INVENTORY caller
//     passed includeSoftware=true and Apps is populated. The size caps
//     already enforced by Normalize still apply.
//
// The two shapes share one field so backends only need one JSONB column;
// payload stays well under the existing inventory details budget because
// Apps is omitempty.
type Summary struct {
	Supported     bool           `json:"supported"`
	AppCount      int            `json:"appCount"`
	WinGetReady   bool           `json:"wingetReady"`
	WinGetVersion string         `json:"wingetVersion,omitempty"`
	SchemaVersion int            `json:"schemaVersion"`
	TotalSizeKB   int            `json:"totalSizeKb,omitempty"`
	Truncated     bool           `json:"truncated,omitempty"`
	ProbeErrors   []string       `json:"probeErrors,omitempty"`
	Apps          []InstalledApp `json:"apps,omitempty"`
}

// CollectOptions controls how Collect populates the snapshot. Zero value
// gives the safe defaults (HKLM only, default caps).
//
// Note on the absent HKCU knob: a future "real per-user inventory"
// path is intentionally NOT exposed here. That work needs to walk
// `HKEY_USERS\<SID>` for *loaded* interactive-user hives (HIGH 1) and
// is a separate ticket. Adding an IncludeHKCU toggle to this struct
// today would invite callers to flip it under LocalSystem and get the
// S-1-5-18 service-account hive — which is exactly the misleading
// scope the HIGH 1 boundary forbids. Codex peer review iter-1
// (thread 019e691c) flagged a dormant field; remediation is "do not
// add the field, document the gap".
type CollectOptions struct {
	MaxApps         int // 0 → DefaultMaxApps
	MaxPayloadBytes int // 0 → DefaultMaxPayloadBytes
}
