// Package winget exposes read-only WinGet App Installer readiness
// probes for AG-026 (basic `--version` health) and AG-026A (source
// list parser + fixed-id package query + egress reachability).
//
// Hard boundary (verbatim — do not weaken):
//
//   - The package NEVER runs `winget install`, `winget upgrade`,
//     `winget uninstall`, `winget settings`, `winget export`,
//     `winget import`, `winget hash`, `winget validate`, `winget pin`,
//     `winget configure`, `winget download`, `winget repair`,
//     `winget features`, `winget complete`, `winget debug`, or any
//     `winget source` mutation (`add`, `remove`, `update`, `reset`).
//   - Read-only surface allowed:
//       * AG-026 `Detect` → `winget --version` (fixed argv).
//       * AG-026A `DetectSourceEgress` → `winget source list` (fixed
//         argv) + `winget show --id 7zip.7zip --exact
//         --disable-interactivity` (hard-coded package id).
//     Every argv element is constructed inside this package — no
//     caller path can inject an alternative subcommand or argument.
//   - `availableInCurrentContext` and `systemContextReady` (AG-026)
//     are SEPARATE signals. Plenty of hosts have winget.exe on disk
//     but cannot invoke it from a LocalSystem service (no source
//     agreements accepted, no AppX alias, no per-user PATH). The
//     probe reports both so the backend can pick the right rollout
//     strategy downstream without conflating them.
//   - AG-026A readiness signals (PASS / WARN / BLOCK semantics via
//     SourceEgressReadiness.SourceListError, .PackageQuery.ErrorReason,
//     .Egress.*[].ErrorReason, .Timeout) are reachability evidence —
//     NOT install authority. The install decision lives in
//     BE-020 (approved catalog) + BE-021A (preflight contract) +
//     AG-027 (executor), not here.
package winget

// SchemaVersion is bumped when a non-additive change ships.
const SchemaVersion = 1

// DefaultProbeTimeout is the wall-clock budget for the entire probe.
// 5 seconds covers cold-start AppX activation on Windows 11 IT pilot
// hosts without keeping the COLLECT_INVENTORY command hanging when
// winget is misbehaving (msstore reset, source repair prompt, etc.).
const DefaultProbeTimeout = 5 // seconds

// Readiness is the wire-safe probe result. Field rules:
//
//   - supported is false on non-Windows; everything else is then
//     trivially false / zero and the rest of the struct is informational.
//   - availableInCurrentContext means "the locator found winget.exe
//     for the current process context" — nothing more. It does NOT
//     imply that the version probe ran or succeeded. A host can flag
//     available=true and still fail to install anything (no source
//     agreements, no AppX activation, etc.).
//   - systemContextReady is the stricter sibling: winget was located
//     AND responded within the timeout budget AND the version string
//     parsed. The two fields are decoupled on purpose — see HIGH 2.
//   - executablePath is sanitised (the user-segment of any
//     "C:\Users\<name>\…" path is redacted via
//     security.RedactSoftwareString) so the wire payload doesn't leak
//     interactive-user names from %LOCALAPPDATA%.
//   - probeError, when set, is also sanitised before being assigned.
type Readiness struct {
	Supported                 bool   `json:"supported"`
	AvailableInCurrentContext bool   `json:"availableInCurrentContext"`
	SystemContextReady        bool   `json:"systemContextReady"`
	ExecutablePath            string `json:"executablePath,omitempty"`
	Version                   string `json:"version,omitempty"`
	ProbeError                string `json:"probeError,omitempty"`
	ProbeDurationMs           int    `json:"probeDurationMs"`
	Timeout                   bool   `json:"timeout"`
	SchemaVersion             int    `json:"schemaVersion"`
}
