// Package winget exposes a read-only WinGet App Installer readiness
// probe for AG-026. It tells the backend whether winget.exe is on the
// host and whether the LocalSystem service context can invoke it
// without prompting — nothing more.
//
// Hard boundary (HIGH 2 in the spawn brief):
//
//   - This package NEVER runs `winget install`, `winget search`,
//     `winget source`, `winget upgrade`, `winget export`, or
//     `winget settings`. The only subcommand invoked is `--version`,
//     with fixed args, no user-controlled input on the argv.
//   - `availableInCurrentContext` and `systemContextReady` are SEPARATE
//     signals. Plenty of hosts have winget.exe on disk but cannot
//     invoke it from a LocalSystem service (no source agreements
//     accepted, no AppX alias, no per-user PATH). The probe reports
//     both so the backend can pick the right rollout strategy
//     downstream without conflating them.
//   - A successful probe does NOT mean "this host is deployment-ready
//     for WinGet installs" — that decision lives in BE-020 + AG-027,
//     not here.
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
//   - availableInCurrentContext means "we found winget.exe on disk AND
//     it returned a version string within the timeout". It does NOT
//     mean "winget can install something right now".
//   - systemContextReady is the stricter sibling: winget responded
//     within budget, the version string parsed, and there was no
//     timeout. The two fields are decoupled on purpose — see HIGH 2.
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
