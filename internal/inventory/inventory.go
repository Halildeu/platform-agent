package inventory

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"runtime"
	"strings"
	"time"

	"platform-agent/internal/identity"
	"platform-agent/internal/protocol"
	"platform-agent/internal/software"
	"platform-agent/internal/winget"
)

type Snapshot struct {
	Hostname     string             `json:"hostname"`
	OSFamily     protocol.OSFamily  `json:"osFamily"`
	OSName       string             `json:"osName"`
	Architecture string             `json:"architecture"`
	AgentVersion string             `json:"agentVersion"`
	CollectedAt  time.Time          `json:"collectedAt"`
	Identity     identity.Inventory `json:"identity"`
	// Software is intentionally nil unless the caller opted into the full
	// software/WinGet block via CollectOptions.IncludeSoftwareApps. The
	// JSON tag omitempty hides the field from the heartbeat / auto-enroll
	// wire payload when the lightweight default applies (AG-025H).
	Software *software.Summary `json:"software,omitempty"`
	// WinGetEgress is intentionally nil unless the caller opted into the
	// AG-026A WinGet source/egress preflight via
	// CollectOptions.IncludeWinGetEgress. The JSON tag omitempty hides
	// the field from the heartbeat / auto-enroll wire payload and from
	// COLLECT_INVENTORY runs that did not request the preflight, so the
	// lightweight default never pays the source-list + package-query +
	// DNS/TCP/HTTPS probe cost.
	WinGetEgress *winget.SourceEgressReadiness `json:"wingetEgress,omitempty"`
	// Hardware is intentionally nil unless the caller opted into the
	// AG-035 hardware probe via CollectOptions.IncludeHardware. The
	// JSON tag omitempty hides the field from the heartbeat /
	// auto-enroll wire payload and from COLLECT_INVENTORY runs that did
	// not request the probe, so the lightweight default never pays the
	// PowerShell + WMI/CIM cost. On non-Windows runtimes the probe
	// returns Supported=false with the canonical OS metadata so the
	// backend can persist evidence of "agent does not support hardware
	// probe here" instead of treating the absence as a failed ingest.
	Hardware *Hardware `json:"hardware,omitempty"`

	// PendingReboot is intentionally nil unless the caller opted into
	// the AG-030 pending-reboot probe via
	// CollectOptions.IncludePendingReboot. The probe is registry-only
	// and cheap, but the AG-025H lightweight contract still applies —
	// heartbeat / auto-enroll never opt in. On non-Windows runtimes
	// the probe returns Supported=false + ProbeComplete=false + a
	// single UNSUPPORTED_PLATFORM error entry (the structured "no
	// positive evidence + evidence incomplete" pair); callers MUST
	// NOT infer "no reboot needed" from a non-Windows result.
	PendingReboot *PendingRebootResult `json:"pendingReboot,omitempty"`

	// SecurityPosture is intentionally nil unless the caller opted into
	// the AG-031 endpoint security posture probe via
	// CollectOptions.IncludeSecurityPosture. The probe shells out to
	// powershell.exe (Get-MpComputerStatus + Get-CimInstance
	// SecurityCenter2 + Get-NetFirewallProfile + Get-BitLockerVolume)
	// once, with a 30-second deadline, and emits a wire-safe roll-up
	// covering antivirus, host firewall and drive encryption. On
	// non-Windows runtimes the probe returns Supported=false +
	// ProbeComplete=false + UNSUPPORTED_PLATFORM error; callers MUST
	// NOT infer "host is unprotected" from a non-Windows result.
	SecurityPosture *SecurityPostureResult `json:"securityPosture,omitempty"`

	// LocalAdminGroup is intentionally nil unless the caller opted
	// into the AG-032 direct local-administrators alias enumeration
	// via CollectOptions.IncludeLocalAdminGroup. The probe is
	// strictly identifier-leak-free: drive letters, GUIDs, account
	// names, full SIDs, RIDs, domain SID prefixes — none reach the
	// wire. Only typed Kind enum + bool scope/risk flags + count
	// totals + bounded Members slice. On non-Windows runtimes the
	// probe returns Supported=false + ProbeComplete=false +
	// UNSUPPORTED_PLATFORM. See COMMAND-CONTRACT.md §14.
	LocalAdminGroup *LocalAdminGroupResult `json:"localAdminGroup,omitempty"`

	// DeviceHealth is intentionally nil unless the caller opted into
	// the AG-033 device health snapshot via
	// CollectOptions.IncludeDeviceHealth. The probe reads via direct
	// Win32 syscalls (GetLogicalDrives + GetDiskFreeSpaceEx +
	// GlobalMemoryStatusEx + DurationSinceBoot) — no PowerShell, no
	// WMI, no performance-counter sampling. It surfaces fixed-disk
	// free %, memory utilization %, uptime/last-boot, and warning
	// booleans for a pre-deployment health gate. On non-Windows
	// runtimes the probe returns Supported=false + ProbeComplete=false
	// + UNSUPPORTED_PLATFORM. See COMMAND-CONTRACT.md §15.
	DeviceHealth *DeviceHealthResult `json:"deviceHealth,omitempty"`
	// OutdatedSoftware is intentionally nil unless the caller opted into
	// the AG-036 outdated-software probe via
	// CollectOptions.IncludeOutdatedSoftware. The JSON tag omitempty
	// hides the field from the heartbeat / auto-enroll wire payload
	// and from COLLECT_INVENTORY runs that did not request the probe.
	// On non-Windows runtimes the probe returns Supported=false with
	// the canonical OS metadata so the backend can persist evidence of
	// "agent does not support outdated-software probe here" instead
	// of treating the absence as a failed ingest.
	OutdatedSoftware *OutdatedSoftwareResult `json:"outdatedSoftware,omitempty"`

	// Diagnostics is intentionally nil unless the caller opted into
	// the AG-038 agent self-diagnostics probe via
	// CollectOptions.IncludeDiagnostics. The JSON tag omitempty
	// hides the field from the heartbeat / auto-enroll wire payload
	// and from COLLECT_INVENTORY runs that did not request the probe.
	// On non-Windows runtimes the probe returns Supported=false with
	// the canonical OS metadata so the backend can persist evidence of
	// "agent does not support diagnostics here" instead of treating
	// the absence as a failed ingest.
	Diagnostics *DiagnosticsResult `json:"diagnostics,omitempty"`

	// HotfixPosture is intentionally nil unless the caller opted into
	// the AG-037 Windows Update / hotfix posture probe via
	// CollectOptions.IncludeHotfixPosture. The JSON tag omitempty
	// hides the field from the heartbeat / auto-enroll wire payload
	// and from COLLECT_INVENTORY runs that did not request the probe.
	// On non-Windows runtimes the probe returns Supported=false +
	// UNSUPPORTED_PLATFORM. The probe is strictly read-only: pinned
	// PowerShell + WUA COM (`Microsoft.Update.Session`) + `Get-HotFix`
	// fallback (installed-only) + SCM service state + AU policy
	// registry reads. NO install/reboot/service mutation is ever
	// performed. See COMMAND-CONTRACT.md §17.
	HotfixPosture *HotfixPostureResult `json:"hotfixPosture,omitempty"`
}

// CollectOptions controls which optional inventory blocks COLLECT_INVENTORY
// asks for. Zero value is the AG-025H lightweight contract: host / os /
// identity only — no software registry enumeration, no WinGet probe,
// no WinGet source/egress preflight. The heartbeat and auto-enroll
// loops keep the zero default and therefore never pay the registry /
// probe / preflight cost.
type CollectOptions struct {
	// IncludeSoftwareApps gates the entire software block. When true,
	// CollectWithOptions enumerates HKLM + HKLM\WOW6432Node, runs the
	// WinGet --version readiness probe, and emits a Summary that includes
	// the full Apps list. When false (the default), the software registry
	// enumeration and the WinGet probe are not invoked at all — the
	// resulting Snapshot.Software stays nil and the wire payload omits it.
	// The backend uses true for explicit COLLECT_INVENTORY scans
	// (includeSoftware=true on the command payload); heartbeat /
	// auto-enroll never opt in.
	IncludeSoftwareApps bool

	// IncludeWinGetEgress gates the AG-026A WinGet source/egress
	// preflight: `winget source list` (read-only, fixed argv),
	// fixed-id `winget show --id 7zip.7zip` package-query reachability
	// probe, and DNS / TCP / HTTPS reachability checks against the
	// hard-coded DefaultEgressTargets list. When true,
	// CollectWithOptions invokes winget.DetectSourceEgress and
	// attaches the result to Snapshot.WinGetEgress. When false (the
	// default), the preflight is not invoked at all and the wire
	// payload omits the field. The backend uses true via
	// COLLECT_INVENTORY's includeWinGetEgress payload bit when an
	// install pilot is being evaluated; heartbeat / auto-enroll /
	// lightweight inventory never opt in.
	//
	// HARD BOUNDARY (Codex 019e6b5d plan-time AGREE): this flag never
	// triggers any install, upgrade, uninstall, or source-mutating
	// subcommand. The preflight is read-only by construction in the
	// winget package (fixed argv, hard-coded package id, hard-coded
	// egress hosts).
	IncludeWinGetEgress bool

	// IncludeHardware gates the AG-035 hardware probe. When true,
	// CollectWithOptions runs CollectHardware (PowerShell +
	// Get-CimInstance on Windows; a Supported=false stub on every
	// other platform) and attaches the result to Snapshot.Hardware.
	// When false (the default), the probe is not invoked and the wire
	// payload omits the field.
	//
	// The backend uses true via COLLECT_INVENTORY's includeHardware
	// payload bit when a hardware snapshot is being requested (manual
	// "Envanteri Şimdi Topla" UI action, scheduled hardware sweep,
	// pre-install evidence collection). Heartbeat / auto-enroll /
	// lightweight inventory never opt in.
	//
	// HARD BOUNDARY: the probe is read-only by construction — it
	// invokes Get-CimInstance with -ErrorAction Continue and never
	// mutates CIM state. There is no remediation surface and no
	// administrator credential required beyond what the agent already
	// runs under (LocalSystem on Windows).
	IncludeHardware bool

	// IncludePendingReboot gates the AG-030 pending-reboot probe.
	// When true, CollectWithOptions invokes ProbePendingReboot and
	// attaches the result to Snapshot.PendingReboot. When false (the
	// default), the probe is not invoked and the wire payload omits
	// the field.
	//
	// The backend uses true via COLLECT_INVENTORY's
	// includePendingReboot payload bit when a posture refresh is
	// requested (Sprint B P1 visibility expansion, pre-install
	// evidence collection, scheduled posture sweep). Heartbeat /
	// auto-enroll / lightweight inventory never opt in.
	//
	// HARD BOUNDARY: the probe is read-only by construction. It
	// opens registry handles with QUERY_VALUE | WOW64_64KEY and
	// never sets, creates, or deletes a key. Raw value contents
	// (PendingFileRenameOperations entries, computer-name strings)
	// are NEVER surfaced to the wire — only the derived signal
	// booleans. There is no remediation surface and no reboot
	// trigger; the agent only reports posture.
	IncludePendingReboot bool

	// IncludeSecurityPosture gates the AG-031 endpoint security
	// posture probe. When true, CollectWithOptions invokes
	// ProbeSecurityPosture and attaches the result to
	// Snapshot.SecurityPosture. When false (the default), the probe
	// is not invoked and the wire payload omits the field.
	//
	// The backend uses true via COLLECT_INVENTORY's
	// includeSecurityPosture payload bit when a posture refresh is
	// requested (Sprint B P1 visibility expansion AG-031, pre-install
	// evidence collection, scheduled posture sweep). Heartbeat /
	// auto-enroll / lightweight inventory never opt in.
	//
	// HARD BOUNDARY: the probe is read-only by construction. It runs
	// one PowerShell process with `-NoProfile -NonInteractive`, a
	// pinned script, and no payload-supplied substitution. The script
	// only calls reader cmdlets (Get-MpComputerStatus,
	// Get-CimInstance root\SecurityCenter2, Get-NetFirewallProfile,
	// Get-BitLockerVolume); no Set-/Disable-/Enable-/Add-/Remove-
	// cmdlet appears in the source. Drive letters, mountpoints,
	// volume GUIDs, recovery passwords, key protectors, and
	// third-party AV product names are NEVER surfaced to the wire —
	// only counts, booleans and bounded enum values.
	IncludeSecurityPosture bool

	// IncludeLocalAdminGroup gates the AG-032 direct local
	// Built-in Administrators alias enumeration probe. When true,
	// CollectWithOptions invokes ProbeLocalAdminGroup (NetAPI
	// primary → PowerShell LocalAccounts fallback → WMI
	// last-resort) and attaches the result to
	// Snapshot.LocalAdminGroup. When false (the default), the
	// probe is not invoked and the wire payload omits the field.
	//
	// HARD BOUNDARY: read-only NetAPI / PowerShell enumeration.
	// NEVER mutates group membership. NEVER emits raw SID bytes,
	// SID family / authority / RID, full SID string, domain SID
	// prefix, account name, display name, description, principal
	// path, or domain name on the wire. ONLY: typed Kind enum +
	// bool scope/risk flags + count totals + bounded Members
	// slice (cap=256, MembersTruncated when exceeded).
	IncludeLocalAdminGroup bool

	// IncludeDeviceHealth gates the AG-033 device health snapshot.
	// When true, CollectWithOptions invokes ProbeDeviceHealth
	// (direct Win32 syscalls on Windows; a Supported=false stub on
	// every other platform) and attaches the result to
	// Snapshot.DeviceHealth. When false (the default), the probe is
	// not invoked and the wire payload omits the field.
	//
	// The backend uses true via COLLECT_INVENTORY's
	// includeDeviceHealth payload bit when a pre-deployment health
	// gate is being evaluated. Heartbeat / auto-enroll /
	// lightweight inventory never opt in.
	//
	// HARD BOUNDARY: read-only point-in-time syscalls. No
	// performance-counter sampling, no per-process enumeration, no
	// continuous polling. Volume labels / serial numbers /
	// file-system types / mount paths / volume GUIDs are NEVER
	// surfaced — only the drive letter + byte totals + derived
	// percent/warning. Health thresholds are const, not
	// payload-configurable.
	IncludeDeviceHealth bool

	// IncludeOutdatedSoftware gates the AG-036 outdated-software probe.
	// When true, CollectWithOptions invokes ProbeOutdatedSoftware
	// (winget --include-returning-apps on Windows; a Supported=false
	// stub on every other platform) and attaches the result to
	// Snapshot.OutdatedSoftware. When false (the default), the probe
	// is not invoked and the wire payload omits the field.
	//
	// The backend uses true via COLLECT_INVENTORY's
	// includeOutdatedSoftware payload bit when an upgrade eligibility
	// scan is being evaluated. Heartbeat / auto-enroll /
	// lightweight inventory never opt in.
	//
	// HARD BOUNDARY: read-only. `winget upgrade --include-returning-apps`
	// never mutates any package state. Per-package wire fields are
	// packageId + installedVersion + availableVersion (the two version
	// strings are required for upgrade-eligibility detection and are
	// public, non-PII). EXCLUDED PII (never serialized): name,
	// publisher, install location, license, and download URL — narrowing
	// the PII surface per the AG-036 spec. The OutdatedSoftwarePackage
	// JSON-keys regression test pins this exact key set.
	IncludeOutdatedSoftware bool

	// IncludeDiagnostics gates the AG-038 agent self-diagnostics
	// probe. When true, CollectWithOptions invokes ProbeDiagnostics
	// (DNS lookup + TLS handshake on Windows; a Supported=false stub
	// on every other platform) and attaches the result to
	// Snapshot.Diagnostics. When false (the default), the probe is not
	// invoked and the wire payload omits the field.
	//
	// The backend uses true via COLLECT_INVENTORY's
	// includeDiagnostics payload bit when an operational health
	// snapshot is being evaluated. Heartbeat / auto-enroll /
	// lightweight inventory never opt in.
	//
	// HARD BOUNDARY: read-only. No PII, credentials, or paths appear
	// in ConfigHash — only SHA-256(version|apiURL). DNS and TLS
	// checks are fire-and-forget with 5s timeout; errors do not block.
	IncludeDiagnostics bool

	// IncludeHotfixPosture gates the AG-037 Windows Update / hotfix
	// posture probe. When true, CollectWithOptions invokes
	// ProbeHotfixPosture (pinned PowerShell + WUA COM
	// `Microsoft.Update.Session` + `Get-HotFix` installed-only fallback
	// + SCM service state + AU policy registry reads on Windows; a
	// Supported=false stub on every other platform) and attaches the
	// result to Snapshot.HotfixPosture. When false (the default), the
	// probe is not invoked and the wire payload omits the field.
	//
	// The backend uses true via COLLECT_INVENTORY's
	// includeHotfixPosture payload bit when a patch posture
	// evaluation is being prepared. Heartbeat / auto-enroll /
	// lightweight inventory never opt in.
	//
	// HARD BOUNDARY: read-only. NO `Install-WindowsUpdate`, NO
	// `wuauclt /detectnow`, NO `sconfig` reboot trigger, NO service
	// start/stop/enable/disable, NO policy mutation. Allowlist
	// projection: per-hotfix `{kbId, installedOn, description}`;
	// per-pending-item `{kbIds, primaryCategory, severity}`. NO raw
	// stdout/stderr, NO account names, NO command lines, NO product
	// codes, NO MSI GUIDs, NO supersedence chains, NO raw update
	// titles in pending items.
	IncludeHotfixPosture bool
}

// Collect returns the AG-025H lightweight default snapshot: host / os /
// identity only, no software registry enumeration, no WinGet probe. It is
// equivalent to CollectWithOptions(agentVersion, now, CollectOptions{}).
// Heartbeat and auto-enroll call this; the registry / probe cost is paid
// only when COLLECT_INVENTORY explicitly opts into full software via
// CollectWithOptions(... IncludeSoftwareApps: true ...).
func Collect(agentVersion string, now time.Time) Snapshot {
	return CollectWithOptions(agentVersion, now, CollectOptions{})
}

// CollectWithOptions is the COLLECT_INVENTORY entry point. When
// opts.IncludeSoftwareApps is true, the software registry enumeration and
// the WinGet --version readiness probe run and a full Summary (including
// the Apps list under the package's size caps) is attached. When false
// (the heartbeat / auto-enroll default), neither probe runs and
// Snapshot.Software stays nil.
func CollectWithOptions(agentVersion string, now time.Time, opts CollectOptions) Snapshot {
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}
	snapshot := Snapshot{
		Hostname:     hostname,
		OSFamily:     RuntimeOSFamily(),
		OSName:       runtime.GOOS,
		Architecture: runtime.GOARCH,
		AgentVersion: agentVersion,
		CollectedAt:  now,
		Identity:     identity.Collect(now),
	}
	if opts.IncludeSoftwareApps {
		snapshot.Software = collectSoftwareSummary(now, true)
	}
	if opts.IncludeWinGetEgress {
		readiness := detectSourceEgress(now)
		snapshot.WinGetEgress = &readiness
	}
	if opts.IncludeHardware {
		hw := collectHardwareForSnapshot(now)
		snapshot.Hardware = &hw
	}
	if opts.IncludePendingReboot {
		pr := collectPendingRebootForSnapshot(now)
		snapshot.PendingReboot = &pr
	}
	if opts.IncludeSecurityPosture {
		sp := collectSecurityPostureForSnapshot(now)
		snapshot.SecurityPosture = &sp
	}
	if opts.IncludeLocalAdminGroup {
		lag := collectLocalAdminGroupForSnapshot(now)
		snapshot.LocalAdminGroup = &lag
	}
	if opts.IncludeDeviceHealth {
		dh := collectDeviceHealthForSnapshot(now)
		snapshot.DeviceHealth = &dh
	}
	if opts.IncludeOutdatedSoftware {
		os := collectOutdatedSoftwareForSnapshot(now)
		snapshot.OutdatedSoftware = &os
	}
	if opts.IncludeDiagnostics {
		diag := collectDiagnosticsForSnapshot(now)
		snapshot.Diagnostics = &diag
	}
	if opts.IncludeHotfixPosture {
		hp := collectHotfixPostureForSnapshot(now)
		snapshot.HotfixPosture = &hp
	}
	return snapshot
}

// collectDeviceHealthForSnapshot is the test seam for the AG-033
// device health probe. Production wires the real ProbeDeviceHealth
// with time.Now (NOT the snapshot's frozen CollectedAt) so
// ProbeDurationMs measures real elapsed wall-clock and the uptime
// last-boot epoch derivation uses the real wall-clock. Tests
// override it to assert default-omit / opt-in / non-Windows stub
// behavior without invoking real syscalls.
var collectDeviceHealthForSnapshot = func(_ time.Time) DeviceHealthResult {
	return ProbeDeviceHealth(context.Background(), time.Now)
}

var collectOutdatedSoftwareForSnapshot = func(_ time.Time) OutdatedSoftwareResult {
	return ProbeOutdatedSoftware(context.Background(), time.Now)
}

var collectDiagnosticsForSnapshot = func(_ time.Time) DiagnosticsResult {
	return ProbeDiagnostics(context.Background(), time.Now)
}

// collectHotfixPostureForSnapshot is the test seam for the AG-037
// Windows Update / hotfix posture probe. Production wires the real
// ProbeHotfixPosture with time.Now (NOT the snapshot's frozen
// CollectedAt) so ProbeDurationMs measures real elapsed wall-clock
// and the LastDetect/Install registry timestamps reflect the moment
// of probe. Tests override it to assert default-omit / opt-in /
// non-Windows stub behavior without invoking real PowerShell.
var collectHotfixPostureForSnapshot = func(_ time.Time) HotfixPostureResult {
	return ProbeHotfixPosture(context.Background(), time.Now)
}

// collectLocalAdminGroupForSnapshot is the test seam for the
// AG-032 local-administrators probe. Production wires the real
// ProbeLocalAdminGroup with time.Now (NOT the snapshot's frozen
// CollectedAt) so ProbeDurationMs measures real elapsed
// wall-clock. Tests override it to assert default-omit / opt-in /
// non-Windows stub behavior without spawning a powershell process
// or invoking NetAPI.
var collectLocalAdminGroupForSnapshot = func(_ time.Time) LocalAdminGroupResult {
	return ProbeLocalAdminGroup(context.Background(), time.Now)
}

// collectSecurityPostureForSnapshot is the test seam for the AG-031
// security posture probe. Production wires the real
// ProbeSecurityPosture (PowerShell on Windows + cross-platform
// stub); tests override it to assert default-omit / opt-in /
// unsupported-stub behavior without spawning a PowerShell process.
//
// As with collectPendingRebootForSnapshot, production must NOT pin
// the probe clock to the snapshot's `CollectedAt` value, otherwise
// the probe's start and end measurements both read the same
// constant and probeDurationMs is always 0. Wire the real time.Now
// into the probe so the duration ms is meaningful elapsed wall-clock.
var collectSecurityPostureForSnapshot = func(_ time.Time) SecurityPostureResult {
	return ProbeSecurityPosture(context.Background(), time.Now)
}

// collectPendingRebootForSnapshot is the test seam for the AG-030
// pending-reboot probe. Production wires the real
// ProbePendingReboot (Windows registry reads + cross-platform
// stub); tests override it to assert default-omit / opt-in /
// unsupported-stub behavior without touching the host registry.
//
// Codex 019e749c post-impl P0#3: production must NOT pin the probe
// clock to the snapshot's `CollectedAt` value, otherwise the
// probe's start and end measurements both read the same constant
// and probeDurationMs is always 0. Wire the real time.Now into the
// probe so the duration ms is meaningful elapsed wall-clock; the
// snapshot's `now` parameter is only the snapshot timestamp and
// has no bearing on probe duration measurement.
var collectPendingRebootForSnapshot = func(_ time.Time) PendingRebootResult {
	return ProbePendingReboot(context.Background(), time.Now)
}

// collectSoftwareSummary runs the software inventory + winget readiness
// probes and folds their results into a single Summary. It is invoked ONLY
// from the explicit IncludeSoftwareApps=true path in CollectWithOptions —
// the AG-025H heartbeat / auto-enroll lightweight contract never reaches
// it. On non-Windows builds both probes return Supported=false so the
// Summary is a no-op rollup rather than missing entirely.
//
// The package-level collectSoftware / detectWinget function variables are
// the test seam: tests override them with t.Cleanup to assert lightweight
// paths never invoke the probes, and to inject fake snapshots when
// asserting full-mode output shape.
func collectSoftwareSummary(now time.Time, includeApps bool) *software.Summary {
	softwareSnapshot := collectSoftware(now, software.CollectOptions{})
	wingetReadiness := detectWinget(now)
	summary := software.Summarize(softwareSnapshot, wingetReadiness.SystemContextReady, wingetReadiness.Version, includeApps)
	return &summary
}

// collectSoftware, detectWinget, detectSourceEgress, and
// collectHardwareForSnapshot are package-level function variables so
// tests can override them with t.Cleanup-restored stubs (AG-025H +
// AG-026A + AG-035 test seam). Production code always wires them to
// the real software.Collect / winget.Detect /
// winget.DetectSourceEgress / inventory.CollectHardware
// implementations.
var (
	collectSoftware            = software.Collect
	detectWinget               = winget.Detect
	detectSourceEgress         = winget.DetectSourceEgress
	collectHardwareForSnapshot = CollectHardware
)

func RuntimeCapabilityReport() protocol.CapabilityReport {
	return protocol.CapabilityReport{
		OSFamily:     RuntimeOSFamily(),
		Architecture: runtime.GOARCH,
		Capabilities: RuntimeCapabilities(),
	}
}

func RuntimeCapabilities() []protocol.CommandType {
	capabilities := []protocol.CommandType{
		protocol.CommandCollectInventory,
		protocol.CommandGetLoggedInUser,
		protocol.CommandGetUserHomePaths,
	}
	if runtime.GOOS == "windows" {
		// DisableLocalUser/EnableLocalUser intentionally omitted: adapter not implemented in executor.
		// Re-add when internal/users gains a Windows local-user disable/enable adapter.
		capabilities = append(capabilities,
			protocol.CommandListLocalUsers,
			// AG-027 (Faz 22.5): Windows-only install execution
			// adapter. Non-Windows agents return
			// FAILED_UNSUPPORTED_PLATFORM via the executor stub;
			// to keep the dispatcher tidy we only advertise this
			// capability on the platform that can actually run it.
			// Codex 019e6c0d iter-1 P0#1 absorb — without this the
			// capability is missing from the heartbeat and
			// Validate() rejects every INSTALL_SOFTWARE command
			// before the executor branch can run.
			protocol.CommandInstallSoftware,
		)
	}
	return capabilities
}

func RuntimeOSFamily() protocol.OSFamily {
	switch runtime.GOOS {
	case "windows":
		return protocol.OSFamilyWindows
	case "darwin":
		return protocol.OSFamilyMacOS
	default:
		return protocol.OSFamilyLinux
	}
}

// MachineFingerprint returns a stable, non-empty identifier for this machine.
// BE-011: the backend enrollment contract (ConsumeEnrollmentRequest
// .machineFingerprint, @NotBlank, max 512) requires it. The value is derived
// deterministically from the hostname and the OS/architecture so it is stable
// across agent restarts and distinct across machines with different hostnames.
// A hardware-bound fingerprint (machine-id / SMBIOS UUID) is a future
// enhancement; this derivation is sufficient to identify the device across the
// enroll → heartbeat → command lifecycle.
func MachineFingerprint() string {
	hostname, err := os.Hostname()
	if err != nil || strings.TrimSpace(hostname) == "" {
		hostname = "unknown-host"
	}
	seed := strings.ToLower(strings.TrimSpace(hostname)) + "|" + runtime.GOOS + "|" + runtime.GOARCH
	sum := sha256.Sum256([]byte(seed))
	return hex.EncodeToString(sum[:])
}
