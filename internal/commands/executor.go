package commands

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"platform-agent/internal/inventory"
	"platform-agent/internal/protocol"
	"platform-agent/internal/users"
	"platform-agent/internal/winget"
)

// installWinGetFn is the package-private dispatcher for the
// `INSTALL_SOFTWARE` command. Production wires this through
// winget.InstallWinGet (Windows runner / non-Windows stub via the
// build-tagged installers). Tests override the seam to exercise the
// executor path without spawning a real winget invocation.
var installWinGetFn = winget.InstallWinGet

type LocalExecutor struct {
	Capabilities []protocol.CommandType
	AgentVersion string
	Now          func() time.Time
}

func NewLocalExecutor(capabilities []protocol.CommandType, agentVersion string) *LocalExecutor {
	return &LocalExecutor{
		Capabilities: capabilities,
		AgentVersion: agentVersion,
		Now:          time.Now,
	}
}

func (e *LocalExecutor) Execute(ctx context.Context, command protocol.AgentCommand) protocol.CommandResult {
	now := e.now()
	result := protocol.CommandResult{
		CommandID:     command.CommandID,
		ClaimID:       command.ClaimID,
		AttemptNumber: command.AttemptNumber,
		Status:        protocol.CommandStatusRunning,
		StartedAt:     now,
		FinishedAt:    now,
	}

	if err := Validate(command, e.Capabilities, now); err != nil {
		return withValidationError(result, err, e.now())
	}

	select {
	case <-ctx.Done():
		result.Status = protocol.CommandStatusFailed
		result.Summary = ctx.Err().Error()
		result.FinishedAt = e.now()
		return result
	default:
	}

	switch command.Type {
	case protocol.CommandCollectInventory:
		// AG-025H + AG-026A — opt-in payload bits:
		//   includeSoftware    -> software registry + winget --version probe
		//   includeWinGetEgress -> AG-026A read-only source/egress preflight
		// Both default to false so the lightweight heartbeat / auto-enroll
		// contract pays neither cost. Backend opts in explicitly when an
		// install pilot is being evaluated.
		snapshot := inventory.CollectWithOptions(e.AgentVersion, e.now(), inventory.CollectOptions{
			IncludeSoftwareApps: boolPayload(command.Payload, "includeSoftware"),
			IncludeWinGetEgress: boolPayload(command.Payload, "includeWinGetEgress"),
			// AG-035 — opt-in hardware probe. Defaults to false so the
			// AG-025H lightweight heartbeat / auto-enroll contract pays
			// neither the PowerShell startup nor the WMI/CIM cost.
			// Backend opts in explicitly via COLLECT_INVENTORY payload
			// when a hardware snapshot is being requested.
			IncludeHardware: boolPayload(command.Payload, "includeHardware"),
			// AG-030 — opt-in pending-reboot probe. Defaults to false
			// so the AG-025H lightweight heartbeat / auto-enroll
			// contract pays neither the registry read nor the
			// computer-name comparison cost. Backend opts in
			// explicitly via COLLECT_INVENTORY's includePendingReboot
			// payload bit when a posture refresh is requested.
			IncludePendingReboot: boolPayload(command.Payload, "includePendingReboot"),
			// AG-031 — opt-in endpoint security posture probe.
			// Defaults to false so the AG-025H lightweight heartbeat /
			// auto-enroll contract pays neither the PowerShell startup
			// nor the Get-MpComputerStatus / Get-NetFirewallProfile /
			// Get-BitLockerVolume / Get-CimInstance cost. Backend opts
			// in explicitly via COLLECT_INVENTORY's
			// includeSecurityPosture payload bit when a Sprint B
			// posture refresh is requested.
			IncludeSecurityPosture: boolPayload(command.Payload, "includeSecurityPosture"),
			// AG-032 — opt-in direct local-Administrators
			// enumeration. Defaults to false so the AG-025H
			// lightweight contract stays cheap. Backend opts in
			// explicitly via COLLECT_INVENTORY's
			// includeLocalAdminGroup payload bit when a Sprint B
			// posture refresh is requested.
			IncludeLocalAdminGroup: boolPayload(command.Payload, "includeLocalAdminGroup"),
			// AG-033 — opt-in device health snapshot. Defaults to
			// false so the AG-025H lightweight contract stays cheap.
			// Backend opts in via COLLECT_INVENTORY's
			// includeDeviceHealth payload bit for pre-deployment
			// health gating.
			IncludeDeviceHealth: boolPayload(command.Payload, "includeDeviceHealth"),
			// AG-036 — opt-in outdated-software probe. Defaults to false
			// so the AG-025H lightweight contract stays cheap. Backend
			// opts in via COLLECT_INVENTORY's includeOutdatedSoftware
			// payload bit for upgrade eligibility scanning.
			// HARD BOUNDARY: read-only `winget upgrade
			// --include-returning-apps`; never mutates package state.
			IncludeOutdatedSoftware: boolPayload(command.Payload, "includeOutdatedSoftware"),
			// AG-038 — opt-in agent self-diagnostics probe. Defaults to
			// false so the AG-025H lightweight contract stays cheap.
			// Backend opts in via COLLECT_INVENTORY's
			// includeDiagnostics payload bit for operational health
			// visibility. HARD BOUNDARY: read-only — DNS lookup + TLS
			// handshake only; no PII, credentials, or paths on wire.
			IncludeDiagnostics: boolPayload(command.Payload, "includeDiagnostics"),
			// AG-037 — opt-in Windows Update / hotfix posture probe.
			// Defaults to false so the AG-025H lightweight contract
			// stays cheap. Backend opts in via COLLECT_INVENTORY's
			// includeHotfixPosture payload bit when a patch posture
			// evaluation is being prepared. HARD BOUNDARY: read-only —
			// pinned PowerShell + WUA COM Search/QueryHistory +
			// Get-HotFix fallback + SCM service state + AU policy
			// registry reads; NO Install-WindowsUpdate, NO
			// `wuauclt /detectnow`, NO service/policy mutation. Wire
			// is allowlist-projected: per-hotfix {kbId, installedOn,
			// description} + per-pending-item {kbIds, primaryCategory,
			// severity} — never raw update titles, account names,
			// product codes, MSI GUIDs, or supersedence chains.
			IncludeHotfixPosture: boolPayload(command.Payload, "includeHotfixPosture"),
			// AG-039 critical services inventory — opt-in only. SCM
			// allowlist enum (WinDefend/wuauserv/BITS/EventLog/
			// EndpointAgent/MpsSvc) + AUTO_DELAYED disambiguation via
			// registry DelayedAutoStart. HARD BOUNDARY: read-only.
			// Wire shape per-entry exactly {name, present, state,
			// startupMode} — no raw description / command line /
			// account / SID / display name.
			IncludeServices: boolPayload(command.Payload, "includeServices"),
		})
		result.Status = protocol.CommandStatusSucceeded
		result.Summary = "Inventory collected"
		result.Details = map[string]interface{}{"inventory": snapshot}
	case protocol.CommandListLocalUsers:
		localUsers, err := users.ListLocal()
		if err != nil {
			if errors.Is(err, users.ErrLocalUserListingUnsupported) {
				result.Status = protocol.CommandStatusUnsupported
			} else {
				result.Status = protocol.CommandStatusFailed
			}
			result.Summary = err.Error()
			break
		}
		result.Status = protocol.CommandStatusSucceeded
		result.Summary = "Local users listed"
		result.Details = map[string]interface{}{"users": localUsers}
	case protocol.CommandGetLoggedInUser:
		current, err := users.Current()
		if err != nil {
			result.Status = protocol.CommandStatusFailed
			result.Summary = err.Error()
			break
		}
		result.Status = protocol.CommandStatusSucceeded
		result.Summary = "Logged-in user resolved"
		result.Details = map[string]interface{}{"user": current}
	case protocol.CommandGetUserHomePaths:
		paths, err := users.CurrentHomePaths()
		if err != nil {
			result.Status = protocol.CommandStatusFailed
			result.Summary = err.Error()
			break
		}
		result.Status = protocol.CommandStatusSucceeded
		result.Summary = "User home paths resolved"
		result.Details = map[string]interface{}{"paths": paths}
	case protocol.CommandInstallSoftware:
		// AG-027 (Faz 22.5) — install execution adapter.
		//
		// Payload is unmarshalled fail-closed via JSON round-trip
		// so a malformed shape is rejected with a precise FAILED
		// state rather than panicking on a missing-field assertion.
		// The structured InstallResult is shipped via Details so
		// the backend audit pipeline can store / query the
		// canonical schema verbatim.
		req, payloadErr := unmarshalInstallRequest(command.Payload)
		if payloadErr != nil {
			result.Status = protocol.CommandStatusFailed
			result.Summary = payloadErr.Error()
			break
		}
		installResult := installWinGetFn(ctx, req)
		result.Status = mapInstallStatusToCommandStatus(installResult.FinalStatus)
		result.Summary = fmt.Sprintf("INSTALL_SOFTWARE %s", installResult.FinalStatus)
		result.Details = map[string]interface{}{"install": installResult}
	default:
		result.Status = protocol.CommandStatusUnsupported
		result.Summary = "Command is not implemented by this agent build"
	}
	result.FinishedAt = e.now()
	return result
}

func (e *LocalExecutor) now() time.Time {
	if e.Now == nil {
		return time.Now()
	}
	return e.Now()
}

// unmarshalInstallRequest converts the wire-side payload map into a
// canonical winget.InstallRequest. Validation is delegated to the
// install pipeline (RunInstall) which fails-closed on unsupported
// detection rules / args policy presets; this function only
// guarantees that the shape JSON-decodes without panicking.
func unmarshalInstallRequest(payload map[string]interface{}) (winget.InstallRequest, error) {
	if payload == nil {
		return winget.InstallRequest{}, errors.New("INSTALL_SOFTWARE payload is empty")
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return winget.InstallRequest{}, fmt.Errorf("INSTALL_SOFTWARE payload re-marshal failed: %w", err)
	}
	var req winget.InstallRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		return winget.InstallRequest{}, fmt.Errorf("INSTALL_SOFTWARE payload decode failed: %w", err)
	}
	if strings.TrimSpace(string(req.DetectionRule.Type)) == "" {
		return winget.InstallRequest{}, errors.New("INSTALL_SOFTWARE payload missing detectionRule.type")
	}
	if strings.TrimSpace(req.PackageID) == "" {
		return winget.InstallRequest{}, errors.New("INSTALL_SOFTWARE payload missing packageId")
	}
	if strings.TrimSpace(req.ArgsPolicyPreset) == "" {
		return winget.InstallRequest{}, errors.New("INSTALL_SOFTWARE payload missing argsPolicyPreset")
	}
	return req, nil
}

// mapInstallStatusToCommandStatus converts the AG-027 fine-grained
// install final status into the BE-014 command status surface so
// the backend command-result endpoint can keep its existing
// SUCCEEDED / FAILED / UNSUPPORTED dispatch unchanged. The
// fine-grained AG-027 status remains visible in the result's
// Details map for audit / UI consumers that need it.
func mapInstallStatusToCommandStatus(finalStatus string) protocol.CommandStatus {
	switch finalStatus {
	case winget.FinalStatusSucceeded,
		winget.FinalStatusSucceededNoop,
		winget.FinalStatusSucceededRebootRequired:
		return protocol.CommandStatusSucceeded
	case winget.FinalStatusFailedUnsupportedPlatform,
		winget.FinalStatusFailedUnsupportedDetectionRule,
		winget.FinalStatusFailedUnsupportedArgsPolicy:
		return protocol.CommandStatusUnsupported
	default:
		return protocol.CommandStatusFailed
	}
}

// boolPayload reads an optional bool argument from a command payload.
// The wire payload is map[string]interface{} so backend-side typing
// drift (true vs "true" vs 1) is normalised here once rather than at
// every call site. Anything else returns false — the default for
// includeSoftware is "off" so unknown shapes degrade safely to the
// AG-025H lightweight contract (no software registry enumeration, no
// WinGet probe; Snapshot.Software stays nil).
func boolPayload(payload map[string]interface{}, key string) bool {
	if payload == nil {
		return false
	}
	switch v := payload[key].(type) {
	case bool:
		return v
	case string:
		// case-insensitive truthy. "1", "true", "True", "TRUE" all
		// flip the flag; everything else (including empty string)
		// keeps the safe default of false.
		switch strings.ToLower(v) {
		case "true", "1":
			return true
		}
		return false
	case float64:
		return v != 0
	case int:
		return v != 0
	default:
		return false
	}
}

func withValidationError(r protocol.CommandResult, err error, finishedAt time.Time) protocol.CommandResult {
	switch {
	case errors.Is(err, ErrUnsupportedCommand):
		r.Status = protocol.CommandStatusUnsupported
	case errors.Is(err, ErrExpiredClaim):
		r.Status = protocol.CommandStatusExpired
	default:
		r.Status = protocol.CommandStatusFailed
	}
	r.Summary = err.Error()
	r.FinishedAt = finishedAt
	return r
}
