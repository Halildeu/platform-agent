package protocol

import "time"

type OSFamily string

const (
	OSFamilyWindows OSFamily = "WINDOWS"
	OSFamilyMacOS   OSFamily = "MACOS"
	OSFamilyLinux   OSFamily = "LINUX"
)

type CommandType string

const (
	CommandCollectInventory       CommandType = "COLLECT_INVENTORY"
	CommandListLocalUsers         CommandType = "LIST_LOCAL_USERS"
	CommandGetLoggedInUser        CommandType = "GET_LOGGED_IN_USER"
	CommandGetUserHomePaths       CommandType = "GET_USER_HOME_PATHS"
	CommandLockUserLogin          CommandType = "LOCK_USER_LOGIN"
	CommandUnlockUserLogin        CommandType = "UNLOCK_USER_LOGIN"
	CommandChangeLocalPassword    CommandType = "CHANGE_LOCAL_PASSWORD"
	CommandDisableLocalUser       CommandType = "DISABLE_LOCAL_USER"
	CommandEnableLocalUser        CommandType = "ENABLE_LOCAL_USER"
	CommandResetLocalUserPassword CommandType = "RESET_LOCAL_USER_PASSWORD"
	CommandListAllowedDirectory   CommandType = "LIST_ALLOWED_DIRECTORY"
	CommandDownloadAllowedFile    CommandType = "DOWNLOAD_ALLOWED_FILE"
	CommandUploadAllowedFile      CommandType = "UPLOAD_ALLOWED_FILE"
	CommandCollectEventLogSummary CommandType = "COLLECT_EVENT_LOG_SUMMARY"
	CommandOSQueryQuery           CommandType = "OSQUERY_QUERY"
	CommandRestartAgent           CommandType = "RESTART_AGENT"
	// AG-027 (Faz 22.5): agent-side install execution adapter. Server
	// (future BE-022) issues a structured INSTALL_SOFTWARE command
	// payload (catalog snapshot pinned, args policy preset, version
	// predicate). Agent re-verifies egress, pre-detects, installs,
	// post-verifies. v1 supports WINGET_PACKAGE detection rules only;
	// other detection rule types are rejected fail-closed BEFORE
	// mutation. See internal/winget/install_winget.go for the
	// canonical wire-shape.
	CommandInstallSoftware CommandType = "INSTALL_SOFTWARE"
	// AG-028 (Faz 22.5.6): agent-side managed uninstall execution
	// adapter. Backend (Phase 1b EndpointUninstallService) dispatches
	// after the propose/approve maker-checker + provenance + capability
	// + heartbeat freshness + authoritative-detection-rule gates pass.
	// Agent runs absence-aware ProbeState pre-/post-probe and reports
	// the AG-028 UninstallResult. v1 authoritative detector tier ONLY:
	// REGISTRY_UNINSTALL / FILE_EXISTS / FILE_SHA256 / FILE_VERSION.
	// WINGET_PACKAGE → FAILED_UNSUPPORTED_VERIFICATION (Codex 019e8de2
	// iter-1 absorb: Session-0 `winget list` cache lag unreliable).
	// See internal/winget/uninstall_winget.go for the canonical
	// wire-shape.
	CommandUninstallSoftware CommandType = "UNINSTALL_SOFTWARE"
	// AG-029 (Faz 22.5.7): signed self-update staging command. Backend
	// may issue this ONLY through the release-catalog-bound dedicated
	// endpoint; generic command surfaces stay fail-closed. The agent
	// stages a verified binary and returns a bounded StageResult. It does
	// not stop/replace the running service in this PR2 command wire.
	CommandUpdateAgent CommandType = "UPDATE_AGENT"
	// #508 (Faz 22.5): managed screensaver + desktop wallpaper Group-Policy.
	// Always maker-checker on the backend; advertised as a capability only on
	// Windows (RuntimeCapabilitiesWithOptions). The agent applies the policy to
	// every loaded interactive user hive (internal/displaypolicy).
	CommandSetDisplayPolicy CommandType = "SET_DISPLAY_POLICY"
)

type CommandStatus string

const (
	CommandStatusQueued      CommandStatus = "QUEUED"
	CommandStatusClaimed     CommandStatus = "CLAIMED"
	CommandStatusRunning     CommandStatus = "RUNNING"
	CommandStatusSucceeded   CommandStatus = "SUCCEEDED"
	CommandStatusFailed      CommandStatus = "FAILED"
	CommandStatusPartial     CommandStatus = "PARTIAL"
	CommandStatusUnsupported CommandStatus = "UNSUPPORTED"
	CommandStatusExpired     CommandStatus = "EXPIRED"
)

type CapabilityReport struct {
	OSFamily     OSFamily      `json:"osFamily"`
	Architecture string        `json:"architecture"`
	Capabilities []CommandType `json:"capabilities"`
}

// EnrollRequest is the agent→backend enrollment-consume body. BE-011: matches
// com.example.endpointadmin.dto.v1.agent.ConsumeEnrollmentRequest — osType is
// an OsType enum name (WINDOWS/MACOS/LINUX/UNKNOWN) and machineFingerprint is
// required.
type EnrollRequest struct {
	EnrollmentToken    string `json:"enrollmentToken"`
	Hostname           string `json:"hostname"`
	OsType             string `json:"osType"`
	OsVersion          string `json:"osVersion,omitempty"`
	AgentVersion       string `json:"agentVersion"`
	MachineFingerprint string `json:"machineFingerprint"`
	DomainName         string `json:"domainName,omitempty"`
}

// EnrollResponse is the backend ConsumeEnrollmentResponse. The device
// credential the agent signs subsequent requests with is
// CredentialKeyID (the X-Device-Credential-Id header) + Secret (the HMAC key).
type EnrollResponse struct {
	DeviceID        string    `json:"deviceId"`
	CredentialKeyID string    `json:"credentialKeyId"`
	Secret          string    `json:"secret"`
	HmacAlgorithm   string    `json:"hmacAlgorithm"`
	ServerTime      time.Time `json:"serverTime"`
}

// HeartbeatRequest matches the backend AgentHeartbeatRequest. The signing
// device is resolved from the X-Device-Credential-Id header, so no agent id is
// carried in the body.
type HeartbeatRequest struct {
	InstallID    string        `json:"installId,omitempty"`
	Hostname     string        `json:"hostname"`
	OsType       string        `json:"osType"`
	Architecture string        `json:"architecture"`
	AgentVersion string        `json:"agentVersion"`
	OsVersion    string        `json:"osVersion,omitempty"`
	State        string        `json:"state"`
	Capabilities []CommandType `json:"capabilities"`
	Timestamp    time.Time     `json:"timestamp"`
}

// HeartbeatResponse matches the backend AgentHeartbeatResponse.
type HeartbeatResponse struct {
	Accepted   bool      `json:"accepted"`
	DeviceID   string    `json:"deviceId"`
	Status     string    `json:"status"`
	ServerTime time.Time `json:"serverTime"`
}

// AgentCommand matches the backend AgentCommandResponse (the GET
// /commands/next body). ClaimID must be echoed back in the result.
type AgentCommand struct {
	CommandID      string                 `json:"commandId"`
	ClaimID        string                 `json:"claimId"`
	AttemptNumber  int                    `json:"attemptNumber"`
	Type           CommandType            `json:"type"`
	RequestedBy    string                 `json:"requestedBy"`
	Reason         string                 `json:"reason"`
	Payload        map[string]interface{} `json:"payload"`
	ClaimExpiresAt time.Time              `json:"claimExpiresAt"`
}

// CommandResult is the executor's internal result type. It is mapped onto the
// backend wire contract by ToWire before submission.
type CommandResult struct {
	CommandID     string                 `json:"commandId"`
	ClaimID       string                 `json:"claimId"`
	AttemptNumber int                    `json:"attemptNumber"`
	Status        CommandStatus          `json:"status"`
	Summary       string                 `json:"summary"`
	Details       map[string]interface{} `json:"details,omitempty"`
	StartedAt     time.Time              `json:"startedAt"`
	FinishedAt    time.Time              `json:"finishedAt"`
}

// CommandResultWire is the agent→backend command-result body, matching the
// backend AgentCommandResultRequest. commandId is NOT a body field — it is the
// {commandId} path segment of POST /api/v1/agent/commands/{commandId}/result.
type CommandResultWire struct {
	ClaimID       string                 `json:"claimId"`
	AttemptNumber int                    `json:"attemptNumber"`
	Status        string                 `json:"status"`
	Summary       string                 `json:"summary,omitempty"`
	Details       map[string]interface{} `json:"details,omitempty"`
	ErrorCode     string                 `json:"errorCode,omitempty"`
	ErrorMessage  string                 `json:"errorMessage,omitempty"`
	StartedAt     time.Time              `json:"startedAt"`
	FinishedAt    time.Time              `json:"finishedAt"`
}

// ToWire maps an executor CommandResult onto the backend wire contract. The
// backend CommandResultStatus enum is {SUCCEEDED, FAILED, PARTIAL,
// UNSUPPORTED} — it has no EXPIRED — so an expired result is reported as
// FAILED with an errorCode (Codex 019e5000 Q4). Any non-terminal status is
// defensively reported as FAILED.
func (r CommandResult) ToWire() CommandResultWire {
	wire := CommandResultWire{
		ClaimID:       r.ClaimID,
		AttemptNumber: r.AttemptNumber,
		Summary:       r.Summary,
		Details:       r.Details,
		StartedAt:     r.StartedAt,
		FinishedAt:    r.FinishedAt,
	}
	switch r.Status {
	case CommandStatusSucceeded:
		wire.Status = "SUCCEEDED"
	case CommandStatusPartial:
		wire.Status = "PARTIAL"
	case CommandStatusUnsupported:
		wire.Status = "UNSUPPORTED"
	case CommandStatusExpired:
		wire.Status = "FAILED"
		wire.ErrorCode = "COMMAND_EXPIRED"
		wire.ErrorMessage = "command claim expired before the result was reported"
	default: // FAILED, plus any non-terminal status, defensively
		wire.Status = "FAILED"
	}
	return wire
}

func (t CommandType) RequiresReason() bool {
	switch t {
	case CommandLockUserLogin, CommandUnlockUserLogin, CommandChangeLocalPassword, CommandDisableLocalUser, CommandEnableLocalUser, CommandResetLocalUserPassword, CommandDownloadAllowedFile, CommandUploadAllowedFile, CommandUpdateAgent:
		return true
	default:
		return false
	}
}

func (t CommandType) IsSensitive() bool {
	switch t {
	case CommandLockUserLogin, CommandUnlockUserLogin, CommandChangeLocalPassword, CommandDisableLocalUser, CommandEnableLocalUser, CommandResetLocalUserPassword, CommandDownloadAllowedFile, CommandUploadAllowedFile, CommandUpdateAgent:
		return true
	default:
		return false
	}
}

func (t CommandType) IsRepeatSafe() bool {
	switch t {
	case CommandCollectInventory, CommandListLocalUsers, CommandGetLoggedInUser, CommandGetUserHomePaths, CommandLockUserLogin, CommandUnlockUserLogin, CommandDisableLocalUser, CommandEnableLocalUser, CommandListAllowedDirectory:
		return true
	default:
		return false
	}
}
