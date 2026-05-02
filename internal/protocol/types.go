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
	CommandDisableLocalUser       CommandType = "DISABLE_LOCAL_USER"
	CommandEnableLocalUser        CommandType = "ENABLE_LOCAL_USER"
	CommandResetLocalUserPassword CommandType = "RESET_LOCAL_USER_PASSWORD"
	CommandListAllowedDirectory   CommandType = "LIST_ALLOWED_DIRECTORY"
	CommandDownloadAllowedFile    CommandType = "DOWNLOAD_ALLOWED_FILE"
	CommandUploadAllowedFile      CommandType = "UPLOAD_ALLOWED_FILE"
	CommandCollectEventLogSummary CommandType = "COLLECT_EVENT_LOG_SUMMARY"
	CommandOSQueryQuery           CommandType = "OSQUERY_QUERY"
	CommandRestartAgent           CommandType = "RESTART_AGENT"
)

type CommandStatus string

const (
	CommandStatusQueued      CommandStatus = "QUEUED"
	CommandStatusClaimed     CommandStatus = "CLAIMED"
	CommandStatusRunning     CommandStatus = "RUNNING"
	CommandStatusSucceeded   CommandStatus = "SUCCEEDED"
	CommandStatusFailed      CommandStatus = "FAILED"
	CommandStatusUnsupported CommandStatus = "UNSUPPORTED"
	CommandStatusExpired     CommandStatus = "EXPIRED"
)

type CapabilityReport struct {
	OSFamily     OSFamily      `json:"osFamily"`
	Architecture string        `json:"architecture"`
	Capabilities []CommandType `json:"capabilities"`
}

type EnrollRequest struct {
	EnrollmentToken string   `json:"enrollmentToken"`
	InstallID       string   `json:"installId"`
	Hostname        string   `json:"hostname"`
	OSFamily        OSFamily `json:"osFamily"`
	Architecture    string   `json:"architecture"`
	AgentVersion    string   `json:"agentVersion"`
}

type EnrollResponse struct {
	AgentID     string `json:"agentId"`
	AgentSecret string `json:"agentSecret"`
	InstallID   string `json:"installId"`
}

type HeartbeatRequest struct {
	AgentID      string        `json:"agentId"`
	InstallID    string        `json:"installId"`
	Hostname     string        `json:"hostname"`
	OSFamily     OSFamily      `json:"osFamily"`
	Architecture string        `json:"architecture"`
	AgentVersion string        `json:"agentVersion"`
	State        string        `json:"state"`
	Capabilities []CommandType `json:"capabilities"`
	Timestamp    time.Time     `json:"timestamp"`
}

type HeartbeatResponse struct {
	Accepted   bool      `json:"accepted"`
	ServerTime time.Time `json:"serverTime"`
}

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

func (t CommandType) RequiresReason() bool {
	switch t {
	case CommandDisableLocalUser, CommandEnableLocalUser, CommandResetLocalUserPassword, CommandDownloadAllowedFile, CommandUploadAllowedFile:
		return true
	default:
		return false
	}
}

func (t CommandType) IsSensitive() bool {
	switch t {
	case CommandDisableLocalUser, CommandEnableLocalUser, CommandResetLocalUserPassword, CommandDownloadAllowedFile, CommandUploadAllowedFile:
		return true
	default:
		return false
	}
}

func (t CommandType) IsRepeatSafe() bool {
	switch t {
	case CommandCollectInventory, CommandListLocalUsers, CommandGetLoggedInUser, CommandGetUserHomePaths, CommandDisableLocalUser, CommandEnableLocalUser, CommandListAllowedDirectory:
		return true
	default:
		return false
	}
}
