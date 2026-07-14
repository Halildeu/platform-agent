package screenview

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"

	"platform-agent/internal/remotebridge/dataplane"
	"platform-agent/internal/security"
)

const (
	// AcceptanceModeEnv is deliberately absent from installer/MSI wiring. A test
	// operator must set the exact value for one acceptance run; production remains
	// unable to invoke the trigger by default.
	AcceptanceModeEnv           = "ENDPOINT_AGENT_REMOTE_BRIDGE_VIEW_ONLY_ACCEPTANCE_MODE"
	ProtectedAcceptanceValue    = "ENDPOINT_AGENT_REMOTE_BRIDGE_VIEW_ONLY_ACCEPTANCE_ALLOWED"
	acceptanceModeTest          = "test"
	maxAcceptanceSessionIDBytes = 256
)

var (
	ErrAcceptanceModeDisabled  = errors.New("screenview: indicator-loss acceptance trigger is disabled")
	ErrAcceptanceProtectedMode = errors.New("screenview: protected indicator-loss acceptance permission is disabled")
	ErrAcceptanceSessionID     = errors.New("screenview: invalid acceptance session id")
	ErrAcceptanceAdminRequired = errors.New("screenview: elevated local administrator is required")
)

// AcceptanceModeEnabled accepts one exact, case-sensitive non-production mode.
// Values such as "production", "true", surrounding whitespace, or an unset env
// fail closed.
func AcceptanceModeEnabled() bool {
	return os.Getenv(AcceptanceModeEnv) == acceptanceModeTest
}

func acceptanceHostPreflight(protectedMode string, isElevated func() bool) error {
	if !AcceptanceModeEnabled() {
		return ErrAcceptanceModeDisabled
	}
	if protectedMode != acceptanceModeTest {
		return ErrAcceptanceProtectedMode
	}
	if isElevated == nil || !isElevated() {
		return ErrAcceptanceAdminRequired
	}
	return nil
}

// AcceptanceWindowBinding maps the broker session id to an opaque fixed-size
// banner binding. The raw session id is never placed in the helper argv or Win32
// window title. IDs are bounded to the wire-safe ASCII alphabet before hashing.
func AcceptanceWindowBinding(sessionID string) (string, error) {
	if sessionID == "" || len(sessionID) > maxAcceptanceSessionIDBytes || strings.TrimSpace(sessionID) != sessionID {
		return "", ErrAcceptanceSessionID
	}
	for i := 0; i < len(sessionID); i++ {
		c := sessionID[i]
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == ':' ||
			c == '@' || c == '+' || c == '=') {
			return "", ErrAcceptanceSessionID
		}
	}
	digest := sha256.Sum256([]byte(sessionID))
	return hex.EncodeToString(digest[:]), nil
}

func validAcceptanceWindowBinding(binding string) bool {
	if len(binding) != sha256.Size*2 || strings.ToLower(binding) != binding {
		return false
	}
	decoded, err := hex.DecodeString(binding)
	return err == nil && len(decoded) == sha256.Size
}

type acceptanceTriggerDeps struct {
	isElevated func() bool
	trigger    func(string) error
}

func triggerIndicatorLossAcceptance(sessionID, maintenanceToken, expectedTokenHash, protectedMode string,
	deps acceptanceTriggerDeps) error {
	if err := acceptanceHostPreflight(protectedMode, deps.isElevated); err != nil {
		return err
	}
	binding, err := AcceptanceWindowBinding(sessionID)
	if err != nil {
		return err
	}
	if strings.TrimSpace(expectedTokenHash) == "" {
		return security.ErrMaintenanceTokenRequired
	}
	if err := security.RequireMaintenanceToken(maintenanceToken, expectedTokenHash); err != nil {
		return err
	}
	if deps.trigger == nil {
		return dataplane.ErrBannerUnsupported
	}
	if err := deps.trigger(binding); err != nil {
		return fmt.Errorf("screenview: trigger session-bound indicator loss: %w", err)
	}
	return nil
}
