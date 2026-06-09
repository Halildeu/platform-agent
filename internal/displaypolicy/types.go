// Package displaypolicy implements the agent side of the #508 Endpoint Display
// Policy (Faz 22.5): the SET_DISPLAY_POLICY command applies a managed
// screensaver + desktop wallpaper Group-Policy via the registry.
//
// Design (Codex 019ea9c5, plan-time AGREE): screensaver and wallpaper policy
// values are USER-class — there is no real HKLM screensaver GPO surface, and
// HKLM wallpaper is not the canonical managed surface. A LocalSystem / Session-0
// service has no interactive HKCU, so v1 is a *loaded-interactive-user-hive
// policy writer*: it enumerates HKEY_USERS and targets only currently-loaded
// real user SID hives. Unloaded profiles are out of scope (documented, never
// claimed). This package is split build-tag-wise — the OS-agnostic contract +
// validation live here; the registry application lives in apply_windows.go
// (//go:build windows) with a fail-loud non-Windows stub in apply_other.go.
package displaypolicy

import (
	"fmt"
	"strings"
)

// Operation values mirror the backend DisplayPolicyOperation enum.
const (
	OperationEnforce = "ENFORCE"
	OperationClear   = "CLEAR"
)

// FinalStatus is the structured per-command outcome shipped via the executor
// CommandResult.Details so the backend audit pipeline stores it verbatim. It is
// richer than the wire CommandStatus (which only has SUCCEEDED/FAILED/PARTIAL/
// UNSUPPORTED); the executor maps FinalStatus → CommandStatus.
type FinalStatus string

const (
	StatusSucceeded           FinalStatus = "SUCCEEDED"
	StatusPartial             FinalStatus = "PARTIAL"
	StatusFailedInvalid       FinalStatus = "FAILED_INVALID_PAYLOAD"
	StatusFailedNoTargetHive  FinalStatus = "FAILED_NO_TARGET_USER_HIVE"
	StatusFailedRegistry      FinalStatus = "FAILED_REGISTRY"
	StatusFailedUnsupportedOS FinalStatus = "FAILED_UNSUPPORTED_PLATFORM"
)

// Command is the SET_DISPLAY_POLICY payload the backend dispatches. The backend
// builds it with putIfNotNull (EndpointDisplayPolicyService#buildEnforcePayload
// / buildClearPayload), so the screensaver/wallpaper blocks are absent unless
// the managed policy carries them; CLEAR carries no policy blocks at all.
type Command struct {
	Operation   string       `json:"operation"`
	RevisionID  string       `json:"revisionId"`
	DeviceID    string       `json:"deviceId"`
	PolicyHash  string       `json:"policyHash"`
	Screensaver *Screensaver `json:"screensaver,omitempty"`
	Wallpaper   *Wallpaper   `json:"wallpaper,omitempty"`
}

// Screensaver mirrors the backend screensaver block.
type Screensaver struct {
	Enabled        bool   `json:"enabled"`
	TimeoutSeconds int    `json:"timeoutSeconds"`
	SecureOnResume bool   `json:"secureOnResume"`
	ScrPath        string `json:"scrPath"`
}

// Wallpaper mirrors the backend wallpaper block. AssetRef in v1 is interpreted
// as an existing absolute LOCAL path the agent can read (no asset download);
// a UNC path is unsupported in v1.
type Wallpaper struct {
	Enabled          bool   `json:"enabled"`
	Style            string `json:"style"`
	UserCannotChange bool   `json:"userCannotChange"`
	AssetRef         string `json:"assetRef"`
}

// Skipped records a scope the v1 writer deliberately did not target.
type Skipped struct {
	Scope  string `json:"scope"`
	Reason string `json:"reason"`
}

// Result is the structured outcome. It is honest about the apply boundary:
// registry writes do not prove the interactive desktop changed (EffectiveState
// note), and unloaded user hives are never targeted (Skipped/Limitations).
type Result struct {
	FinalStatus    FinalStatus `json:"finalStatus"`
	Operation      string      `json:"operation"`
	TargetModel    string      `json:"targetModel"`
	TargetedSIDs   []string    `json:"targetedLoadedUserSids"`
	WrittenValues  []string    `json:"writtenValues"`
	DeletedValues  []string    `json:"deletedValues"`
	Skipped        []Skipped   `json:"skipped,omitempty"`
	EffectiveState string      `json:"effectiveState"`
	Limitations    []string    `json:"limitations,omitempty"`
	Errors         []string    `json:"errors,omitempty"`
	Summary        string      `json:"summary"`
}

const targetModel = "loaded-user-hives"

const effectiveNote = "Registry policy values written. The interactive desktop may require next sign-in, " +
	"Group Policy refresh, or an Explorer/session refresh to visibly apply."

// allowedScrPaths is the exact 6-entry System32 .scr allowlist (mirrors the
// web ALLOWED_SCR_PATHS + the backend DisplayPolicyValidator). Compared
// case-insensitively; no path traversal / env vars / relative paths.
var allowedScrPaths = map[string]struct{}{
	`c:\windows\system32\scrnsave.scr`:         {},
	`c:\windows\system32\mystify.scr`:          {},
	`c:\windows\system32\ribbons.scr`:          {},
	`c:\windows\system32\bubbles.scr`:          {},
	`c:\windows\system32\photoscreensaver.scr`: {},
	`c:\windows\system32\sstext3d.scr`:         {},
}

// styleRegistryValue maps the backend WallpaperStyle enum name to the
// WallpaperStyle registry REG_SZ value.
var styleRegistryValue = map[string]string{
	"CENTER":  "0",
	"STRETCH": "2",
	"FIT":     "6",
	"FILL":    "10",
	"SPAN":    "22",
}

// StyleToRegistryValue returns the WallpaperStyle REG_SZ value for a backend
// style enum name, and whether it is a recognised value.
func StyleToRegistryValue(style string) (string, bool) {
	v, ok := styleRegistryValue[strings.ToUpper(strings.TrimSpace(style))]
	return v, ok
}

const (
	minScreensaverTimeout = 60
	maxScreensaverTimeout = 86400
)

// Validate fail-closes a decoded command BEFORE any registry side effect. It
// rejects an unknown operation, an out-of-range screensaver timeout, a
// non-allowlisted .scr path, an unknown wallpaper style, and a wallpaper that
// is enabled without a usable local path (never claim "wallpaper enforced"
// without one). CLEAR requires no policy blocks.
func Validate(cmd Command) error {
	switch cmd.Operation {
	case OperationEnforce:
		// validated below
	case OperationClear:
		return nil
	default:
		return fmt.Errorf("SET_DISPLAY_POLICY: unknown operation %q (want ENFORCE|CLEAR)", cmd.Operation)
	}

	if cmd.Screensaver == nil && cmd.Wallpaper == nil {
		return fmt.Errorf("SET_DISPLAY_POLICY ENFORCE: neither screensaver nor wallpaper specified")
	}

	if s := cmd.Screensaver; s != nil && s.Enabled {
		if s.TimeoutSeconds < minScreensaverTimeout || s.TimeoutSeconds > maxScreensaverTimeout {
			return fmt.Errorf("SET_DISPLAY_POLICY: screensaver timeout %d out of range [%d,%d]",
				s.TimeoutSeconds, minScreensaverTimeout, maxScreensaverTimeout)
		}
		if !IsAllowedScrPath(s.ScrPath) {
			return fmt.Errorf("SET_DISPLAY_POLICY: screensaver scrPath %q is not in the System32 allowlist", s.ScrPath)
		}
	}

	if w := cmd.Wallpaper; w != nil && w.Enabled {
		if _, ok := StyleToRegistryValue(w.Style); !ok {
			return fmt.Errorf("SET_DISPLAY_POLICY: unknown wallpaper style %q", w.Style)
		}
		if strings.TrimSpace(w.AssetRef) == "" {
			return fmt.Errorf("SET_DISPLAY_POLICY: wallpaper enabled but no usable asset path (assetRef empty)")
		}
	}
	return nil
}

// IsAllowedScrPath reports whether p is one of the 6 built-in System32 .scr
// files (case-insensitive, exact match — no traversal / env / relative path).
func IsAllowedScrPath(p string) bool {
	_, ok := allowedScrPaths[strings.ToLower(strings.TrimSpace(p))]
	return ok
}

// IsTargetUserSID reports whether a HKEY_USERS subkey name is a loaded real
// interactive user hive the v1 writer should target: an S-1-5-21-… user SID,
// excluding the .DEFAULT template, the well-known service SIDs (S-1-5-18/19/20)
// and the per-user *_Classes hives.
func IsTargetUserSID(sid string) bool {
	s := strings.TrimSpace(sid)
	if !strings.HasPrefix(s, "S-1-5-21-") {
		return false
	}
	if strings.HasSuffix(strings.ToLower(s), "_classes") {
		return false
	}
	return true
}
