package software

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"regexp"
	"sort"
	"strings"
	"time"

	"platform-agent/internal/security"
)

// RegistrySource enumerates one of the Uninstall hives. Collector
// implementations populate a slice of these and hand them to Normalize,
// which is the entire I/O boundary of this package: Normalize takes
// pre-read data and produces a SoftwareSnapshot, so unit tests can drive
// it without touching the real Windows registry.
type RegistrySource struct {
	// Label is the InstallSource value that will appear on every
	// InstalledApp produced from this source. Must be one of the
	// SourceHKLM64 / SourceHKLM32 / SourceHKCUAgentContext constants.
	Label string

	// Architecture is the package architecture inferred from the hive
	// ("x64" for HKLM 64-bit view, "x86" for WOW6432). Empty leaves
	// the field unset on the resulting InstalledApp.
	Architecture string

	// Subkeys are the raw Uninstall entries discovered under this hive.
	Subkeys []RegistrySubkey

	// ReadErr captures a fatal enumeration error (e.g. registry key
	// did not exist on this OS edition). It becomes a probeErrors
	// entry on the snapshot rather than failing the whole collect.
	ReadErr error
}

// RegistrySubkey is one Uninstall registry key as it was read from disk.
// The collector populates these; Normalize never reads from disk.
type RegistrySubkey struct {
	Name string // the subkey name (often the MSI ProductCode GUID)

	DisplayName          string
	DisplayVersion       string
	Publisher            string
	InstallDate          string
	EstimatedSize        int // raw EstimatedSize DWORD (KB on Windows)
	UninstallString      string
	QuietUninstallString string
	SystemComponent      int // SystemComponent DWORD; 1 means "hidden"
	ParentKeyName        string
	ReleaseType          string
}

// Normalize turns the per-hive read results into a wire-safe
// SoftwareSnapshot. It enforces every payload-discipline guarantee the
// package promises: dedup, hidden-row filtering, sanitisation, MSI
// ProductCode hashing, max-app + max-payload truncation, deterministic
// ordering.
//
// Determinism matters because the snapshot ends up in an HMAC-signed
// request body — two consecutive collects on the same host must
// produce the same JSON modulo the timestamp.
func Normalize(sources []RegistrySource, now time.Time, opts CollectOptions) SoftwareSnapshot {
	if opts.MaxApps <= 0 {
		opts.MaxApps = DefaultMaxApps
	}
	if opts.MaxPayloadBytes <= 0 {
		opts.MaxPayloadBytes = DefaultMaxPayloadBytes
	}

	snapshot := SoftwareSnapshot{
		Supported:     true,
		SchemaVersion: SchemaVersion,
		CollectedAt:   now.UTC(),
	}

	// Dedup by (displayName, displayVersion, label) — Windows often
	// records the same product under both HKLM64 and HKLM32 views and
	// we don't want to double-count.
	seen := map[string]struct{}{}
	candidates := make([]InstalledApp, 0, 256)
	totalSize := 0

	for _, source := range sources {
		if source.ReadErr != nil {
			snapshot.ProbeErrors = append(snapshot.ProbeErrors,
				security.RedactSoftwareString(source.Label+": "+source.ReadErr.Error()))
			continue
		}
		if !isAllowedLabel(source.Label) {
			snapshot.ProbeErrors = append(snapshot.ProbeErrors,
				"unknown install source label: "+source.Label)
			continue
		}
		for _, subkey := range source.Subkeys {
			if shouldSkip(subkey) {
				continue
			}
			app := buildApp(subkey, source.Label, source.Architecture)
			if app.DisplayName == "" {
				continue
			}
			key := strings.ToLower(app.DisplayName + "|" + app.DisplayVersion + "|" + app.InstallSource)
			if _, dup := seen[key]; dup {
				continue
			}
			seen[key] = struct{}{}
			candidates = append(candidates, app)
			totalSize += app.EstimatedSizeKB
		}
	}

	// Deterministic ordering: case-insensitive displayName, then
	// version, then install source. This makes JSON output stable for
	// HMAC signing and diff-able for operators.
	sort.Slice(candidates, func(i, j int) bool {
		a, b := candidates[i], candidates[j]
		if cmp := strings.Compare(strings.ToLower(a.DisplayName), strings.ToLower(b.DisplayName)); cmp != 0 {
			return cmp < 0
		}
		if a.DisplayVersion != b.DisplayVersion {
			return a.DisplayVersion < b.DisplayVersion
		}
		return a.InstallSource < b.InstallSource
	})

	// Cap by app count first. We record the original count (pre-cap)
	// in TotalSizeKB so operators can see how much we dropped on the
	// floor without scraping the host directly.
	snapshot.AppCount = len(candidates)
	snapshot.TotalSizeKB = totalSize
	if len(candidates) > opts.MaxApps {
		candidates = candidates[:opts.MaxApps]
		snapshot.Truncated = true
	}

	// Cap by serialised payload size. We re-marshal after each append
	// rather than estimating, so the cap is precise regardless of
	// string lengths. This is O(N) on the cap rather than O(N²)
	// because we stop the first time the budget is exceeded.
	accepted := candidates[:0]
	for _, app := range candidates {
		probe := append(accepted, app)
		raw, _ := json.Marshal(probe)
		if len(raw) > opts.MaxPayloadBytes {
			snapshot.Truncated = true
			break
		}
		accepted = probe
	}
	snapshot.Apps = accepted

	return snapshot
}

func shouldSkip(subkey RegistrySubkey) bool {
	if subkey.SystemComponent == 1 {
		// SystemComponent=1 marks rows the OS hides from
		// "Programs and Features". Including them would balloon
		// the inventory with internal Windows updates and
		// runtime fragments operators don't care about.
		return true
	}
	if strings.TrimSpace(subkey.ParentKeyName) != "" {
		// Hotfix / cumulative update rows reference a parent key
		// and are skipped for the same reason.
		return true
	}
	if strings.EqualFold(subkey.ReleaseType, "Hotfix") ||
		strings.EqualFold(subkey.ReleaseType, "Security Update") ||
		strings.EqualFold(subkey.ReleaseType, "Update Rollup") {
		return true
	}
	return false
}

func buildApp(subkey RegistrySubkey, label, architecture string) InstalledApp {
	hasUninstall := strings.TrimSpace(subkey.UninstallString) != "" ||
		strings.TrimSpace(subkey.QuietUninstallString) != ""
	return InstalledApp{
		DisplayName:            security.RedactSoftwareString(strings.TrimSpace(subkey.DisplayName)),
		DisplayVersion:         security.RedactSoftwareString(strings.TrimSpace(subkey.DisplayVersion)),
		Publisher:              security.RedactSoftwareString(strings.TrimSpace(subkey.Publisher)),
		InstallDate:            normalizeInstallDate(subkey.InstallDate),
		EstimatedSizeKB:        clampNonNegative(subkey.EstimatedSize),
		Architecture:           architecture,
		InstallSource:          label,
		UninstallStringPresent: hasUninstall,
		MSIProductCodeHash:     msiProductCodeHash(subkey.Name),
	}
}

var (
	allowedLabels = map[string]struct{}{
		SourceHKLM64:           {},
		SourceHKLM32:           {},
		SourceHKCUAgentContext: {},
	}
	// MSI ProductCode subkey names look like
	// "{4A03706F-666A-4037-7777-5F2748764D10}" — case-insensitive,
	// curly-brace wrapped, GUID body.
	msiProductCodePattern = regexp.MustCompile(`^\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}$`)
	// Windows registry InstallDate convention is YYYYMMDD (eight
	// digits). Anything else is dropped to keep the field disciplined.
	installDatePattern = regexp.MustCompile(`^\d{8}$`)
)

func isAllowedLabel(label string) bool {
	_, ok := allowedLabels[label]
	return ok
}

func normalizeInstallDate(raw string) string {
	raw = strings.TrimSpace(raw)
	if installDatePattern.MatchString(raw) {
		return raw
	}
	return ""
}

func clampNonNegative(value int) int {
	if value < 0 {
		return 0
	}
	return value
}

// msiProductCodeHash returns the SHA-256 of the canonical (upper-cased)
// ProductCode GUID, prefixed with "sha256:" to match the existing
// identity-hash convention. Non-MSI subkey names (often the product
// DisplayName itself, e.g. "Mozilla Firefox 123.0") return empty so the
// field is dropped from JSON via omitempty.
func msiProductCodeHash(subkeyName string) string {
	name := strings.TrimSpace(subkeyName)
	if !msiProductCodePattern.MatchString(name) {
		return ""
	}
	sum := sha256.Sum256([]byte(strings.ToUpper(name)))
	return "sha256:" + hex.EncodeToString(sum[:])[:16]
}

// Summarize collapses a SoftwareSnapshot + WinGet readiness into the
// Summary the inventory payload embeds. When includeApps is false the
// full Apps slice is dropped (default behaviour, keeps the payload
// small); when true the slice is carried through with the size caps
// already enforced by Normalize.
//
// ProbeErrors / TotalSizeKB / Truncated are always copied across
// because they're either empty (cheap) or operationally important
// (callers want to know we hit a cap or failed a hive read even on the
// summary-only path).
func Summarize(snapshot SoftwareSnapshot, wingetReady bool, wingetVersion string, includeApps bool) Summary {
	summary := Summary{
		Supported:     snapshot.Supported,
		AppCount:      snapshot.AppCount,
		WinGetReady:   wingetReady,
		WinGetVersion: wingetVersion,
		SchemaVersion: SchemaVersion,
		TotalSizeKB:   snapshot.TotalSizeKB,
		Truncated:     snapshot.Truncated,
		ProbeErrors:   snapshot.ProbeErrors,
	}
	if includeApps {
		summary.Apps = snapshot.Apps
	}
	return summary
}
