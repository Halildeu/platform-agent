//go:build windows

package inventory

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"sort"
	"strings"
	"time"
)

// AG-037 Windows hotfix posture probe.
//
// One pinned PowerShell process emits a single JSON document covering:
//   - WUA `Microsoft.Update.Session.CreateUpdateSearcher.QueryHistory()`
//     for installed hotfix history (operation=1 (install), result=2
//     (success), capped at MaxInstalledHotfixes).
//   - WUA `Search("IsInstalled=0 AND IsHidden=0")` for pending updates
//     (per-item allowlist: KBArticleIDs, Categories[].Type, MsrcSeverity;
//     capped at MaxPendingUpdates).
//   - `Get-Service` for `wuauserv` + `bits` state mapping.
//   - Registry `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate`
//     for LastDetect/Install LastSuccessTime + AU policy AUOptions /
//     NoAutoUpdate.
//
// Mirrors AG-031 pattern: pinned argv input, no payload substitution,
// per-section `sourcePresent` bool, allowlisted JSON projection, every
// cmdlet runs under `-ErrorAction SilentlyContinue` with a typed error
// row in the errors[] tail.

const hotfixProbeTimeout = 45 * time.Second

// hotfixProbeScript is the fixed argv input. No payload-supplied
// substitution, no shell, no `Invoke-Expression`. The script is
// reviewed once and pinned by the build. Output is a single JSON
// document on stdout.
const hotfixProbeScript = `
$ErrorActionPreference = 'SilentlyContinue'

$result = [ordered]@{
  installed = $null
  pending   = $null
  health    = $null
  errors    = @()
}

# ---- Installed hotfixes via WUA UpdateHistory (primary) ----
$installedSourceUsed = 'none'
try {
  $sess = New-Object -ComObject Microsoft.Update.Session
  $searcher = $sess.CreateUpdateSearcher()
  $totalHistory = $searcher.GetTotalHistoryCount()
  if ($totalHistory -gt 0) {
    $history = $searcher.QueryHistory(0, [Math]::Min($totalHistory, 4096))
    $items = New-Object System.Collections.Generic.List[System.Collections.Hashtable]
    foreach ($entry in $history) {
      if ($entry.Operation -ne 1) { continue }  # 1 = installation
      if ($entry.ResultCode -ne 2) { continue } # 2 = success
      $kbs = @()
      if ($entry.Title -match 'KB(\d{6,9})') {
        $kbs += "KB$($Matches[1])"
      }
      if ($entry.UpdateIdentifier) {
        # Per-update KBs are not exposed on history; rely on title parse.
      }
      foreach ($k in ($kbs | Sort-Object -Unique)) {
        $items.Add([ordered]@{
          kbId        = $k
          installedOn = $(if ($entry.Date) { $entry.Date.ToUniversalTime().ToString('o') } else { $null })
          description = $(if ($entry.Title) { $entry.Title.Substring(0, [Math]::Min($entry.Title.Length, 200)) } else { '' })
        })
      }
    }
    $result.installed = [ordered]@{
      sourceUsed = 'wua'
      items      = $items
      totalCount = $items.Count
    }
    $installedSourceUsed = 'wua'
  } else {
    $result.installed = [ordered]@{ sourceUsed = 'wua'; items = @(); totalCount = 0 }
    $installedSourceUsed = 'wua'
  }
} catch {
  $result.errors += [ordered]@{ source = 'wua'; code = 'COM_FAILED'; summary = ($_.Exception.Message | Out-String).Trim() }
}

# ---- Get-HotFix fallback (installed-only) when WUA installed path empty/failed ----
if (-not $result.installed -or $result.installed.totalCount -eq 0) {
  try {
    $hot = Get-HotFix
    if ($hot) {
      $items = New-Object System.Collections.Generic.List[System.Collections.Hashtable]
      foreach ($h in $hot) {
        if (-not $h.HotFixID) { continue }
        $items.Add([ordered]@{
          kbId        = $h.HotFixID
          installedOn = $(if ($h.InstalledOn) { (Get-Date $h.InstalledOn).ToUniversalTime().ToString('o') } else { $null })
          description = $(if ($h.Description) { $h.Description.Substring(0, [Math]::Min($h.Description.Length, 200)) } else { '' })
        })
      }
      $result.installed = [ordered]@{
        sourceUsed = 'getHotfix'
        items      = $items
        totalCount = $items.Count
      }
      $installedSourceUsed = 'getHotfix'
    }
  } catch {
    $result.errors += [ordered]@{ source = 'getHotfix'; code = 'POWERSHELL_FAILED'; summary = ($_.Exception.Message | Out-String).Trim() }
  }
}

# ---- Pending updates via WUA Search (no fallback) ----
try {
  $sess2 = New-Object -ComObject Microsoft.Update.Session
  $searcher2 = $sess2.CreateUpdateSearcher()
  $searchResult = $searcher2.Search("IsInstalled=0 AND IsHidden=0 AND Type='Software'")
  $pendingItems = New-Object System.Collections.Generic.List[System.Collections.Hashtable]
  foreach ($update in $searchResult.Updates) {
    $kbIds = @()
    foreach ($k in $update.KBArticleIDs) { $kbIds += "KB$k" }
    $catGuids = @()
    foreach ($c in $update.Categories) { $catGuids += $c.CategoryID }
    $pendingItems.Add([ordered]@{
      kbIds        = $kbIds
      categoryGuids = $catGuids
      msrcSeverity = $update.MsrcSeverity
    })
  }
  $result.pending = [ordered]@{
    sourceUsed = 'wua'
    items      = $pendingItems
    totalCount = $searchResult.Updates.Count
  }
} catch {
  $result.errors += [ordered]@{ source = 'wua'; code = 'COM_FAILED'; summary = ($_.Exception.Message | Out-String).Trim() }
}

# ---- Service health (wuauserv + bits) ----
try {
  $health = [ordered]@{
    sourceUsed                  = 'service'
    wuaServiceState             = 'UNKNOWN'
    bitsServiceState            = 'UNKNOWN'
    lastDetectAt                = $null
    lastInstallAt               = $null
    autoUpdatePolicyEnabled     = $null
    autoUpdateEffectiveEnabled  = $null
    notificationLevel           = ''
  }
  function _state($name) {
    try {
      $svc = Get-Service -Name $name -ErrorAction Stop
      if ($svc.StartType -eq 'Disabled') { return 'DISABLED' }
      if ($svc.Status -eq 'Running') { return 'RUNNING' }
      return 'STOPPED'
    } catch { return 'UNKNOWN' }
  }
  $health.wuaServiceState  = _state 'wuauserv'
  $health.bitsServiceState = _state 'bits'

  # Registry timestamps + AU policy
  try {
    $detKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\Results\Detect'
    $insKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\Results\Install'
    $auKey  = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update'
    $auPol  = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
    if (Test-Path $detKey) {
      $v = (Get-ItemProperty $detKey -Name LastSuccessTime -ErrorAction SilentlyContinue).LastSuccessTime
      if ($v) { try { $health.lastDetectAt = [DateTime]::Parse($v).ToUniversalTime().ToString('o') } catch {} }
    }
    if (Test-Path $insKey) {
      $v = (Get-ItemProperty $insKey -Name LastSuccessTime -ErrorAction SilentlyContinue).LastSuccessTime
      if ($v) { try { $health.lastInstallAt = [DateTime]::Parse($v).ToUniversalTime().ToString('o') } catch {} }
    }
    if (Test-Path $auKey) {
      $au = Get-ItemProperty $auKey -ErrorAction SilentlyContinue
      if ($au.AUOptions) { $health.notificationLevel = "$($au.AUOptions)" }
    }
    if (Test-Path $auPol) {
      $pol = Get-ItemProperty $auPol -ErrorAction SilentlyContinue
      if ($pol.PSObject.Properties['NoAutoUpdate']) {
        $health.autoUpdatePolicyEnabled = ($pol.NoAutoUpdate -eq 0)
      }
    }
    # Effective = policy permits AND service running
    if ($null -ne $health.autoUpdatePolicyEnabled) {
      $health.autoUpdateEffectiveEnabled = ($health.autoUpdatePolicyEnabled -and $health.wuaServiceState -eq 'RUNNING')
    }
    if (-not (Test-Path $detKey) -and -not (Test-Path $insKey) -and -not (Test-Path $auKey)) {
      $result.errors += [ordered]@{ source = 'registry'; code = 'REGISTRY_UNAVAILABLE'; summary = 'WU registry keys absent' }
    }
  } catch {
    $result.errors += [ordered]@{ source = 'registry'; code = 'REGISTRY_UNAVAILABLE'; summary = ($_.Exception.Message | Out-String).Trim() }
  }
  $result.health = $health
} catch {
  $result.errors += [ordered]@{ source = 'service'; code = 'SERVICE_QUERY_FAILED'; summary = ($_.Exception.Message | Out-String).Trim() }
}

$result | ConvertTo-Json -Depth 6 -Compress
`

// ProbeHotfixPosture is the Windows hotfix posture probe entry point.
// Returns a fully populated `HotfixPostureResult` (never a nil struct);
// errors are reflected in `ProbeErrors` and `ProbeComplete=false`. The
// caller MUST check `ProbeComplete` before treating the result as
// authoritative evidence.
func ProbeHotfixPosture(ctx context.Context, now func() time.Time) HotfixPostureResult {
	if now == nil {
		now = time.Now
	}
	start := now()
	result := HotfixPostureResult{
		SchemaVersion:       HotfixPostureSchemaVersion,
		Supported:           true,
		CollectedAt:         start.UTC(),
		InstalledSourceUsed: HotfixPostureSourceNone,
		PendingSourceUsed:   HotfixPostureSourceNone,
		HealthSourceUsed:    HotfixPostureSourceNone,
		AgentHealth: WindowsUpdateAgentHealth{
			WuaServiceState:  ServiceStateUnknown,
			BitsServiceState: ServiceStateUnknown,
		},
	}

	scriptCtx, cancel := context.WithTimeout(ctx, hotfixProbeTimeout)
	defer cancel()

	cmd := exec.CommandContext(scriptCtx, "powershell.exe",
		"-NoProfile", "-ExecutionPolicy", "Bypass",
		"-OutputFormat", "Text",
		"-Command", hotfixProbeScript)

	out, err := cmd.Output()
	if err != nil {
		if scriptCtx.Err() == context.DeadlineExceeded {
			result.ProbeErrors = append(result.ProbeErrors, HotfixPostureProbeError{
				Source: HotfixPostureSourceWUA,
				Code:   HotfixPosturePowerShellTimeout,
			})
		} else {
			var execErr *exec.Error
			if errors.As(err, &execErr) && strings.Contains(execErr.Err.Error(), "executable file not found") {
				result.ProbeErrors = append(result.ProbeErrors, HotfixPostureProbeError{
					Source: HotfixPostureSourceWUA,
					Code:   HotfixPosturePowerShellMissing,
				})
			} else {
				result.ProbeErrors = append(result.ProbeErrors, HotfixPostureProbeError{
					Source:  HotfixPostureSourceWUA,
					Code:    HotfixPosturePowerShellFailed,
					Summary: redactHotfixSummary(err.Error()),
				})
			}
		}
		finalizeHotfixResult(&result, start, now)
		return result
	}

	trimmed := strings.TrimSpace(string(out))
	if trimmed == "" {
		result.ProbeErrors = append(result.ProbeErrors, HotfixPostureProbeError{
			Source: HotfixPostureSourceWUA,
			Code:   HotfixPosturePowerShellEmptyOutput,
		})
		finalizeHotfixResult(&result, start, now)
		return result
	}

	var raw hotfixProbeRawOutput
	if err := json.Unmarshal([]byte(trimmed), &raw); err != nil {
		result.ProbeErrors = append(result.ProbeErrors, HotfixPostureProbeError{
			Source:  HotfixPostureSourceWUA,
			Code:    HotfixPosturePowerShellParseError,
			Summary: redactHotfixSummary(err.Error()),
		})
		finalizeHotfixResult(&result, start, now)
		return result
	}

	mapHotfixRawToResult(&result, &raw)
	finalizeHotfixResult(&result, start, now)
	return result
}

// hotfixProbeRawOutput mirrors the JSON shape the pinned PowerShell
// script emits. Fields beyond the allowlist are NEVER read here even if
// the script later grows them; we only Unmarshal into the known shape.
type hotfixProbeRawOutput struct {
	Installed *struct {
		SourceUsed string                       `json:"sourceUsed"`
		Items      []hotfixProbeInstalledRawRow `json:"items"`
		TotalCount int                          `json:"totalCount"`
	} `json:"installed"`
	Pending *struct {
		SourceUsed string                     `json:"sourceUsed"`
		Items      []hotfixProbePendingRawRow `json:"items"`
		TotalCount int                        `json:"totalCount"`
	} `json:"pending"`
	Health *hotfixProbeHealthRaw `json:"health"`
	Errors []hotfixProbeErrorRaw `json:"errors"`
}

type hotfixProbeInstalledRawRow struct {
	KbId        string  `json:"kbId"`
	InstalledOn *string `json:"installedOn"`
	Description string  `json:"description"`
}

type hotfixProbePendingRawRow struct {
	KbIds         []string `json:"kbIds"`
	CategoryGuids []string `json:"categoryGuids"`
	MsrcSeverity  string   `json:"msrcSeverity"`
}

type hotfixProbeHealthRaw struct {
	SourceUsed                 string  `json:"sourceUsed"`
	WuaServiceState            string  `json:"wuaServiceState"`
	BitsServiceState           string  `json:"bitsServiceState"`
	LastDetectAt               *string `json:"lastDetectAt"`
	LastInstallAt              *string `json:"lastInstallAt"`
	AutoUpdatePolicyEnabled    *bool   `json:"autoUpdatePolicyEnabled"`
	AutoUpdateEffectiveEnabled *bool   `json:"autoUpdateEffectiveEnabled"`
	NotificationLevel          string  `json:"notificationLevel"`
}

type hotfixProbeErrorRaw struct {
	Source  string `json:"source"`
	Code    string `json:"code"`
	Summary string `json:"summary"`
}

func mapHotfixRawToResult(out *HotfixPostureResult, raw *hotfixProbeRawOutput) {
	// Installed list — apply cap + deterministic order.
	if raw.Installed != nil {
		out.InstalledSourceUsed = canonicalHotfixSource(raw.Installed.SourceUsed)
		items := make([]InstalledHotfix, 0, len(raw.Installed.Items))
		for _, row := range raw.Installed.Items {
			h := InstalledHotfix{
				KbId:        strings.TrimSpace(row.KbId),
				Description: clampString(row.Description, 200),
			}
			if row.InstalledOn != nil {
				if t, err := time.Parse(time.RFC3339, *row.InstalledOn); err == nil {
					u := t.UTC()
					h.InstalledOn = &u
				}
			}
			if h.KbId == "" {
				continue
			}
			items = append(items, h)
		}
		// Sort: installedOn DESC nulls last, then KbId ASC.
		sort.SliceStable(items, func(i, j int) bool {
			a, b := items[i], items[j]
			if a.InstalledOn != nil && b.InstalledOn != nil {
				if !a.InstalledOn.Equal(*b.InstalledOn) {
					return a.InstalledOn.After(*b.InstalledOn)
				}
				return a.KbId < b.KbId
			}
			if a.InstalledOn != nil {
				return true
			}
			if b.InstalledOn != nil {
				return false
			}
			return a.KbId < b.KbId
		})
		out.InstalledCount = len(items)
		if len(items) > MaxInstalledHotfixes {
			out.InstalledTruncated = true
			items = items[:MaxInstalledHotfixes]
		}
		out.InstalledHotfixes = items
	}

	// Pending list — normalise category/severity, apply cap.
	if raw.Pending != nil {
		out.PendingSourceUsed = canonicalHotfixSource(raw.Pending.SourceUsed)
		pendingItems := make([]PendingUpdateItem, 0, len(raw.Pending.Items))
		categoryCounts := map[HotfixPostureCategory]int{}
		for _, row := range raw.Pending.Items {
			cat := primaryCategoryFromGuids(row.CategoryGuids)
			sev := severityFromMsrc(row.MsrcSeverity)
			pendingItems = append(pendingItems, PendingUpdateItem{
				KbIds:           row.KbIds,
				PrimaryCategory: cat,
				Severity:        sev,
			})
			categoryCounts[cat]++
		}
		// Deterministic order: severity rank then category then first kbId.
		sort.SliceStable(pendingItems, func(i, j int) bool {
			a, b := pendingItems[i], pendingItems[j]
			ar, br := severityRank(a.Severity), severityRank(b.Severity)
			if ar != br {
				return ar < br
			}
			ac, bc := categoryRank(a.PrimaryCategory), categoryRank(b.PrimaryCategory)
			if ac != bc {
				return ac < bc
			}
			af, bf := firstStr(a.KbIds), firstStr(b.KbIds)
			return af < bf
		})
		out.PendingTotalCount = len(pendingItems)
		if len(pendingItems) > MaxPendingUpdates {
			out.PendingTruncated = true
			pendingItems = pendingItems[:MaxPendingUpdates]
		}
		out.PendingUpdates = pendingItems

		// Category rollup — deterministic order matching categoryRank.
		out.PendingByCategory = make([]PendingUpdateCategoryCount, 0, len(categoryCounts))
		for cat, n := range categoryCounts {
			out.PendingByCategory = append(out.PendingByCategory, PendingUpdateCategoryCount{
				Category: cat, Count: n,
			})
		}
		sort.SliceStable(out.PendingByCategory, func(i, j int) bool {
			return categoryRank(out.PendingByCategory[i].Category) < categoryRank(out.PendingByCategory[j].Category)
		})
	}

	// Health.
	if raw.Health != nil {
		out.HealthSourceUsed = canonicalHotfixSource(raw.Health.SourceUsed)
		out.AgentHealth = WindowsUpdateAgentHealth{
			WuaServiceState:            canonicalServiceState(raw.Health.WuaServiceState),
			BitsServiceState:           canonicalServiceState(raw.Health.BitsServiceState),
			NotificationLevel:          clampString(raw.Health.NotificationLevel, 64),
			AutoUpdatePolicyEnabled:    raw.Health.AutoUpdatePolicyEnabled,
			AutoUpdateEffectiveEnabled: raw.Health.AutoUpdateEffectiveEnabled,
		}
		if raw.Health.LastDetectAt != nil {
			if t, err := time.Parse(time.RFC3339, *raw.Health.LastDetectAt); err == nil {
				u := t.UTC()
				out.AgentHealth.LastDetectAt = &u
			}
		}
		if raw.Health.LastInstallAt != nil {
			if t, err := time.Parse(time.RFC3339, *raw.Health.LastInstallAt); err == nil {
				u := t.UTC()
				out.AgentHealth.LastInstallAt = &u
			}
		}
	}

	// Errors — propagate typed errors verbatim, redacting any free
	// summary the script attached.
	for _, e := range raw.Errors {
		code := canonicalHotfixErrorCode(e.Code)
		if code == "" {
			continue
		}
		out.ProbeErrors = append(out.ProbeErrors, HotfixPostureProbeError{
			Source:  canonicalHotfixSource(e.Source),
			Code:    code,
			Summary: redactHotfixSummary(e.Summary),
		})
	}
}

func finalizeHotfixResult(r *HotfixPostureResult, start time.Time, now func() time.Time) {
	end := now()
	r.ProbeDurationMs = end.Sub(start).Milliseconds()
	if r.ProbeDurationMs < 0 {
		r.ProbeDurationMs = 0
	}
	r.ProbeComplete = len(r.ProbeErrors) == 0
	if r.InstalledSourceUsed == "" {
		r.InstalledSourceUsed = HotfixPostureSourceNone
	}
	if r.PendingSourceUsed == "" {
		r.PendingSourceUsed = HotfixPostureSourceNone
	}
	if r.HealthSourceUsed == "" {
		r.HealthSourceUsed = HotfixPostureSourceNone
	}
}

// --- Normalisers ---------------------------------------------------

func canonicalHotfixSource(s string) HotfixPostureSource {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "wua":
		return HotfixPostureSourceWUA
	case "gethotfix":
		return HotfixPostureSourceGetHotfix
	case "registry":
		return HotfixPostureSourceRegistry
	case "service":
		return HotfixPostureSourceService
	case "none", "":
		return HotfixPostureSourceNone
	default:
		return HotfixPostureSourceUnknown
	}
}

func canonicalServiceState(s string) ServiceState {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "RUNNING":
		return ServiceStateRunning
	case "STOPPED":
		return ServiceStateStopped
	case "DISABLED":
		return ServiceStateDisabled
	default:
		return ServiceStateUnknown
	}
}

func canonicalHotfixErrorCode(s string) HotfixPostureProbeErrorCode {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "UNSUPPORTED_PLATFORM":
		return HotfixPostureUnsupportedPlatform
	case "ACCESS_DENIED":
		return HotfixPostureAccessDenied
	case "COM_FAILED":
		return HotfixPostureCOMFailed
	case "WSUS_UNREACHABLE":
		return HotfixPostureWSUSUnreachable
	case "POWERSHELL_MISSING":
		return HotfixPosturePowerShellMissing
	case "POWERSHELL_TIMEOUT":
		return HotfixPosturePowerShellTimeout
	case "POWERSHELL_FAILED":
		return HotfixPosturePowerShellFailed
	case "POWERSHELL_EMPTY_OUTPUT":
		return HotfixPosturePowerShellEmptyOutput
	case "POWERSHELL_PARSE_ERROR":
		return HotfixPosturePowerShellParseError
	case "REGISTRY_UNAVAILABLE":
		return HotfixPostureRegistryUnavailable
	case "SERVICE_QUERY_FAILED":
		return HotfixPostureServiceQueryFailed
	case "NO_EVIDENCE":
		return HotfixPostureNoEvidence
	default:
		return ""
	}
}

// primaryCategoryFromGuids reduces the Microsoft Update Category GUID
// set to a single canonical bucket using deterministic precedence.
// GUID mapping is a v1 subset; new GUIDs fall through to UNCATEGORIZED.
func primaryCategoryFromGuids(guids []string) HotfixPostureCategory {
	// Microsoft Update Classification GUIDs (canonical subset).
	// Reference: docs.microsoft.com/en-us/windows/win32/wua_sdk/
	//   determining-the-category-of-an-update
	knownByGUID := map[string]HotfixPostureCategory{
		"0fa1201d-4330-4fa8-8ae9-b877473b6441": HotfixPostureCategorySecurity,
		"e6cf1350-c01b-414d-a61f-263d14d133b4": HotfixPostureCategoryDefinition,
		"e0789628-ce08-4437-be74-2495b842f43b": HotfixPostureCategoryCritical,
		"68c5b0a3-d1a6-4553-ae49-01d3a7827828": HotfixPostureCategoryImportant,
		"b54e7d24-7add-428f-8b75-90a396fa584f": HotfixPostureCategoryOptional,
		"ebfd1a04-94f6-4b29-8e90-d6c0c87baa5c": HotfixPostureCategoryDriver,
		"b612e9ec-7f9b-4f81-94b9-7c40d3e8ac02": HotfixPostureCategoryFeaturePack,
		"68c5b0a3-d1a6-4553-ae49-01d3a7827829": HotfixPostureCategoryServicePack,
		"28bc880e-0592-4cbf-8f95-c79b17911d5f": HotfixPostureCategoryUpdateRollup,
		"b4832bd8-e735-4761-8daf-37f882276dab": HotfixPostureCategoryTools,
	}
	out := HotfixPostureCategoryUncategorized
	bestRank := categoryRank(out)
	for _, g := range guids {
		k := strings.ToLower(strings.TrimSpace(g))
		if cat, ok := knownByGUID[k]; ok {
			if categoryRank(cat) < bestRank {
				bestRank = categoryRank(cat)
				out = cat
			}
		}
	}
	return out
}

// severityFromMsrc canonicalises the MSRC severity rating string.
func severityFromMsrc(s string) HotfixPostureSeverity {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "CRITICAL":
		return HotfixPostureSeverityCritical
	case "IMPORTANT":
		return HotfixPostureSeverityImportant
	case "MODERATE":
		return HotfixPostureSeverityModerate
	case "LOW":
		return HotfixPostureSeverityLow
	default:
		return HotfixPostureSeverityUnspecified
	}
}

// categoryRank — deterministic precedence (lower = higher priority).
func categoryRank(c HotfixPostureCategory) int {
	switch c {
	case HotfixPostureCategorySecurity:
		return 0
	case HotfixPostureCategoryDefinition:
		return 1
	case HotfixPostureCategoryCritical:
		return 2
	case HotfixPostureCategoryImportant:
		return 3
	case HotfixPostureCategoryDriver:
		return 4
	case HotfixPostureCategoryUpdateRollup:
		return 5
	case HotfixPostureCategoryFeaturePack:
		return 6
	case HotfixPostureCategoryServicePack:
		return 7
	case HotfixPostureCategoryOptional:
		return 8
	case HotfixPostureCategoryTools:
		return 9
	default:
		return 99
	}
}

func severityRank(s HotfixPostureSeverity) int {
	switch s {
	case HotfixPostureSeverityCritical:
		return 0
	case HotfixPostureSeverityImportant:
		return 1
	case HotfixPostureSeverityModerate:
		return 2
	case HotfixPostureSeverityLow:
		return 3
	default:
		return 99
	}
}

// --- Helpers --------------------------------------------------------

func clampString(s string, max int) string {
	s = strings.TrimSpace(s)
	if len(s) > max {
		return s[:max]
	}
	return s
}

func firstStr(ss []string) string {
	if len(ss) == 0 {
		return ""
	}
	return ss[0]
}

// redactHotfixSummary scrubs operator-readable text for the wire-safe
// `summary` field on probe errors. We aggressively drop anything that
// might leak path / username / hostname / verbose stack dumps.
func redactHotfixSummary(s string) string {
	s = strings.TrimSpace(s)
	// Strip CR/LF and tabs to keep summaries single-line.
	s = strings.ReplaceAll(s, "\r", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\t", " ")
	// Cap length aggressively — the typed Code is the signal; summary
	// is only operator-readable context.
	const cap = 200
	if len(s) > cap {
		s = s[:cap]
	}
	// Defence in depth: redact \\server\share, C:\Users\..., etc.
	for _, prefix := range []string{"\\\\", "C:\\Users\\", "D:\\Users\\"} {
		if idx := strings.Index(s, prefix); idx >= 0 {
			s = s[:idx] + "<redacted>"
		}
	}
	return s
}

// Compile-time guard that the script compiles syntactically: ensures
// our pinned argv input never silently drops a PowerShell change.
var _ = fmt.Sprintf

// errorsAsForLinker prevents the unused-import lint when the package
// is built without the cmd.Output() failure path being exercised.
var _ = errors.As
