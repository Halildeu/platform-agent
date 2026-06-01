//go:build windows

package inventory

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/windows/registry"
)

// startupExposureAggregate is the channel payload from the
// registry/filesystem/Task Scheduler worker.
type startupExposureAggregate struct {
	apps                    []StartupApp
	rdpEnabled              bool
	firewallEventLogEnabled bool
	probeErrors             []StartupExposureProbeError
}

// ProbeStartupExposure is the Windows registry + filesystem + Task
// Scheduler implementation. Codex 019e8387 plan iter-1 absorb:
//
//   - Registry: HKLM/HKCU \SOFTWARE\Microsoft\Windows\CurrentVersion\
//     {Run, RunOnce} + WOW6432Node Run mirrors — opened with
//     QUERY_VALUE | WOW64_64KEY; only the value NAMES are reported
//     (NOT the data, which contains executable paths).
//   - Filesystem: enumerate the Common Startup
//     (%ALLUSERSPROFILE%\Microsoft\Windows\Start Menu\Programs\Startup)
//     and User Startup
//     (%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup) folders
//     for shortcut / script entries — only the file basename (without
//     extension) is reported.
//   - Task Scheduler: pinned PowerShell `Get-ScheduledTask` enumeration
//     filtered to non-disabled tasks; only TaskName + TaskPath (folder
//     hierarchy, NOT executable) are extracted; TaskPath is then
//     bucketed to ROOT / MICROSOFT_WINDOWS / CUSTOM. NO command / args
//     / RunAs / triggers ever surface.
//   - Win32 RDP exposure: registry read
//     HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\
//     fDenyTSConnections; RdpEnabled is the INVERSE
//     (fDenyTSConnections=0 → RdpEnabled=true). Codex 019e8387 plan
//     iter-1 P1 #3 absorb (the authoritative listener state; TermService
//     running is NOT equivalent).
//   - Win32 Firewall event-log: registry read
//     HKLM\SYSTEM\CurrentControlSet\Services\MpsSvc\Parameters\
//     PolicyStore — boolean check (key exists and non-empty →
//     enabled).
//
// Codex 019e8302 iter-3 P1 #3 + iter-4 P1 absorb pattern (carried from
// AG-039): ProbeStartupExposure owns its own StartupExposureProbeTimeout
// bounded context AND runs the blocking work in a background goroutine
// so the contract is actually enforced. A timeout-fired result returns
// supported=true + empty apps + NO_EVIDENCE probe error +
// probeComplete=false.
func ProbeStartupExposure(ctx context.Context, now func() time.Time) StartupExposureResult {
	if now == nil {
		now = time.Now
	}
	startedAt := now()

	// Bounded context.
	probeCtx, cancel := context.WithTimeout(ctx, StartupExposureProbeTimeout)
	defer cancel()

	done := make(chan startupExposureAggregate, 1)
	go func() {
		done <- runStartupExposureProbeBlocking(probeCtx)
	}()

	select {
	case agg := <-done:
		return orchestrateStartupExposureProbe(
			probeCtx, now, true,
			agg.apps, agg.rdpEnabled, agg.firewallEventLogEnabled,
			agg.probeErrors, startedAt,
		)
	case <-probeCtx.Done():
		// Timeout / caller cancel — the worker may still be blocked in
		// PowerShell or registry calls; we abandon it (goroutine drains
		// itself) and return fail-closed no-evidence shape rather than
		// waiting indefinitely.
		return orchestrateStartupExposureProbe(
			probeCtx, now, true,
			[]StartupApp{}, false, false,
			[]StartupExposureProbeError{{
				Code:    StartupExposureErrNoEvidence,
				Summary: "Startup/exposure probe deadline exceeded",
			}},
			startedAt,
		)
	}
}

// runStartupExposureProbeBlocking is the synchronous registry +
// filesystem + Task Scheduler enumeration body.
//
// Codex 019e83a8 iter-2 P1 absorb (visibility DoS): redaction probe
// errors are aggregated per source location (NOT per redacted entry).
// A misbehaving / hostile host with 17+ forbidden-named autorun
// entries cannot otherwise exhaust the backend's PROBE_ERRORS_MAX=16
// cap and break ingest entirely. Caps NAME_VALUE_REDACTED contributions
// at 10 (one per autorun anchor enum) — leaving 6 of the 16 slots
// for real probe errors.
func runStartupExposureProbeBlocking(ctx context.Context) startupExposureAggregate {
	var apps []StartupApp
	var probeErrors []StartupExposureProbeError
	// redactionCounts tracks per-source redaction tallies so we can
	// emit ONE NAME_VALUE_REDACTED probe error per location with a
	// non-PII count (not per redacted entry).
	redactionCounts := make(map[StartupAppLocation]int)

	// Registry enumerations.
	for _, spec := range registryStartupSpecs() {
		entries, redactions, err := enumerateRegistryRun(spec.root, spec.path, spec.location)
		if err != nil {
			probeErrors = append(probeErrors, StartupExposureProbeError{
				Code:    StartupExposureErrRegistryQueryFailed,
				Source:  spec.location,
				Summary: "Registry enumeration failed",
			})
			continue
		}
		apps = append(apps, entries...)
		redactionCounts[spec.location] += len(redactions)
	}

	// Filesystem startup folders.
	for _, spec := range filesystemStartupSpecs() {
		entries, redactions, err := enumerateStartupFolder(spec.envExpand, spec.location)
		if err != nil {
			probeErrors = append(probeErrors, StartupExposureProbeError{
				Code:    StartupExposureErrStartupFolderUnreadable,
				Source:  spec.location,
				Summary: "Startup folder enumeration failed",
			})
			continue
		}
		apps = append(apps, entries...)
		redactionCounts[spec.location] += len(redactions)
	}

	// Task Scheduler enumeration (filtered to startup/logon triggers
	// only — Codex 019e83a8 iter-1 P1#1 absorb: an unfiltered
	// Get-ScheduledTask sweep returns 100+ Microsoft system tasks on
	// a stock Windows host, swamps the cap, and hides actual
	// persistence signals).
	taskApps, taskRedactions, taskErr := enumerateScheduledTasks(ctx)
	if taskErr != nil {
		probeErrors = append(probeErrors, *taskErr)
	}
	apps = append(apps, taskApps...)
	for _, r := range taskRedactions {
		// taskRedactions carry the bucket Location already; aggregate
		// into the per-source counter.
		redactionCounts[r.Source]++
	}

	// Emit aggregated NAME_VALUE_REDACTED probe errors (1 per
	// affected source location, max 10 total).
	probeErrors = append(probeErrors,
		buildRedactionProbeErrors(redactionCounts)...,
	)

	// RDP scalar.
	rdp, rdpErr := probeRdpEnabled()
	if rdpErr != nil {
		probeErrors = append(probeErrors, *rdpErr)
	}

	// Firewall event-log scalar.
	fwEvt, fwErr := probeFirewallEventLog()
	if fwErr != nil {
		probeErrors = append(probeErrors, *fwErr)
	}

	return startupExposureAggregate{
		apps:                    apps,
		rdpEnabled:              rdp,
		firewallEventLogEnabled: fwEvt,
		probeErrors:             probeErrors,
	}
}

// registryStartupSpec couples a registry root + relative path with the
// wire Location enum it should report under.
type registryStartupSpec struct {
	root     registry.Key
	path     string
	location StartupAppLocation
}

func registryStartupSpecs() []registryStartupSpec {
	return []registryStartupSpec{
		{registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`, StartupLocationHKLMRun},
		{registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`, StartupLocationHKLMRunOnce},
		{registry.LOCAL_MACHINE, `SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run`, StartupLocationHKLMWow6432Run},
		{registry.CURRENT_USER, `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`, StartupLocationHKCURun},
		{registry.CURRENT_USER, `SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`, StartupLocationHKCURunOnce},
	}
}

// enumerateRegistryRun opens the Run/RunOnce key read-only and returns
// the value NAMES (NOT the data). A registry value being PRESENT in
// these keys means it is enabled by Windows definition — there is no
// separate enabled flag. Codex 019e83a8 iter-1 P1#2 absorb: every value
// NAME is filtered through shouldRedactName() because the name field
// itself is operator-controlled and can carry path/command fragments
// (`C:\Users\Alice\...`, `cmd /c ...`, `\\server\share\foo`,
// `OneDrive.exe`). Redacted entries are OMITTED and a NAME_VALUE_REDACTED
// probe error is emitted with `source` = anchor enum + bounded summary.
func enumerateRegistryRun(root registry.Key, path string, location StartupAppLocation) ([]StartupApp, []StartupExposureProbeError, error) {
	key, err := registry.OpenKey(root, path, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		// "Key does not exist" is NOT an error — it means no autorun
		// entries in that slot. Distinguish from genuine read failures.
		if err == registry.ErrNotExist {
			return nil, nil, nil
		}
		return nil, nil, err
	}
	defer key.Close()

	names, err := key.ReadValueNames(-1)
	if err != nil {
		return nil, nil, err
	}

	apps := make([]StartupApp, 0, len(names))
	var redactions []StartupExposureProbeError
	for _, name := range names {
		if shouldRedactName(name) {
			redactions = append(redactions, StartupExposureProbeError{
				Code:    StartupExposureErrNameValueRedacted,
				Source:  location,
				Summary: "Autorun entry name redacted (path or command fragment)",
			})
			continue
		}
		apps = append(apps, StartupApp{
			Name:        name,
			Location:    location,
			Enabled:     true,
			ProbeOrigin: StartupProbeOriginRegistry,
		})
	}
	return apps, redactions, nil
}

// filesystemStartupSpec couples an env-var path expander with the wire
// Location enum it should report under.
type filesystemStartupSpec struct {
	envExpand func() string
	location  StartupAppLocation
}

func filesystemStartupSpecs() []filesystemStartupSpec {
	return []filesystemStartupSpec{
		{
			envExpand: func() string {
				allUsers := os.Getenv("ALLUSERSPROFILE")
				if allUsers == "" {
					return ""
				}
				return filepath.Join(allUsers, `Microsoft\Windows\Start Menu\Programs\Startup`)
			},
			location: StartupLocationStartupFolderCommon,
		},
		{
			envExpand: func() string {
				appData := os.Getenv("APPDATA")
				if appData == "" {
					return ""
				}
				return filepath.Join(appData, `Microsoft\Windows\Start Menu\Programs\Startup`)
			},
			location: StartupLocationStartupFolderUser,
		},
	}
}

// enumerateStartupFolder reads the startup folder and returns one
// StartupApp per regular file. Only the basename WITHOUT the extension
// is captured (e.g., "OneDrive.lnk" → "OneDrive"); the full path is
// NEVER surfaced. Codex 019e83a8 iter-1 P1#2 absorb: shouldRedactName
// filter applies to the basename too — a malicious operator could
// create a shortcut named `C\Users\Alice\foo.lnk` which after extension
// strip becomes `C\Users\Alice\foo`; that should be redacted.
func enumerateStartupFolder(envExpand func() string, location StartupAppLocation) ([]StartupApp, []StartupExposureProbeError, error) {
	dir := envExpand()
	if dir == "" {
		// Env var not set; treat as empty (NOT an error).
		return nil, nil, nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			// Folder simply does not exist on this host; treat as empty.
			return nil, nil, nil
		}
		return nil, nil, err
	}
	apps := make([]StartupApp, 0, len(entries))
	var redactions []StartupExposureProbeError
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		// "desktop.ini" is a Windows metadata file — exclude.
		if strings.EqualFold(name, "desktop.ini") {
			continue
		}
		ext := filepath.Ext(name)
		base := strings.TrimSuffix(name, ext)
		if shouldRedactName(base) {
			redactions = append(redactions, StartupExposureProbeError{
				Code:    StartupExposureErrNameValueRedacted,
				Source:  location,
				Summary: "Startup-folder entry name redacted (path or command fragment)",
			})
			continue
		}
		apps = append(apps, StartupApp{
			Name:        base,
			Location:    location,
			Enabled:     true,
			ProbeOrigin: StartupProbeOriginRegistry,
		})
	}
	return apps, redactions, nil
}

// scheduledTaskRow is the JSON shape produced by the pinned PowerShell
// enumeration script. We capture ONLY the task name + task folder path
// + state — no Actions, no Triggers, no Author, no RunAs, no
// Description.
type scheduledTaskRow struct {
	TaskName string `json:"TaskName"`
	TaskPath string `json:"TaskPath"`
	State    string `json:"State"`
}

// enumerateScheduledTasks invokes PowerShell with a pinned script that
// returns ONLY the bounded fields above. Codex 019e8387 plan + 019e83a8
// post-impl iter-1 P1#1 absorb: scheduled task enumeration uses a
// fixed argv (no payload-supplied interpolation), the script body
// never calls a mutating cmdlet, AND the result is FILTERED to tasks
// with at least one Boot (MSFT_TaskBootTrigger) or Logon
// (MSFT_TaskLogonTrigger) trigger — an unfiltered sweep returns
// hundreds of Microsoft system tasks on a stock Windows host and
// drowns the cap with noise.
//
// The script:
//   1. Get-ScheduledTask returns all tasks (read-only).
//   2. Where-Object filters to non-Disabled state AND at least one
//      Boot/Logon trigger.
//   3. ForEach-Object projects to the 3-field shape.
//   4. ConvertTo-Json -Compress for compact transport.
//
// On any failure (powershell.exe missing, COM unavailable, JSON
// decode), the function returns nil + a probe error.
func enumerateScheduledTasks(ctx context.Context) ([]StartupApp, []StartupExposureProbeError, *StartupExposureProbeError) {
	const psScript = `$ErrorActionPreference = 'Stop'
try {
  $autorunTriggerClasses = @('MSFT_TaskBootTrigger', 'MSFT_TaskLogonTrigger')
  $tasks = Get-ScheduledTask | Where-Object {
    $_.State -ne 'Disabled' -and (
      $_.Triggers | Where-Object {
        $_ -ne $null -and $_.CimClass -ne $null -and ($autorunTriggerClasses -contains $_.CimClass.CimClassName)
      }
    )
  } | ForEach-Object {
    [PSCustomObject]@{
      TaskName = $_.TaskName
      TaskPath = $_.TaskPath
      State    = [string]$_.State
    }
  }
  if ($null -eq $tasks) { '[]' } else { $tasks | ConvertTo-Json -Compress -Depth 4 }
} catch {
  Write-Error $_.Exception.Message
  exit 1
}`

	cmd := exec.CommandContext(ctx,
		"powershell.exe",
		"-NoProfile",
		"-NonInteractive",
		"-ExecutionPolicy", "Bypass",
		"-Command", psScript,
	)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, nil, &StartupExposureProbeError{
			Code:    StartupExposureErrTaskSchedulerUnavail,
			Summary: "Task Scheduler enumeration failed",
		}
	}

	// ConvertTo-Json yields either a JSON object (1 task) or array (n
	// tasks) or our literal "[]" string when none matched. Handle all.
	out := bytes.TrimSpace(stdout.Bytes())
	if len(out) == 0 || bytes.Equal(out, []byte("[]")) {
		return nil, nil, nil
	}

	var rows []scheduledTaskRow
	if out[0] == '{' {
		// Single object — wrap in array for unified decode.
		var row scheduledTaskRow
		if err := json.Unmarshal(out, &row); err != nil {
			return nil, nil, &StartupExposureProbeError{
				Code:    StartupExposureErrTaskSchedulerQuery,
				Summary: "Task Scheduler JSON decode failed",
			}
		}
		rows = []scheduledTaskRow{row}
	} else {
		if err := json.Unmarshal(out, &rows); err != nil {
			return nil, nil, &StartupExposureProbeError{
				Code:    StartupExposureErrTaskSchedulerQuery,
				Summary: "Task Scheduler JSON decode failed",
			}
		}
	}

	apps := make([]StartupApp, 0, len(rows))
	var redactions []StartupExposureProbeError
	for _, row := range rows {
		name := strings.TrimSpace(row.TaskName)
		if name == "" {
			continue
		}
		bucket := bucketTaskPath(row.TaskPath)
		// Codex 019e83a8 iter-1 P1#2 absorb: task name itself is
		// operator-controllable and may carry path/command fragments;
		// redact and emit a typed probe error rather than leaking.
		if shouldRedactName(name) {
			redactions = append(redactions, StartupExposureProbeError{
				Code:    StartupExposureErrNameValueRedacted,
				Source:  bucket,
				Summary: "Scheduled task name redacted (path or command fragment)",
			})
			continue
		}
		apps = append(apps, StartupApp{
			Name:        name,
			Location:    bucket,
			Enabled:     !strings.EqualFold(row.State, "Disabled"),
			ProbeOrigin: StartupProbeOriginScheduledTask,
		})
	}
	return apps, redactions, nil
}


// probeRdpEnabled reads
// HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\
// fDenyTSConnections. RdpEnabled is the INVERSE: fDenyTSConnections=0
// means RDP is enabled.
//
// Codex 019e8387 plan iter-1 P1 #3 absorb: this is the authoritative
// listener state. TermService running is NOT equivalent — the service
// can be running while connections are administratively denied.
func probeRdpEnabled() (bool, *StartupExposureProbeError) {
	key, err := registry.OpenKey(
		registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Control\Terminal Server`,
		registry.QUERY_VALUE|registry.WOW64_64KEY,
	)
	if err != nil {
		return false, &StartupExposureProbeError{
			Code:    StartupExposureErrRdpProbeFailed,
			Summary: "Terminal Server key unreadable",
		}
	}
	defer key.Close()
	v, _, err := key.GetIntegerValue("fDenyTSConnections")
	if err != nil {
		return false, &StartupExposureProbeError{
			Code:    StartupExposureErrRdpProbeFailed,
			Summary: "fDenyTSConnections value unreadable",
		}
	}
	// fDenyTSConnections = 0 → connections allowed → RdpEnabled = true.
	return v == 0, nil
}

// probeFirewallEventLog reads a registry signal indicating whether
// Windows Firewall logging is enabled. We probe the
// HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\
// FirewallPolicy\StandardProfile\Logging\LogDroppedPackets value (a
// canonical bool flag). Codex 019e8387 plan iter-1 absorb: this is a
// SCALAR boolean — no per-rule enumeration, no log path, no recent
// events.
func probeFirewallEventLog() (bool, *StartupExposureProbeError) {
	key, err := registry.OpenKey(
		registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile\Logging`,
		registry.QUERY_VALUE|registry.WOW64_64KEY,
	)
	if err != nil {
		// Key not present in some Windows editions; treat as
		// "logging not configured" rather than a probe error.
		if err == registry.ErrNotExist {
			return false, nil
		}
		return false, &StartupExposureProbeError{
			Code:    StartupExposureErrFirewallProbeFailed,
			Summary: "Firewall logging key unreadable",
		}
	}
	defer key.Close()
	v, _, err := key.GetIntegerValue("LogDroppedPackets")
	if err != nil {
		if err == registry.ErrNotExist {
			return false, nil
		}
		return false, &StartupExposureProbeError{
			Code:    StartupExposureErrFirewallProbeFailed,
			Summary: "LogDroppedPackets value unreadable",
		}
	}
	return v != 0, nil
}
