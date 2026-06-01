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
func runStartupExposureProbeBlocking(ctx context.Context) startupExposureAggregate {
	var apps []StartupApp
	var probeErrors []StartupExposureProbeError

	// Registry enumerations.
	for _, spec := range registryStartupSpecs() {
		entries, err := enumerateRegistryRun(spec.root, spec.path, spec.location)
		if err != nil {
			probeErrors = append(probeErrors, StartupExposureProbeError{
				Code:    StartupExposureErrRegistryQueryFailed,
				Source:  spec.location,
				Summary: "Registry enumeration failed",
			})
			continue
		}
		apps = append(apps, entries...)
	}

	// Filesystem startup folders.
	for _, spec := range filesystemStartupSpecs() {
		entries, err := enumerateStartupFolder(spec.envExpand, spec.location)
		if err != nil {
			probeErrors = append(probeErrors, StartupExposureProbeError{
				Code:    StartupExposureErrStartupFolderUnreadable,
				Source:  spec.location,
				Summary: "Startup folder enumeration failed",
			})
			continue
		}
		apps = append(apps, entries...)
	}

	// Task Scheduler enumeration.
	taskApps, taskErr := enumerateScheduledTasks(ctx)
	if taskErr != nil {
		probeErrors = append(probeErrors, *taskErr)
	}
	apps = append(apps, taskApps...)

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
// separate enabled flag.
func enumerateRegistryRun(root registry.Key, path string, location StartupAppLocation) ([]StartupApp, error) {
	key, err := registry.OpenKey(root, path, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		// "Key does not exist" is NOT an error — it means no autorun
		// entries in that slot. Distinguish from genuine read failures.
		if err == registry.ErrNotExist {
			return nil, nil
		}
		return nil, err
	}
	defer key.Close()

	names, err := key.ReadValueNames(-1)
	if err != nil {
		return nil, err
	}

	apps := make([]StartupApp, 0, len(names))
	for _, name := range names {
		// HARD REDACTION: only the value NAME is captured. The data
		// (executable path / command line) is NEVER read.
		apps = append(apps, StartupApp{
			Name:        name,
			Location:    location,
			Enabled:     true,
			ProbeOrigin: StartupProbeOriginRegistry,
		})
	}
	return apps, nil
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
// NEVER surfaced.
func enumerateStartupFolder(envExpand func() string, location StartupAppLocation) ([]StartupApp, error) {
	dir := envExpand()
	if dir == "" {
		// Env var not set; treat as empty (NOT an error).
		return nil, nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			// Folder simply does not exist on this host; treat as empty.
			return nil, nil
		}
		return nil, err
	}
	apps := make([]StartupApp, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		ext := filepath.Ext(name)
		base := strings.TrimSuffix(name, ext)
		// "desktop.ini" is a Windows metadata file — exclude.
		if strings.EqualFold(name, "desktop.ini") {
			continue
		}
		apps = append(apps, StartupApp{
			Name:        base,
			Location:    location,
			Enabled:     true,
			ProbeOrigin: StartupProbeOriginRegistry,
		})
	}
	return apps, nil
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
// returns ONLY the bounded fields above. Codex 019e8387 plan absorb:
// scheduled task enumeration uses a fixed argv (no payload-supplied
// interpolation) and the script body never calls a mutating cmdlet.
//
// The script:
//   1. Get-ScheduledTask returns all tasks (read-only).
//   2. Where-Object filters to non-Disabled state.
//   3. ForEach-Object projects to the 3-field shape.
//   4. ConvertTo-Json -Compress for compact transport.
//
// On any failure (powershell.exe missing, COM unavailable, JSON
// decode), the function returns nil + a probe error.
func enumerateScheduledTasks(ctx context.Context) ([]StartupApp, *StartupExposureProbeError) {
	const psScript = `$ErrorActionPreference = 'Stop'
try {
  $tasks = Get-ScheduledTask | Where-Object { $_.State -ne 'Disabled' } | ForEach-Object {
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
		return nil, &StartupExposureProbeError{
			Code:    StartupExposureErrTaskSchedulerUnavail,
			Summary: "Task Scheduler enumeration failed",
		}
	}

	// ConvertTo-Json yields either a JSON object (1 task) or array (n
	// tasks) or our literal "[]" string when none matched. Handle all.
	out := bytes.TrimSpace(stdout.Bytes())
	if len(out) == 0 || bytes.Equal(out, []byte("[]")) {
		return nil, nil
	}

	var rows []scheduledTaskRow
	if out[0] == '{' {
		// Single object — wrap in array for unified decode.
		var row scheduledTaskRow
		if err := json.Unmarshal(out, &row); err != nil {
			return nil, &StartupExposureProbeError{
				Code:    StartupExposureErrTaskSchedulerQuery,
				Summary: "Task Scheduler JSON decode failed",
			}
		}
		rows = []scheduledTaskRow{row}
	} else {
		if err := json.Unmarshal(out, &rows); err != nil {
			return nil, &StartupExposureProbeError{
				Code:    StartupExposureErrTaskSchedulerQuery,
				Summary: "Task Scheduler JSON decode failed",
			}
		}
	}

	apps := make([]StartupApp, 0, len(rows))
	for _, row := range rows {
		name := strings.TrimSpace(row.TaskName)
		if name == "" {
			continue
		}
		// HARD REDACTION: only TaskName + bucketed TaskPath are kept.
		apps = append(apps, StartupApp{
			Name:        name,
			Location:    bucketTaskPath(row.TaskPath),
			Enabled:     !strings.EqualFold(row.State, "Disabled"),
			ProbeOrigin: StartupProbeOriginScheduledTask,
		})
	}
	return apps, nil
}

// bucketTaskPath maps a Task Scheduler folder path to one of three
// buckets. Codex 019e8387 plan iter-1 P1 #1 absorb: the wire MUST carry
// only the bucket, never the full folder path.
//
//   - "\" or "" → ROOT (admin-installed or schtasks-created)
//   - starts with "\Microsoft\Windows" → MICROSOFT_WINDOWS (system)
//   - anything else under "\" → CUSTOM (operator-installed)
func bucketTaskPath(taskPath string) StartupAppLocation {
	p := strings.TrimSpace(taskPath)
	if p == "" || p == `\` {
		return StartupLocationTaskRoot
	}
	// PowerShell Get-ScheduledTask TaskPath comes back as "\Foo\Bar\"
	// with leading and trailing backslashes. Normalize.
	p = strings.TrimSuffix(p, `\`)
	if p == "" || p == `\` {
		return StartupLocationTaskRoot
	}
	upper := strings.ToUpper(p)
	if strings.HasPrefix(upper, `\MICROSOFT\WINDOWS`) {
		return StartupLocationTaskMicrosoft
	}
	return StartupLocationTaskCustom
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
