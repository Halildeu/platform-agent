//go:build windows

package inventory

import (
	"bytes"
	"context"
	"encoding/json"
	"os/exec"
	"strings"
	"time"
)

type securityNetworkProbeAggregate struct {
	events      []rawSecurityNetworkEvent
	probeErrors []SecurityNetworkProbeError
}

func ProbeSecurityNetwork(ctx context.Context, now func() time.Time) SecurityNetworkResult {
	if now == nil {
		now = time.Now
	}
	startedAt := now()
	probeCtx, cancel := context.WithTimeout(ctx, SecurityNetworkProbeTimeout)
	defer cancel()

	done := make(chan securityNetworkProbeAggregate, 1)
	go func() {
		done <- runSecurityNetworkProbeBlocking(probeCtx)
	}()

	select {
	case agg := <-done:
		return orchestrateSecurityNetworkProbe(
			probeCtx, now, true, agg.events, agg.probeErrors, startedAt)
	case <-probeCtx.Done():
		return orchestrateSecurityNetworkProbe(
			probeCtx,
			now,
			true,
			nil,
			[]SecurityNetworkProbeError{{
				Code:    SecurityNetworkErrProbeTimeout,
				Summary: securityNetworkSummaryPtr("Security/network probe deadline exceeded"),
			}},
			startedAt,
		)
	}
}

func runSecurityNetworkProbeBlocking(ctx context.Context) securityNetworkProbeAggregate {
	rows, errCode := queryWindowsFirewallBlockEvents(ctx)
	if errCode != "" {
		return securityNetworkProbeAggregate{
			probeErrors: []SecurityNetworkProbeError{{
				Code:    errCode,
				Summary: securityNetworkSummaryPtr("Windows firewall block event query failed"),
			}},
		}
	}
	return securityNetworkProbeAggregate{events: rows}
}

type windowsFirewallBlockEventRow struct {
	ProcessPath        string `json:"processPath"`
	DestinationAddress string `json:"destinationAddress"`
	DestinationPort    string `json:"destinationPort"`
	Protocol           string `json:"protocol"`
	FilterID           string `json:"filterId"`
	ObservedAt         string `json:"observedAt"`
}

func queryWindowsFirewallBlockEvents(ctx context.Context) ([]rawSecurityNetworkEvent, string) {
	const psScript = `$ErrorActionPreference = 'Stop'
$start = (Get-Date).AddHours(-24)
$eventIds = @(5152,5157)
try {
  try {
    $events = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=$eventIds; StartTime=$start} -MaxEvents 50 -ErrorAction Stop
  } catch {
    if ($_.Exception.Message -like '*No events were found*') {
      $events = @()
    } else {
      throw
    }
  }
  $rows = @()
  foreach ($event in $events) {
    try {
      [xml]$xml = $event.ToXml()
      $data = @{}
      foreach ($node in $xml.Event.EventData.Data) {
        if ($null -ne $node.Name -and $node.Name -ne '') {
          $data[$node.Name] = [string]$node.'#text'
        }
      }
      $process = $data['Application']
      if ([string]::IsNullOrWhiteSpace($process)) { $process = $data['ProcessName'] }
      $dest = $data['DestAddress']
      if ([string]::IsNullOrWhiteSpace($dest)) { $dest = $data['DestinationAddress'] }
      $port = $data['DestPort']
      if ([string]::IsNullOrWhiteSpace($port)) { $port = $data['DestinationPort'] }
      $protocol = $data['Protocol']
      $filter = $data['FilterRTID']
      if ([string]::IsNullOrWhiteSpace($filter)) { $filter = $data['FilterId'] }
      if ([string]::IsNullOrWhiteSpace($filter)) { $filter = $data['FilterRunTimeId'] }
      $rows += [PSCustomObject]@{
        processPath = $process
        destinationAddress = $dest
        destinationPort = $port
        protocol = $protocol
        filterId = $filter
        observedAt = $event.TimeCreated.ToUniversalTime().ToString('o')
      }
    } catch {
      continue
    }
  }
  ConvertTo-Json -Compress -Depth 4 -InputObject @($rows)
} catch [System.UnauthorizedAccessException] {
  Write-Error 'ACCESS_DENIED'
  exit 13
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
		if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 13 {
			return nil, SecurityNetworkErrAccessDenied
		}
		if strings.Contains(stderr.String(), "ACCESS_DENIED") {
			return nil, SecurityNetworkErrAccessDenied
		}
		return nil, SecurityNetworkErrEventLogUnavailable
	}

	out := bytes.TrimSpace(stdout.Bytes())
	if len(out) == 0 || bytes.Equal(out, []byte("[]")) {
		return nil, ""
	}

	var rows []windowsFirewallBlockEventRow
	if out[0] == '{' {
		var row windowsFirewallBlockEventRow
		if err := json.Unmarshal(out, &row); err != nil {
			return nil, SecurityNetworkErrProbeFailed
		}
		rows = []windowsFirewallBlockEventRow{row}
	} else if err := json.Unmarshal(out, &rows); err != nil {
		return nil, SecurityNetworkErrProbeFailed
	}

	events := make([]rawSecurityNetworkEvent, 0, len(rows))
	for _, row := range rows {
		observedAt, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(row.ObservedAt))
		if err != nil {
			continue
		}
		events = append(events, rawSecurityNetworkEvent{
			ProcessPath:        row.ProcessPath,
			DestinationAddress: row.DestinationAddress,
			DestinationPort:    row.DestinationPort,
			Protocol:           row.Protocol,
			FilterID:           row.FilterID,
			ObservedAt:         observedAt,
		})
	}
	return events, ""
}
