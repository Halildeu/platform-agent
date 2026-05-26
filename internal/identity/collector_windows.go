//go:build windows

package identity

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"strings"
	"time"
)

type computerSystemProbe struct {
	Hostname     string `json:"Hostname"`
	Domain       string `json:"Domain"`
	PartOfDomain bool   `json:"PartOfDomain"`
	Workgroup    string `json:"Workgroup"`
	OSVersion    string `json:"OSVersion"`
	OSBuild      string `json:"OSBuild"`
}

func collect(now time.Time) Inventory {
	inv := Inventory{
		AzureAdJoined:   "UNKNOWN",
		DomainJoined:    "UNKNOWN",
		WorkplaceJoined: "UNKNOWN",
		CollectedAt:     now,
	}
	if probe, err := probeComputerSystem(); err == nil {
		inv.Hostname = probe.Hostname
		inv.Domain = probe.Domain
		inv.PartOfDomain = probe.PartOfDomain
		inv.Workgroup = probe.Workgroup
		inv.OSVersion = probe.OSVersion
		inv.OSBuild = probe.OSBuild
	} else {
		inv.ProbeErrors = append(inv.ProbeErrors, "Win32_ComputerSystem probe failed")
	}
	if dsreg, err := probeDSReg(); err == nil {
		inv.AzureAdJoined = NormalizeJoinValue(dsreg["AzureAdJoined"])
		inv.DomainJoined = NormalizeJoinValue(dsreg["DomainJoined"])
		inv.WorkplaceJoined = NormalizeJoinValue(dsreg["WorkplaceJoined"])
		inv.TenantIDHash = HashIdentifier(dsreg["TenantId"])
		inv.DeviceIDHash = HashIdentifier(dsreg["DeviceId"])
		inv.DeviceNameHash = HashIdentifier(dsreg["DeviceName"])
	} else {
		inv.ProbeErrors = append(inv.ProbeErrors, "dsregcmd status probe failed")
	}
	inv.DomainReachable, inv.DomainProbe = probeDomainReachability(inv.Domain, inv.PartOfDomain)
	inv.LoggedIn = currentLoggedInIdentity()
	inv.Classification = Classify(JoinSignals{
		PartOfDomain:    inv.PartOfDomain,
		Domain:          inv.Domain,
		Workgroup:       inv.Workgroup,
		AzureAdJoined:   inv.AzureAdJoined,
		DomainJoined:    inv.DomainJoined,
		WorkplaceJoined: inv.WorkplaceJoined,
	})
	return inv
}

func probeComputerSystem() (computerSystemProbe, error) {
	const script = `$ErrorActionPreference = "Stop"
$cs = Get-CimInstance Win32_ComputerSystem
$os = Get-CimInstance Win32_OperatingSystem
[PSCustomObject]@{
  Hostname = $env:COMPUTERNAME
  Domain = $cs.Domain
  PartOfDomain = $cs.PartOfDomain
  Workgroup = $cs.Workgroup
  OSVersion = $os.Version
  OSBuild = $os.BuildNumber
} | ConvertTo-Json -Compress`
	out, err := runCommand(5*time.Second, "powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script)
	if err != nil {
		return computerSystemProbe{}, err
	}
	var probe computerSystemProbe
	if err := json.Unmarshal([]byte(out), &probe); err != nil {
		return computerSystemProbe{}, fmt.Errorf("parse computer system JSON: %w", err)
	}
	return probe, nil
}

func probeDSReg() (map[string]string, error) {
	out, err := runCommand(5*time.Second, "cmd", "/c", "dsregcmd /status")
	if err != nil {
		return nil, err
	}
	fields := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		switch key {
		case "AzureAdJoined", "DomainJoined", "WorkplaceJoined", "TenantId", "DeviceId", "DeviceName":
			fields[key] = strings.TrimSpace(value)
		}
	}
	return fields, nil
}

func probeDomainReachability(domain string, partOfDomain bool) (*bool, string) {
	domain = strings.TrimSpace(domain)
	if !partOfDomain || domain == "" || strings.EqualFold(domain, "WORKGROUP") {
		return nil, "SKIPPED_NOT_DOMAIN_JOINED"
	}
	if _, err := runCommand(5*time.Second, "cmd", "/c", "nltest /dsgetdc:"+domain); err != nil {
		reachable := false
		return &reachable, "FAIL"
	}
	reachable := true
	return &reachable, "PASS"
}

func currentLoggedInIdentity() LoggedInIdentity {
	current, err := user.Current()
	if err != nil {
		return LoggedInIdentity{}
	}
	upn := ""
	if strings.Contains(current.Username, "@") {
		upn = current.Username
	} else if dnsDomain := strings.TrimSpace(os.Getenv("USERDNSDOMAIN")); dnsDomain != "" {
		account, _ := splitAccount(current.Username)
		if account != "" {
			upn = account + "@" + dnsDomain
		}
	}
	return BuildLoggedInIdentity(current.Username, upn, current.Uid)
}

func runCommand(timeout time.Duration, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		return "", ctx.Err()
	}
	if err != nil {
		return "", fmt.Errorf("%s failed: %w", name, err)
	}
	return string(out), nil
}
