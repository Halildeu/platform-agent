package commands

import (
	"context"
	"testing"
	"time"

	"platform-agent/internal/inventory"
	"platform-agent/internal/protocol"
	"platform-agent/internal/winget"
)

// installSoftwareTestPayload builds the canonical INSTALL_SOFTWARE
// payload shape used by the AG-027 executor tests. Mirrors the
// future BE-022 issuer wire so the executor unmarshalling path is
// exercised end-to-end.
func installSoftwareTestPayload() map[string]interface{} {
	return map[string]interface{}{
		"commandResultId":   "00000000-0000-0000-0000-000000000001",
		"idempotencyKey":    "00000000-0000-0000-0000-000000000002",
		"catalogItemId":     "00000000-0000-0000-0000-000000000003",
		"catalogItemKey":    "7zip.7zip",
		"catalogRowVersion": 1,
		"provider":          "WINGET",
		"packageId":         "7zip.7zip",
		"argsPolicyPreset":  winget.ArgsPresetDefault,
		"versionPredicate": map[string]interface{}{
			"type": "LATEST",
		},
		"detectionRule": map[string]interface{}{
			"type":      "WINGET_PACKAGE",
			"packageId": "7zip.7zip",
		},
	}
}

// installSoftwareSeam overrides the package-private installWinGetFn
// for the duration of a test and restores the production wire on
// cleanup. Mirrors the AG-026A detectSourceEgress seam test pattern.
func installSoftwareSeam(t *testing.T, stub func(ctx context.Context, req winget.InstallRequest) winget.InstallResult) {
	t.Helper()
	prev := installWinGetFn
	installWinGetFn = stub
	t.Cleanup(func() { installWinGetFn = prev })
}

// snapshotFromDetails extracts the inventory.Snapshot the executor
// embedded in CommandResult.Details["inventory"]. The executor stores
// the struct value (not the pointer); we type-assert so the AG-025H
// wire-shape tests can pin Snapshot.Software nilness.
func snapshotFromDetails(t *testing.T, details map[string]interface{}) inventory.Snapshot {
	t.Helper()
	raw, ok := details["inventory"]
	if !ok {
		t.Fatalf("inventory detail missing: %#v", details)
	}
	snap, ok := raw.(inventory.Snapshot)
	if !ok {
		t.Fatalf("inventory detail type = %T, want inventory.Snapshot", raw)
	}
	return snap
}

func TestLocalExecutorCollectInventory(t *testing.T) {
	executor := NewLocalExecutor([]protocol.CommandType{protocol.CommandCollectInventory}, "test")
	command := protocol.AgentCommand{
		CommandID:      "cmd-1",
		ClaimID:        "claim-1",
		AttemptNumber:  1,
		Type:           protocol.CommandCollectInventory,
		ClaimExpiresAt: time.Now().Add(time.Minute),
	}

	result := executor.Execute(context.Background(), command)

	if result.Status != protocol.CommandStatusSucceeded {
		t.Fatalf("status = %s, want %s", result.Status, protocol.CommandStatusSucceeded)
	}
	if result.Details["inventory"] == nil {
		t.Fatalf("inventory detail missing: %#v", result.Details)
	}
}

func TestLocalExecutorUnsupportedCommandReturnsUnsupported(t *testing.T) {
	executor := NewLocalExecutor([]protocol.CommandType{protocol.CommandCollectInventory}, "test")
	command := protocol.AgentCommand{
		CommandID:      "cmd-1",
		ClaimID:        "claim-1",
		AttemptNumber:  1,
		Type:           protocol.CommandDisableLocalUser,
		Reason:         "ticket",
		ClaimExpiresAt: time.Now().Add(time.Minute),
	}

	result := executor.Execute(context.Background(), command)

	if result.Status != protocol.CommandStatusUnsupported {
		t.Fatalf("status = %s, want %s", result.Status, protocol.CommandStatusUnsupported)
	}
}

// AG-025H — boolPayload mapping + COLLECT_INVENTORY wire shape (Codex
// 019e6aef post-impl iter-1 P2 / iter-2 absorb). When includeSoftware
// is absent / false / non-truthy, Snapshot.Software must stay nil
// (lightweight contract). When truthy, the executor wires the explicit
// CollectWithOptions(IncludeSoftwareApps=true) path. The boolean
// normalization must accept the documented payload typing drift
// (bool true, "true" string, "1" string, 1 int, 1.0 float64).
func TestLocalExecutorCollectInventoryDefaultOmitsSoftware(t *testing.T) {
	executor := NewLocalExecutor([]protocol.CommandType{protocol.CommandCollectInventory}, "test")
	command := protocol.AgentCommand{
		CommandID:      "cmd-default",
		ClaimID:        "claim-default",
		AttemptNumber:  1,
		Type:           protocol.CommandCollectInventory,
		ClaimExpiresAt: time.Now().Add(time.Minute),
	}

	result := executor.Execute(context.Background(), command)

	if result.Status != protocol.CommandStatusSucceeded {
		t.Fatalf("status = %s", result.Status)
	}
	snap := snapshotFromDetails(t, result.Details)
	if snap.Software != nil {
		t.Fatalf("AG-025H: default payload must keep Snapshot.Software nil (got %+v)", snap.Software)
	}
}

func TestLocalExecutorBoolPayloadAccepts(t *testing.T) {
	cases := []struct {
		name    string
		payload map[string]interface{}
		wantOn  bool
	}{
		{"nil-payload", nil, false},
		{"missing-key", map[string]interface{}{"unrelated": true}, false},
		{"bool-false", map[string]interface{}{"includeSoftware": false}, false},
		{"bool-true", map[string]interface{}{"includeSoftware": true}, true},
		{"string-true", map[string]interface{}{"includeSoftware": "true"}, true},
		{"string-True", map[string]interface{}{"includeSoftware": "True"}, true},
		{"string-TRUE", map[string]interface{}{"includeSoftware": "TRUE"}, true},
		{"string-1", map[string]interface{}{"includeSoftware": "1"}, true},
		{"string-false", map[string]interface{}{"includeSoftware": "false"}, false},
		{"string-0", map[string]interface{}{"includeSoftware": "0"}, false},
		{"int-1", map[string]interface{}{"includeSoftware": 1}, true},
		{"int-0", map[string]interface{}{"includeSoftware": 0}, false},
		{"float64-1", map[string]interface{}{"includeSoftware": float64(1)}, true},
		{"float64-0", map[string]interface{}{"includeSoftware": float64(0)}, false},
		{"unknown-type", map[string]interface{}{"includeSoftware": []string{"yes"}}, false},
	}
	for _, tc := range cases {
		got := boolPayload(tc.payload, "includeSoftware")
		if got != tc.wantOn {
			t.Errorf("%s: boolPayload = %v, want %v", tc.name, got, tc.wantOn)
		}
	}
}

// AG-026A — COLLECT_INVENTORY default omits the WinGet source/egress
// preflight. The boolean payload bit `includeWinGetEgress` opts in;
// when absent or false the wire payload must NOT carry the wingetEgress
// field and the preflight runner must NOT be invoked. Mirrors the
// AG-025H lightweight-default contract for includeSoftware.
func TestLocalExecutorCollectInventoryDefaultOmitsWinGetEgress(t *testing.T) {
	executor := NewLocalExecutor([]protocol.CommandType{protocol.CommandCollectInventory}, "test")
	command := protocol.AgentCommand{
		CommandID:      "cmd-egress-default",
		ClaimID:        "claim-egress-default",
		AttemptNumber:  1,
		Type:           protocol.CommandCollectInventory,
		ClaimExpiresAt: time.Now().Add(time.Minute),
	}

	result := executor.Execute(context.Background(), command)

	if result.Status != protocol.CommandStatusSucceeded {
		t.Fatalf("status = %s", result.Status)
	}
	snap := snapshotFromDetails(t, result.Details)
	if snap.WinGetEgress != nil {
		t.Fatalf("AG-026A: default payload must keep Snapshot.WinGetEgress nil (got %+v)", snap.WinGetEgress)
	}
}

// AG-026A — boolPayload mapping for the new includeWinGetEgress key.
// The function reuses the same logic as includeSoftware so the cases
// are intentionally a subset of the includeSoftware matrix; the focus
// is "the key name is wired and the default is safe".
func TestLocalExecutorBoolPayloadIncludeWinGetEgress(t *testing.T) {
	cases := []struct {
		name    string
		payload map[string]interface{}
		wantOn  bool
	}{
		{"nil-payload", nil, false},
		{"missing-key", map[string]interface{}{"includeSoftware": true}, false},
		{"bool-true", map[string]interface{}{"includeWinGetEgress": true}, true},
		{"bool-false", map[string]interface{}{"includeWinGetEgress": false}, false},
		{"string-true", map[string]interface{}{"includeWinGetEgress": "true"}, true},
		{"string-1", map[string]interface{}{"includeWinGetEgress": "1"}, true},
		{"int-0", map[string]interface{}{"includeWinGetEgress": 0}, false},
	}
	for _, tc := range cases {
		got := boolPayload(tc.payload, "includeWinGetEgress")
		if got != tc.wantOn {
			t.Errorf("%s: boolPayload(includeWinGetEgress) = %v, want %v", tc.name, got, tc.wantOn)
		}
	}
}

// AG-035 — boolPayload mapping for the new includeHardware key.
// Mirrors the includeSoftware / includeWinGetEgress matrix so the
// "lightweight default is safe" contract is enforced uniformly for
// every COLLECT_INVENTORY opt-in bit. A hardware probe accidentally
// firing for every heartbeat would be the cost-default we are guarding
// against, so the "missing key / non-boolean / unknown shape ⇒ false"
// branch is the load-bearing one here.
func TestLocalExecutorBoolPayloadIncludeHardware(t *testing.T) {
	cases := []struct {
		name    string
		payload map[string]interface{}
		wantOn  bool
	}{
		{"nil-payload", nil, false},
		{"missing-key", map[string]interface{}{"includeSoftware": true}, false},
		{"bool-true", map[string]interface{}{"includeHardware": true}, true},
		{"bool-false", map[string]interface{}{"includeHardware": false}, false},
		{"string-true", map[string]interface{}{"includeHardware": "true"}, true},
		{"string-1", map[string]interface{}{"includeHardware": "1"}, true},
		{"string-True", map[string]interface{}{"includeHardware": "True"}, true},
		{"string-false", map[string]interface{}{"includeHardware": "false"}, false},
		{"string-0", map[string]interface{}{"includeHardware": "0"}, false},
		{"int-1", map[string]interface{}{"includeHardware": 1}, true},
		{"int-0", map[string]interface{}{"includeHardware": 0}, false},
		{"float64-1", map[string]interface{}{"includeHardware": float64(1)}, true},
		{"float64-0", map[string]interface{}{"includeHardware": float64(0)}, false},
		{"unknown-type", map[string]interface{}{"includeHardware": []string{"yes"}}, false},
	}
	for _, tc := range cases {
		got := boolPayload(tc.payload, "includeHardware")
		if got != tc.wantOn {
			t.Errorf("%s: boolPayload(includeHardware) = %v, want %v", tc.name, got, tc.wantOn)
		}
	}
}

// AG-030 — boolPayload mapping for the new includePendingReboot
// key. Mirrors the includeSoftware / includeWinGetEgress /
// includeHardware matrix so the "lightweight default is safe"
// contract is enforced uniformly for every COLLECT_INVENTORY
// opt-in bit. The pending-reboot probe accidentally firing for
// every heartbeat would defeat the AG-025H lightweight contract,
// so the "missing key / non-boolean / unknown shape ⇒ false"
// branch is the load-bearing one here.
func TestLocalExecutorBoolPayloadIncludePendingReboot(t *testing.T) {
	cases := []struct {
		name    string
		payload map[string]interface{}
		wantOn  bool
	}{
		{"nil-payload", nil, false},
		{"missing-key", map[string]interface{}{"includeSoftware": true}, false},
		{"bool-true", map[string]interface{}{"includePendingReboot": true}, true},
		{"bool-false", map[string]interface{}{"includePendingReboot": false}, false},
		{"string-true", map[string]interface{}{"includePendingReboot": "true"}, true},
		{"string-1", map[string]interface{}{"includePendingReboot": "1"}, true},
		{"string-True", map[string]interface{}{"includePendingReboot": "True"}, true},
		{"string-false", map[string]interface{}{"includePendingReboot": "false"}, false},
		{"string-0", map[string]interface{}{"includePendingReboot": "0"}, false},
		{"int-1", map[string]interface{}{"includePendingReboot": 1}, true},
		{"int-0", map[string]interface{}{"includePendingReboot": 0}, false},
		{"float64-1", map[string]interface{}{"includePendingReboot": float64(1)}, true},
		{"float64-0", map[string]interface{}{"includePendingReboot": float64(0)}, false},
		{"unknown-type", map[string]interface{}{"includePendingReboot": []string{"yes"}}, false},
	}
	for _, tc := range cases {
		got := boolPayload(tc.payload, "includePendingReboot")
		if got != tc.wantOn {
			t.Errorf("%s: boolPayload(includePendingReboot) = %v, want %v", tc.name, got, tc.wantOn)
		}
	}
}

func TestLocalExecutorBoolPayloadIncludeSecurityPosture(t *testing.T) {
	cases := []struct {
		name    string
		payload map[string]interface{}
		wantOn  bool
	}{
		{"nil-payload", nil, false},
		{"missing-key", map[string]interface{}{"includeSoftware": true}, false},
		{"bool-true", map[string]interface{}{"includeSecurityPosture": true}, true},
		{"bool-false", map[string]interface{}{"includeSecurityPosture": false}, false},
		{"string-true", map[string]interface{}{"includeSecurityPosture": "true"}, true},
		{"string-1", map[string]interface{}{"includeSecurityPosture": "1"}, true},
		{"string-True", map[string]interface{}{"includeSecurityPosture": "True"}, true},
		{"string-false", map[string]interface{}{"includeSecurityPosture": "false"}, false},
		{"string-0", map[string]interface{}{"includeSecurityPosture": "0"}, false},
		{"int-1", map[string]interface{}{"includeSecurityPosture": 1}, true},
		{"int-0", map[string]interface{}{"includeSecurityPosture": 0}, false},
		{"float64-1", map[string]interface{}{"includeSecurityPosture": float64(1)}, true},
		{"float64-0", map[string]interface{}{"includeSecurityPosture": float64(0)}, false},
		{"unknown-type", map[string]interface{}{"includeSecurityPosture": []string{"yes"}}, false},
	}
	for _, tc := range cases {
		got := boolPayload(tc.payload, "includeSecurityPosture")
		if got != tc.wantOn {
			t.Errorf("%s: boolPayload(includeSecurityPosture) = %v, want %v", tc.name, got, tc.wantOn)
		}
	}
}

func TestLocalExecutorBoolPayloadIncludeLocalAdminGroup(t *testing.T) {
	cases := []struct {
		name    string
		payload map[string]interface{}
		wantOn  bool
	}{
		{"nil-payload", nil, false},
		{"missing-key", map[string]interface{}{"includeSoftware": true}, false},
		{"bool-true", map[string]interface{}{"includeLocalAdminGroup": true}, true},
		{"bool-false", map[string]interface{}{"includeLocalAdminGroup": false}, false},
		{"string-true", map[string]interface{}{"includeLocalAdminGroup": "true"}, true},
		{"string-1", map[string]interface{}{"includeLocalAdminGroup": "1"}, true},
		{"string-True", map[string]interface{}{"includeLocalAdminGroup": "True"}, true},
		{"string-false", map[string]interface{}{"includeLocalAdminGroup": "false"}, false},
		{"string-0", map[string]interface{}{"includeLocalAdminGroup": "0"}, false},
		{"int-1", map[string]interface{}{"includeLocalAdminGroup": 1}, true},
		{"int-0", map[string]interface{}{"includeLocalAdminGroup": 0}, false},
		{"float64-1", map[string]interface{}{"includeLocalAdminGroup": float64(1)}, true},
		{"float64-0", map[string]interface{}{"includeLocalAdminGroup": float64(0)}, false},
		{"unknown-type", map[string]interface{}{"includeLocalAdminGroup": []string{"yes"}}, false},
	}
	for _, tc := range cases {
		got := boolPayload(tc.payload, "includeLocalAdminGroup")
		if got != tc.wantOn {
			t.Errorf("%s: boolPayload(includeLocalAdminGroup) = %v, want %v", tc.name, got, tc.wantOn)
		}
	}
}

func TestLocalExecutorBoolPayloadIncludeDeviceHealth(t *testing.T) {
	cases := []struct {
		name    string
		payload map[string]interface{}
		wantOn  bool
	}{
		{"nil-payload", nil, false},
		{"missing-key", map[string]interface{}{"includeSoftware": true}, false},
		{"bool-true", map[string]interface{}{"includeDeviceHealth": true}, true},
		{"bool-false", map[string]interface{}{"includeDeviceHealth": false}, false},
		{"string-true", map[string]interface{}{"includeDeviceHealth": "true"}, true},
		{"string-1", map[string]interface{}{"includeDeviceHealth": "1"}, true},
		{"string-True", map[string]interface{}{"includeDeviceHealth": "True"}, true},
		{"string-false", map[string]interface{}{"includeDeviceHealth": "false"}, false},
		{"string-0", map[string]interface{}{"includeDeviceHealth": "0"}, false},
		{"int-1", map[string]interface{}{"includeDeviceHealth": 1}, true},
		{"int-0", map[string]interface{}{"includeDeviceHealth": 0}, false},
		{"float64-1", map[string]interface{}{"includeDeviceHealth": float64(1)}, true},
		{"float64-0", map[string]interface{}{"includeDeviceHealth": float64(0)}, false},
		{"unknown-type", map[string]interface{}{"includeDeviceHealth": []string{"yes"}}, false},
	}
	for _, tc := range cases {
		got := boolPayload(tc.payload, "includeDeviceHealth")
		if got != tc.wantOn {
			t.Errorf("%s: boolPayload(includeDeviceHealth) = %v, want %v", tc.name, got, tc.wantOn)
		}
	}
}

// AG-036 — boolPayload mapping for the includeOutdatedSoftware key.
func TestLocalExecutorBoolPayloadIncludeOutdatedSoftware(t *testing.T) {
	cases := []struct {
		name    string
		payload map[string]interface{}
		wantOn  bool
	}{
		{"nil-payload", nil, false},
		{"missing-key", map[string]interface{}{"includeSoftware": true}, false},
		{"bool-true", map[string]interface{}{"includeOutdatedSoftware": true}, true},
		{"bool-false", map[string]interface{}{"includeOutdatedSoftware": false}, false},
		{"string-true", map[string]interface{}{"includeOutdatedSoftware": "true"}, true},
		{"string-1", map[string]interface{}{"includeOutdatedSoftware": "1"}, true},
		{"string-True", map[string]interface{}{"includeOutdatedSoftware": "True"}, true},
		{"string-false", map[string]interface{}{"includeOutdatedSoftware": "false"}, false},
		{"string-0", map[string]interface{}{"includeOutdatedSoftware": "0"}, false},
		{"int-1", map[string]interface{}{"includeOutdatedSoftware": 1}, true},
		{"int-0", map[string]interface{}{"includeOutdatedSoftware": 0}, false},
		{"float64-1", map[string]interface{}{"includeOutdatedSoftware": float64(1)}, true},
		{"float64-0", map[string]interface{}{"includeOutdatedSoftware": float64(0)}, false},
		{"unknown-type", map[string]interface{}{"includeOutdatedSoftware": []string{"yes"}}, false},
	}
	for _, tc := range cases {
		got := boolPayload(tc.payload, "includeOutdatedSoftware")
		if got != tc.wantOn {
			t.Errorf("%s: boolPayload(includeOutdatedSoftware) = %v, want %v", tc.name, got, tc.wantOn)
		}
	}
}

func TestLocalExecutorListLocalUsersUnsupportedOutsideWindows(t *testing.T) {
	executor := NewLocalExecutor([]protocol.CommandType{protocol.CommandListLocalUsers}, "test")
	command := protocol.AgentCommand{
		CommandID:      "cmd-1",
		ClaimID:        "claim-1",
		AttemptNumber:  1,
		Type:           protocol.CommandListLocalUsers,
		ClaimExpiresAt: time.Now().Add(time.Minute),
	}

	result := executor.Execute(context.Background(), command)

	if result.Status != protocol.CommandStatusUnsupported && result.Status != protocol.CommandStatusSucceeded {
		t.Fatalf("status = %s, want %s or %s", result.Status, protocol.CommandStatusUnsupported, protocol.CommandStatusSucceeded)
	}
}

// ────────────────────────────────────────────────────────────────
// AG-027 — INSTALL_SOFTWARE executor specs

func TestLocalExecutorInstallSoftwareHappyPathSucceeds(t *testing.T) {
	installSoftwareSeam(t, func(_ context.Context, req winget.InstallRequest) winget.InstallResult {
		if req.PackageID != "7zip.7zip" {
			t.Fatalf("unexpected packageId %q", req.PackageID)
		}
		if req.ArgsPolicyPreset != winget.ArgsPresetDefault {
			t.Fatalf("unexpected argsPolicyPreset %q", req.ArgsPolicyPreset)
		}
		return winget.InstallResult{
			FinalStatus:      winget.FinalStatusSucceeded,
			SchemaVersion:    winget.InstallSchemaVersion,
			Supported:        true,
			ExitCode:         0,
			DurationMs:       1234,
			PostVerification: winget.PostVerificationResult{Satisfied: true, MatchedPackageID: "7zip.7zip", MatchedVersion: "24.07", RuleType: winget.DetectionRuleTypeWingetPackage},
		}
	})
	executor := NewLocalExecutor([]protocol.CommandType{protocol.CommandInstallSoftware}, "test")
	command := protocol.AgentCommand{
		CommandID:      "cmd-1",
		ClaimID:        "claim-1",
		AttemptNumber:  1,
		Type:           protocol.CommandInstallSoftware,
		Payload:        installSoftwareTestPayload(),
		ClaimExpiresAt: time.Now().Add(time.Minute),
	}
	result := executor.Execute(context.Background(), command)
	if result.Status != protocol.CommandStatusSucceeded {
		t.Fatalf("status = %s, want SUCCEEDED", result.Status)
	}
	install, ok := result.Details["install"].(winget.InstallResult)
	if !ok {
		t.Fatalf("install detail type = %T", result.Details["install"])
	}
	if install.FinalStatus != winget.FinalStatusSucceeded {
		t.Fatalf("install.FinalStatus = %s", install.FinalStatus)
	}
}

func TestLocalExecutorInstallSoftwareMissingPackageIDFails(t *testing.T) {
	executor := NewLocalExecutor([]protocol.CommandType{protocol.CommandInstallSoftware}, "test")
	payload := installSoftwareTestPayload()
	delete(payload, "packageId")
	command := protocol.AgentCommand{
		CommandID:      "cmd-1",
		ClaimID:        "claim-1",
		AttemptNumber:  1,
		Type:           protocol.CommandInstallSoftware,
		Payload:        payload,
		ClaimExpiresAt: time.Now().Add(time.Minute),
	}
	result := executor.Execute(context.Background(), command)
	if result.Status != protocol.CommandStatusFailed {
		t.Fatalf("status = %s, want FAILED", result.Status)
	}
}

func TestLocalExecutorInstallSoftwareUnsupportedFinalStatusMapsToUnsupported(t *testing.T) {
	installSoftwareSeam(t, func(_ context.Context, _ winget.InstallRequest) winget.InstallResult {
		return winget.InstallResult{
			FinalStatus:      winget.FinalStatusFailedUnsupportedPlatform,
			SchemaVersion:    winget.InstallSchemaVersion,
			Supported:        false,
			FailedReasonCode: "platform_not_windows",
		}
	})
	executor := NewLocalExecutor([]protocol.CommandType{protocol.CommandInstallSoftware}, "test")
	command := protocol.AgentCommand{
		CommandID:      "cmd-1",
		ClaimID:        "claim-1",
		AttemptNumber:  1,
		Type:           protocol.CommandInstallSoftware,
		Payload:        installSoftwareTestPayload(),
		ClaimExpiresAt: time.Now().Add(time.Minute),
	}
	result := executor.Execute(context.Background(), command)
	if result.Status != protocol.CommandStatusUnsupported {
		t.Fatalf("status = %s, want UNSUPPORTED", result.Status)
	}
}

func TestLocalExecutorInstallSoftwareInstallFailureMapsToFailed(t *testing.T) {
	installSoftwareSeam(t, func(_ context.Context, _ winget.InstallRequest) winget.InstallResult {
		return winget.InstallResult{
			FinalStatus:      winget.FinalStatusFailedInstall,
			SchemaVersion:    winget.InstallSchemaVersion,
			Supported:        true,
			FailedReasonCode: "winget_exit_1",
			ExitCode:         1,
		}
	})
	executor := NewLocalExecutor([]protocol.CommandType{protocol.CommandInstallSoftware}, "test")
	command := protocol.AgentCommand{
		CommandID:      "cmd-1",
		ClaimID:        "claim-1",
		AttemptNumber:  1,
		Type:           protocol.CommandInstallSoftware,
		Payload:        installSoftwareTestPayload(),
		ClaimExpiresAt: time.Now().Add(time.Minute),
	}
	result := executor.Execute(context.Background(), command)
	if result.Status != protocol.CommandStatusFailed {
		t.Fatalf("status = %s, want FAILED", result.Status)
	}
}
