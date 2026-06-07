package commands

import (
	"context"
	"encoding/json"
	"io"
	"runtime"
	"strings"
	"testing"
	"time"

	"platform-agent/internal/inventory"
	"platform-agent/internal/protocol"
	"platform-agent/internal/selfupdate"
	"platform-agent/internal/users"
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

func updateAgentStageSeam(t *testing.T, stub func(ctx context.Context, stager *selfupdate.Stager, payload selfupdate.UpdateAgentPayload, currentVersion string) selfupdate.StageResult) {
	t.Helper()
	prev := updateAgentStageFn
	updateAgentStageFn = stub
	t.Cleanup(func() { updateAgentStageFn = prev })
}

func mutateLocalUserSeam(t *testing.T, stub func(users.LocalUserMutationRequest) (users.LocalUserMutationResult, error)) {
	t.Helper()
	prev := mutateLocalUserFn
	mutateLocalUserFn = stub
	t.Cleanup(func() { mutateLocalUserFn = prev })
}

func updateAgentTestPayload() map[string]interface{} {
	return map[string]interface{}{
		"releaseId":               "release-1",
		"channel":                 "stable",
		"ring":                    "pilot",
		"targetVersion":           "0.2.1",
		"binaryUrl":               "https://objects.githubusercontent.com/releases/endpoint-agent.exe",
		"claimedSha256":           "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"claimedSignerThumbprint": "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
		"signingTier":             "TRUSTED",
		"maxBytes":                float64(104857600),
	}
}

type fakeUpdateVerifier struct{}

func (fakeUpdateVerifier) Verify(context.Context, string) (selfupdate.AuthenticodeEvidence, error) {
	return selfupdate.AuthenticodeEvidence{
		ChainValid:        true,
		HasCodeSigningEKU: true,
		SignerThumbprint:  "AABBCC",
		CurrentTimeValid:  true,
	}, nil
}

type fakeUpdateVersionReader struct{}

func (fakeUpdateVersionReader) ReadVersion(context.Context, string) (string, error) {
	return "0.2.1", nil
}

type fakeUpdateDownloader struct{}

func (fakeUpdateDownloader) Download(context.Context, string, selfupdate.URLPolicy, int64, io.Writer) (int64, selfupdate.ErrorCode, string) {
	return 0, "", ""
}

type fakeUpdateStaging struct{}

func (fakeUpdateStaging) Commit(context.Context, string, string) (string, error) {
	return "local-only", nil
}

type fakeActivationPlanWriter struct{}

func (fakeActivationPlanWriter) WriteActivationPlan(context.Context, selfupdate.ActivationPlan) error {
	return nil
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

func TestLocalExecutorLockUserLoginCallsLocalMutationAdapter(t *testing.T) {
	mutateLocalUserSeam(t, func(req users.LocalUserMutationRequest) (users.LocalUserMutationResult, error) {
		if req.Action != users.ActionLockUserLogin {
			t.Fatalf("action = %q, want %q", req.Action, users.ActionLockUserLogin)
		}
		if req.Username != "pilot-local" {
			t.Fatalf("username = %q", req.Username)
		}
		if req.NewPassword != "" {
			t.Fatal("LOCK_USER_LOGIN must not pass password material to the adapter")
		}
		disabled := true
		return users.LocalUserMutationResult{
			Username: "pilot-local",
			Action:   string(users.ActionLockUserLogin),
			Disabled: &disabled,
		}, nil
	})
	executor := NewLocalExecutor([]protocol.CommandType{protocol.CommandLockUserLogin}, "test")
	command := protocol.AgentCommand{
		CommandID:      "cmd-lock",
		ClaimID:        "claim-lock",
		AttemptNumber:  1,
		Type:           protocol.CommandLockUserLogin,
		Reason:         "dual-control approved local recovery drill",
		Payload:        map[string]interface{}{"username": "pilot-local"},
		ClaimExpiresAt: time.Now().Add(time.Minute),
	}

	result := executor.Execute(context.Background(), command)

	if result.Status != protocol.CommandStatusSucceeded {
		t.Fatalf("status = %s, want SUCCEEDED; summary=%q", result.Status, result.Summary)
	}
	localUser, ok := result.Details["localUser"].(users.LocalUserMutationResult)
	if !ok {
		t.Fatalf("localUser detail type = %T", result.Details["localUser"])
	}
	if localUser.Username != "pilot-local" || localUser.Disabled == nil || !*localUser.Disabled {
		t.Fatalf("unexpected localUser detail: %+v", localUser)
	}
}

func TestLocalExecutorUnlockUserLoginCallsLocalMutationAdapter(t *testing.T) {
	mutateLocalUserSeam(t, func(req users.LocalUserMutationRequest) (users.LocalUserMutationResult, error) {
		if req.Action != users.ActionUnlockUserLogin {
			t.Fatalf("action = %q, want %q", req.Action, users.ActionUnlockUserLogin)
		}
		if req.Username != "pilot-local" {
			t.Fatalf("username = %q", req.Username)
		}
		disabled := false
		lockedOut := false
		return users.LocalUserMutationResult{
			Username:  "pilot-local",
			Action:    string(users.ActionUnlockUserLogin),
			Disabled:  &disabled,
			LockedOut: &lockedOut,
		}, nil
	})
	executor := NewLocalExecutor([]protocol.CommandType{protocol.CommandUnlockUserLogin}, "test")
	command := protocol.AgentCommand{
		CommandID:      "cmd-unlock",
		ClaimID:        "claim-unlock",
		AttemptNumber:  1,
		Type:           protocol.CommandUnlockUserLogin,
		Reason:         "dual-control approved recovery restore",
		Payload:        map[string]interface{}{"username": "pilot-local"},
		ClaimExpiresAt: time.Now().Add(time.Minute),
	}

	result := executor.Execute(context.Background(), command)

	if result.Status != protocol.CommandStatusSucceeded {
		t.Fatalf("status = %s, want SUCCEEDED; summary=%q", result.Status, result.Summary)
	}
}

func TestLocalExecutorChangeLocalPasswordRequiresSecretMaterial(t *testing.T) {
	executor := NewLocalExecutor([]protocol.CommandType{protocol.CommandChangeLocalPassword}, "test")
	command := protocol.AgentCommand{
		CommandID:      "cmd-password",
		ClaimID:        "claim-password",
		AttemptNumber:  1,
		Type:           protocol.CommandChangeLocalPassword,
		Reason:         "dual-control approved recovery password rotation",
		Payload:        map[string]interface{}{"username": "pilot-local"},
		ClaimExpiresAt: time.Now().Add(time.Minute),
	}

	result := executor.Execute(context.Background(), command)

	if result.Status != protocol.CommandStatusFailed {
		t.Fatalf("status = %s, want FAILED", result.Status)
	}
	if result.Summary != "CHANGE_LOCAL_PASSWORD payload missing newPassword" {
		t.Fatalf("summary = %q", result.Summary)
	}
}

func TestLocalExecutorChangeLocalPasswordDoesNotReturnSecretMaterial(t *testing.T) {
	const secret = "Temp-Passphrase-12345!"
	mutateLocalUserSeam(t, func(req users.LocalUserMutationRequest) (users.LocalUserMutationResult, error) {
		if req.Action != users.ActionChangeLocalPassword {
			t.Fatalf("action = %q, want %q", req.Action, users.ActionChangeLocalPassword)
		}
		if req.NewPassword != secret {
			t.Fatalf("adapter did not receive the exact secret bytes")
		}
		return users.LocalUserMutationResult{
			Username:        req.Username,
			Action:          string(users.ActionChangeLocalPassword),
			PasswordChanged: true,
		}, nil
	})
	executor := NewLocalExecutor([]protocol.CommandType{protocol.CommandChangeLocalPassword}, "test")
	command := protocol.AgentCommand{
		CommandID:      "cmd-password",
		ClaimID:        "claim-password",
		AttemptNumber:  1,
		Type:           protocol.CommandChangeLocalPassword,
		Reason:         "dual-control approved recovery password rotation",
		Payload:        map[string]interface{}{"username": "pilot-local", "newPassword": secret},
		ClaimExpiresAt: time.Now().Add(time.Minute),
	}

	result := executor.Execute(context.Background(), command)

	if result.Status != protocol.CommandStatusSucceeded {
		t.Fatalf("status = %s, want SUCCEEDED; summary=%q", result.Status, result.Summary)
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), secret) {
		t.Fatalf("command result leaked password secret: %s", encoded)
	}
}

func TestLocalExecutorUpdateAgentStagesAndReturnsStructuredResult(t *testing.T) {
	updateAgentStageSeam(t, func(_ context.Context, _ *selfupdate.Stager, payload selfupdate.UpdateAgentPayload, currentVersion string) selfupdate.StageResult {
		if payload.TargetVersion != "0.2.1" {
			t.Fatalf("targetVersion = %q", payload.TargetVersion)
		}
		if currentVersion != "0.1.0-dev" {
			t.Fatalf("currentVersion = %q", currentVersion)
		}
		return selfupdate.StageResult{
			StageStatus:            selfupdate.StageReady,
			StagingID:              "0123456789abcdef0123456789abcdef",
			ActivationPlanID:       "0123456789abcdef0123456789abcdef",
			OldVersion:             currentVersion,
			TargetVersion:          payload.TargetVersion,
			ActualSha256:           "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
			ActualSignerThumbprint: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
			SigningTier:            selfupdate.TierTrusted,
			Reason:                 "verified and staged; awaiting activation",
		}
	})
	executor := NewLocalExecutor([]protocol.CommandType{protocol.CommandUpdateAgent}, "0.1.0-dev")
	executor.UpdateAgentStager = &selfupdate.Stager{}
	command := protocol.AgentCommand{
		CommandID:      "cmd-update",
		ClaimID:        "claim-update",
		AttemptNumber:  1,
		Type:           protocol.CommandUpdateAgent,
		Reason:         "approved maintenance window",
		Payload:        updateAgentTestPayload(),
		ClaimExpiresAt: time.Now().Add(time.Minute),
	}

	result := executor.Execute(context.Background(), command)

	if result.Status != protocol.CommandStatusSucceeded {
		t.Fatalf("status = %s, want %s; summary=%q", result.Status, protocol.CommandStatusSucceeded, result.Summary)
	}
	if result.Summary != "UPDATE_AGENT STAGED_ACTIVATION_READY" {
		t.Fatalf("summary = %q", result.Summary)
	}
	update, ok := result.Details["update"].(selfupdate.StageResult)
	if !ok {
		t.Fatalf("update detail type = %T", result.Details["update"])
	}
	if update.StageStatus != selfupdate.StageReady || update.ActivationPlanID == "" {
		t.Fatalf("unexpected update detail: %+v", update)
	}
}

func TestLocalExecutorUpdateAgentFailedStageMapsFailed(t *testing.T) {
	updateAgentStageSeam(t, func(context.Context, *selfupdate.Stager, selfupdate.UpdateAgentPayload, string) selfupdate.StageResult {
		return selfupdate.Failed(selfupdate.ErrSignerNotAllowed, "verified signer not in local allowlist")
	})
	executor := NewLocalExecutor([]protocol.CommandType{protocol.CommandUpdateAgent}, "0.1.0-dev")
	executor.UpdateAgentStager = &selfupdate.Stager{}
	command := protocol.AgentCommand{
		CommandID:      "cmd-update",
		ClaimID:        "claim-update",
		AttemptNumber:  1,
		Type:           protocol.CommandUpdateAgent,
		Reason:         "approved maintenance window",
		Payload:        updateAgentTestPayload(),
		ClaimExpiresAt: time.Now().Add(time.Minute),
	}

	result := executor.Execute(context.Background(), command)

	if result.Status != protocol.CommandStatusFailed {
		t.Fatalf("status = %s, want FAILED", result.Status)
	}
	update := result.Details["update"].(selfupdate.StageResult)
	if update.ErrorCode != selfupdate.ErrSignerNotAllowed {
		t.Fatalf("errorCode = %q", update.ErrorCode)
	}
}

func TestLocalExecutorUpdateAgentRequiresPayload(t *testing.T) {
	executor := NewLocalExecutor([]protocol.CommandType{protocol.CommandUpdateAgent}, "0.1.0-dev")
	command := protocol.AgentCommand{
		CommandID:      "cmd-update",
		ClaimID:        "claim-update",
		AttemptNumber:  1,
		Type:           protocol.CommandUpdateAgent,
		Reason:         "approved maintenance window",
		ClaimExpiresAt: time.Now().Add(time.Minute),
	}

	result := executor.Execute(context.Background(), command)

	if result.Status != protocol.CommandStatusFailed {
		t.Fatalf("status = %s, want FAILED", result.Status)
	}
	if result.Summary != "UPDATE_AGENT payload is empty" {
		t.Fatalf("summary = %q", result.Summary)
	}
}

func TestLocalExecutorUpdateAgentNilStagerFailsClosed(t *testing.T) {
	executor := NewLocalExecutor([]protocol.CommandType{protocol.CommandUpdateAgent}, "0.1.0-dev")
	command := protocol.AgentCommand{
		CommandID:      "cmd-update",
		ClaimID:        "claim-update",
		AttemptNumber:  1,
		Type:           protocol.CommandUpdateAgent,
		Reason:         "approved maintenance window",
		Payload:        updateAgentTestPayload(),
		ClaimExpiresAt: time.Now().Add(time.Minute),
	}

	result := executor.Execute(context.Background(), command)

	if result.Status != protocol.CommandStatusFailed {
		t.Fatalf("status = %s, want FAILED", result.Status)
	}
	update := result.Details["update"].(selfupdate.StageResult)
	if update.ErrorCode != selfupdate.ErrStagingIO {
		t.Fatalf("errorCode = %q, want %q", update.ErrorCode, selfupdate.ErrStagingIO)
	}
}

func TestNewPolicyAwareExecutorDoesNotAdvertiseUpdateAgentWithoutRuntimeCollaborators(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows default runtime collaborators are wired by AG-029 PR1b")
	}
	executor := NewPolicyAwareExecutor("0.1.0-dev", true, UpdateAgentStagerOptions{
		AllowedHosts:      []string{"github.com"},
		SignerThumbprints: []string{"AABBCC"},
		MaxRedirects:      5,
		HardMaxBytes:      1000,
	})

	if hasExecutorCapability(executor, protocol.CommandUpdateAgent) {
		t.Fatal("local policy without runtime verifier/staging collaborators must not advertise UPDATE_AGENT")
	}
	if executor.UpdateAgentStager != nil {
		t.Fatal("runtime-incomplete policy must not wire an update stager")
	}
}

func TestNewPolicyAwareExecutorCanWireUpdateAgentWhenRuntimeReady(t *testing.T) {
	executor := NewPolicyAwareExecutor("0.1.0-dev", true, UpdateAgentStagerOptions{
		AllowedHosts:      []string{"github.com"},
		SignerThumbprints: []string{"AABBCC"},
		MaxRedirects:      5,
		HardMaxBytes:      1000,
		Verifier:          fakeUpdateVerifier{},
		VersionReader:     fakeUpdateVersionReader{},
		Downloader:        fakeUpdateDownloader{},
		Staging:           fakeUpdateStaging{},
		PlanWriter:        fakeActivationPlanWriter{},
		CurrentBinaryPath: "/agent/current",
		ServiceName:       "EndpointAgent",
	})

	if runtime.GOOS == "windows" && !hasExecutorCapability(executor, protocol.CommandUpdateAgent) {
		t.Fatal("runtime-ready Windows agent should advertise UPDATE_AGENT")
	}
	if runtime.GOOS != "windows" && hasExecutorCapability(executor, protocol.CommandUpdateAgent) {
		t.Fatal("non-Windows agent must not advertise UPDATE_AGENT even with test collaborators")
	}
	if executor.UpdateAgentStager == nil {
		t.Fatal("runtime-ready options should wire an update stager")
	}
}

func hasExecutorCapability(executor *LocalExecutor, target protocol.CommandType) bool {
	for _, capability := range executor.Capabilities {
		if capability == target {
			return true
		}
	}
	return false
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

// AG-037 — boolPayload mapping for the includeHotfixPosture key. Mirrors
// the AG-036 matrix above so a regression in the payload coercion is
// caught at the executor surface, not just at the inventory opt-in test
// seam (Codex 019e8167 iter-2 P2 gap absorb).
func TestLocalExecutorBoolPayloadIncludeHotfixPosture(t *testing.T) {
	cases := []struct {
		name    string
		payload map[string]interface{}
		wantOn  bool
	}{
		{"nil-payload", nil, false},
		{"missing-key", map[string]interface{}{"includeSoftware": true}, false},
		{"bool-true", map[string]interface{}{"includeHotfixPosture": true}, true},
		{"bool-false", map[string]interface{}{"includeHotfixPosture": false}, false},
		{"string-true", map[string]interface{}{"includeHotfixPosture": "true"}, true},
		{"string-1", map[string]interface{}{"includeHotfixPosture": "1"}, true},
		{"string-True", map[string]interface{}{"includeHotfixPosture": "True"}, true},
		{"string-false", map[string]interface{}{"includeHotfixPosture": "false"}, false},
		{"string-0", map[string]interface{}{"includeHotfixPosture": "0"}, false},
		{"int-1", map[string]interface{}{"includeHotfixPosture": 1}, true},
		{"int-0", map[string]interface{}{"includeHotfixPosture": 0}, false},
		{"float64-1", map[string]interface{}{"includeHotfixPosture": float64(1)}, true},
		{"float64-0", map[string]interface{}{"includeHotfixPosture": float64(0)}, false},
		{"unknown-type", map[string]interface{}{"includeHotfixPosture": []string{"yes"}}, false},
	}
	for _, tc := range cases {
		got := boolPayload(tc.payload, "includeHotfixPosture")
		if got != tc.wantOn {
			t.Errorf("%s: boolPayload(includeHotfixPosture) = %v, want %v", tc.name, got, tc.wantOn)
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
