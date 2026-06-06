package selfupdate

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestActivatePreparedUpdateSwapsBinaryAndStartsService(t *testing.T) {
	root, stagingID, plan, stagedPayload, currentPayload := writeActivationFixture(t)
	svc := &fakeActivationService{}
	highWater := &fakeHighWaterWriter{}

	out := ActivatePreparedUpdate(context.Background(), root, stagingID, 1024, svc, highWater)

	if out.Status != ActivationActivated || !out.ServiceRunningVerified || !out.EvidencePersisted {
		t.Fatalf("outcome=%+v", out)
	}
	if got := readFileString(t, plan.CurrentBinaryPath); got != string(stagedPayload) {
		t.Fatalf("current binary=%q, want staged", got)
	}
	if got := readFileString(t, activationBackupNameFor(root, stagingID)); got != string(currentPayload) {
		t.Fatalf("rollback backup=%q, want original current", got)
	}
	if len(svc.calls) != 2 || svc.calls[0] != "stop:EndpointAgent" || svc.calls[1] != "start:EndpointAgent" {
		t.Fatalf("service calls=%v", svc.calls)
	}
	if highWater.version != plan.TargetVersion {
		t.Fatalf("high-water version=%q", highWater.version)
	}
	persisted, code, reason := LoadActivationOutcome(root, stagingID)
	if code != "" || reason != "" {
		t.Fatalf("LoadActivationOutcome: code=%q reason=%q", code, reason)
	}
	if !persisted.EvidencePersisted {
		t.Fatalf("persisted outcome should record evidencePersisted=true: %+v", persisted)
	}
}

func TestActivatePreparedUpdateRollsBackWhenStartFails(t *testing.T) {
	root, stagingID, plan, _, currentPayload := writeActivationFixture(t)
	svc := &fakeActivationService{failFirstStart: true}

	out := ActivatePreparedUpdate(context.Background(), root, stagingID, 1024, svc, nil)

	if out.Status != ActivationRolledBack || !out.ServiceRunningVerified {
		t.Fatalf("outcome=%+v", out)
	}
	if got := readFileString(t, plan.CurrentBinaryPath); got != string(currentPayload) {
		t.Fatalf("current binary=%q, want rollback payload", got)
	}
	if len(svc.calls) != 3 || svc.calls[0] != "stop:EndpointAgent" || svc.calls[1] != "start:EndpointAgent" || svc.calls[2] != "start:EndpointAgent" {
		t.Fatalf("service calls=%v", svc.calls)
	}
}

func TestActivatePreparedUpdateStopFailureDoesNotSwapCurrentBinary(t *testing.T) {
	root, stagingID, plan, _, currentPayload := writeActivationFixture(t)
	svc := &fakeActivationService{stopErr: errors.New("cannot stop")}

	out := ActivatePreparedUpdate(context.Background(), root, stagingID, 1024, svc, nil)

	if out.Status != ActivationFailed {
		t.Fatalf("outcome=%+v", out)
	}
	if got := readFileString(t, plan.CurrentBinaryPath); got != string(currentPayload) {
		t.Fatalf("current binary=%q, want original current", got)
	}
	if len(svc.calls) != 1 || svc.calls[0] != "stop:EndpointAgent" {
		t.Fatalf("service calls=%v", svc.calls)
	}
}

func writeActivationFixture(t *testing.T) (string, string, ActivationPlan, []byte, []byte) {
	t.Helper()
	root := t.TempDir()
	stagingID := "0123456789abcdef0123456789abcdef"
	stagedPayload := []byte("new agent binary")
	currentPayload := []byte("current agent binary")
	stagedPath := stagedNameFor(root, stagingID)
	currentPath := filepath.Join(root, "current.exe")
	if err := os.WriteFile(stagedPath, stagedPayload, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(currentPath, currentPayload, 0o600); err != nil {
		t.Fatal(err)
	}
	hash, code, reason := HashFileWithLimit(stagedPath, 1024)
	if code != "" || reason != "" {
		t.Fatalf("HashFileWithLimit: code=%q reason=%q", code, reason)
	}
	plan, code, reason := BuildActivationPlan(stagedPath, currentPath, "EndpointAgent", readyStageForPlan(stagingID, hash.ActualSha256))
	if code != "" || reason != "" {
		t.Fatalf("BuildActivationPlan: code=%q reason=%q", code, reason)
	}
	writeActivationPlanOrSkip(t, plan)
	return root, stagingID, plan, stagedPayload, currentPayload
}

type fakeActivationService struct {
	calls          []string
	stopErr        error
	failFirstStart bool
}

func (f *fakeActivationService) Stop(_ context.Context, serviceName string) error {
	f.calls = append(f.calls, "stop:"+serviceName)
	return f.stopErr
}

func (f *fakeActivationService) Start(_ context.Context, serviceName string) error {
	f.calls = append(f.calls, "start:"+serviceName)
	if f.failFirstStart {
		f.failFirstStart = false
		return errors.New("start failed")
	}
	return nil
}

type fakeHighWaterWriter struct {
	version string
}

func (f *fakeHighWaterWriter) WriteMaxSeen(_ context.Context, version string) error {
	f.version = version
	return nil
}

func readFileString(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}
