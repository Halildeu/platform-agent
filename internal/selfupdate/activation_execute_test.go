package selfupdate

import (
	"context"
	"errors"
	"os"
	"testing"
)

func TestActivatePreparedUpdateSwapsBinaryAndStartsService(t *testing.T) {
	root := t.TempDir()
	withNoopStagedFileHardener(t)
	paths, plan, stagedPayload := writeTestActivationPlan(t, root)
	currentPayload := []byte("current agent binary")
	if err := os.WriteFile(plan.CurrentBinaryPath, currentPayload, 0o600); err != nil {
		t.Fatal(err)
	}
	if code, reason := WriteActivationPlan(paths, plan); code != "" || reason != "" {
		t.Fatalf("WriteActivationPlan: code=%q reason=%q", code, reason)
	}
	if err := os.WriteFile(paths.BinaryPath, stagedPayload, 0o600); err != nil {
		t.Fatal(err)
	}

	svc := &fakeActivationService{}
	outcome := ActivatePreparedUpdate(context.Background(), paths, 1024, svc)

	if outcome.Status != ActivationActivated || outcome.ActivationPlanID != plan.ActivationPlanID || outcome.NewSha256 != plan.ActualSha256 {
		t.Fatalf("outcome=%+v", outcome)
	}
	if got := readFileString(t, plan.CurrentBinaryPath); got != string(stagedPayload) {
		t.Fatalf("current binary=%q, want staged payload", got)
	}
	if got := readFileString(t, rollbackBackupPath(paths)); got != string(currentPayload) {
		t.Fatalf("rollback backup=%q, want original current", got)
	}
	if got := svc.calls; len(got) != 2 || got[0] != "stop:EndpointAgent" || got[1] != "start:EndpointAgent" {
		t.Fatalf("service calls=%v", got)
	}
}

func TestActivatePreparedUpdateRollsBackWhenStartFails(t *testing.T) {
	root := t.TempDir()
	withNoopStagedFileHardener(t)
	paths, plan, stagedPayload := writeTestActivationPlan(t, root)
	currentPayload := []byte("current agent binary")
	if err := os.WriteFile(plan.CurrentBinaryPath, currentPayload, 0o600); err != nil {
		t.Fatal(err)
	}
	if code, reason := WriteActivationPlan(paths, plan); code != "" || reason != "" {
		t.Fatalf("WriteActivationPlan: code=%q reason=%q", code, reason)
	}
	if err := os.WriteFile(paths.BinaryPath, stagedPayload, 0o600); err != nil {
		t.Fatal(err)
	}

	svc := &fakeActivationService{failFirstStart: true}
	outcome := ActivatePreparedUpdate(context.Background(), paths, 1024, svc)

	if outcome.Status != ActivationRolledBack || outcome.ActivationPlanID != plan.ActivationPlanID {
		t.Fatalf("outcome=%+v", outcome)
	}
	if got := readFileString(t, plan.CurrentBinaryPath); got != string(currentPayload) {
		t.Fatalf("current binary=%q, want rollback payload", got)
	}
	if got := svc.calls; len(got) != 3 || got[0] != "stop:EndpointAgent" || got[1] != "start:EndpointAgent" || got[2] != "start:EndpointAgent" {
		t.Fatalf("service calls=%v", got)
	}
}

func TestActivatePreparedUpdateStopFailureDoesNotSwapCurrentBinary(t *testing.T) {
	root := t.TempDir()
	withNoopStagedFileHardener(t)
	paths, plan, stagedPayload := writeTestActivationPlan(t, root)
	currentPayload := []byte("current agent binary")
	if err := os.WriteFile(plan.CurrentBinaryPath, currentPayload, 0o600); err != nil {
		t.Fatal(err)
	}
	if code, reason := WriteActivationPlan(paths, plan); code != "" || reason != "" {
		t.Fatalf("WriteActivationPlan: code=%q reason=%q", code, reason)
	}
	if err := os.WriteFile(paths.BinaryPath, stagedPayload, 0o600); err != nil {
		t.Fatal(err)
	}

	svc := &fakeActivationService{stopErr: errors.New("cannot stop")}
	outcome := ActivatePreparedUpdate(context.Background(), paths, 1024, svc)

	if outcome.Status != ActivationFailed {
		t.Fatalf("outcome=%+v", outcome)
	}
	if got := readFileString(t, plan.CurrentBinaryPath); got != string(currentPayload) {
		t.Fatalf("current binary=%q, want original current", got)
	}
	if got := svc.calls; len(got) != 1 || got[0] != "stop:EndpointAgent" {
		t.Fatalf("service calls=%v", got)
	}
}

func TestActivatePreparedUpdateRequiresServiceController(t *testing.T) {
	outcome := ActivatePreparedUpdate(context.Background(), StagingPaths{}, 1024, nil)
	if outcome.Status != ActivationFailed {
		t.Fatalf("outcome=%+v", outcome)
	}
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

func readFileString(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}
