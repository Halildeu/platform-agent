package commands

import (
	"context"
	"strings"
	"testing"
	"time"

	"platform-agent/internal/dataprotection"
	"platform-agent/internal/inventory"
	"platform-agent/internal/protocol"
)

const executorDefaultSummaryDryRun = "Command is not implemented by this agent build"

// TestOptInCapabilitiesAllDispatchable extends the AG-013 coherence guard to
// the OPT-IN capabilities (UPDATE_AGENT + COLLECT_BACKUP_DRYRUN). These are not
// in inventory.RuntimeCapabilities() (default), and on a non-Windows host they
// are not advertised at all — but their executor dispatch cases must still
// exist, so that when a policy-ready Windows build advertises them the backend
// does not get false "agent fail" UNSUPPORTED from a missing switch arm.
func TestOptInCapabilitiesAllDispatchable(t *testing.T) {
	optIn := []protocol.CommandType{
		protocol.CommandUpdateAgent,
		protocol.CommandCollectBackupDryRun,
	}
	caps := append(inventory.RuntimeCapabilities(), optIn...)
	executor := NewLocalExecutor(caps, "test")
	ctx := context.Background()
	for _, cmd := range optIn {
		c := protocol.AgentCommand{
			CommandID:      "t-" + string(cmd),
			ClaimID:        "cl",
			AttemptNumber:  1,
			Type:           cmd,
			ClaimExpiresAt: time.Now().Add(time.Minute),
		}
		if cmd.RequiresReason() {
			c.Reason = "regression"
		}
		if cmd == protocol.CommandCollectBackupDryRun {
			c.Payload = map[string]interface{}{
				"roots": []interface{}{
					map[string]interface{}{
						"root_ref":   "managed_root:00000000-0000-0000-0000-000000000000",
						"local_path": t.TempDir(),
						"path_class": "managed/it-folder",
					},
				},
			}
		}
		r := executor.Execute(ctx, c)
		if r.Status == protocol.CommandStatusUnsupported && r.Summary == executorDefaultSummaryDryRun {
			t.Errorf("opt-in capability %q reported no executor case (false advertising)", cmd)
		}
	}
}

// TestExecute_BackupDryRun_Success exercises the executor seam with a fake
// manifest generator and asserts the result is SUCCEEDED, carries the manifest
// in Details, and the Summary is PATH-FREE.
func TestExecute_BackupDryRun_Success(t *testing.T) {
	old := generateBackupDryRunFn
	defer func() { generateBackupDryRunFn = old }()
	generateBackupDryRunFn = func(req dataprotection.Request, now time.Time) (dataprotection.Manifest, error) {
		if len(req.Roots) == 0 {
			t.Error("executor must pass roots through to the generator")
		}
		return dataprotection.Manifest{
			ManifestVersion: "1",
			Aggregate: dataprotection.Aggregate{
				TotalEligibleCount: 7, DeniedCount: 3, ContainerCount: 1, UnresolvedPathCount: 0,
			},
		}, nil
	}

	executor := NewLocalExecutor([]protocol.CommandType{protocol.CommandCollectBackupDryRun}, "test")
	cmd := protocol.AgentCommand{
		CommandID: "c1", ClaimID: "cl1", AttemptNumber: 1,
		Type:           protocol.CommandCollectBackupDryRun,
		Reason:         "audit-prep",
		ClaimExpiresAt: time.Now().Add(time.Minute),
		Payload: map[string]interface{}{
			"device_id": "dev-1", "tenant_id": "ten-1",
			"roots": []interface{}{
				map[string]interface{}{
					"root_ref":   "managed_root:11111111-1111-1111-1111-111111111111",
					"local_path": `C:\Users\alice\OneDrive - Acme`,
					"path_class": "managed/onedrive-business",
				},
			},
		},
	}
	r := executor.Execute(context.Background(), cmd)
	if r.Status != protocol.CommandStatusSucceeded {
		t.Fatalf("expected SUCCEEDED, got %s (%s)", r.Status, r.Summary)
	}
	if _, ok := r.Details["backupDryRun"]; !ok {
		t.Error("expected manifest in result.Details[backupDryRun]")
	}
	if !strings.Contains(r.Summary, "eligible=7") || !strings.Contains(r.Summary, "denied=3") {
		t.Errorf("summary should carry aggregate counts, got %q", r.Summary)
	}
	// PATH-FREE: the raw local_path must not leak into the Summary.
	if strings.Contains(r.Summary, "OneDrive") || strings.Contains(r.Summary, "alice") {
		t.Errorf("raw path leaked into Summary: %q", r.Summary)
	}
}

// TestExecute_BackupDryRun_EmptyPayloadFailsPathFree asserts a missing-roots
// payload fails closed with a path-free summary.
func TestExecute_BackupDryRun_EmptyPayloadFailsPathFree(t *testing.T) {
	executor := NewLocalExecutor([]protocol.CommandType{protocol.CommandCollectBackupDryRun}, "test")
	cmd := protocol.AgentCommand{
		CommandID: "c2", ClaimID: "cl2", AttemptNumber: 1,
		Type:           protocol.CommandCollectBackupDryRun,
		Reason:         "audit-prep",
		ClaimExpiresAt: time.Now().Add(time.Minute),
		Payload:        map[string]interface{}{}, // no roots
	}
	r := executor.Execute(context.Background(), cmd)
	if r.Status != protocol.CommandStatusFailed {
		t.Fatalf("expected FAILED, got %s", r.Status)
	}
	if !strings.Contains(r.Summary, "COLLECT_BACKUP_DRYRUN") {
		t.Errorf("summary should name the command, got %q", r.Summary)
	}
}

// TestValidate_BackupDryRun_RequiresReason asserts the sensitive command is
// reason-gated by Validate.
func TestValidate_BackupDryRun_RequiresReason(t *testing.T) {
	caps := []protocol.CommandType{protocol.CommandCollectBackupDryRun}
	base := protocol.AgentCommand{
		CommandID: "c3", ClaimID: "cl3", AttemptNumber: 1,
		Type:           protocol.CommandCollectBackupDryRun,
		ClaimExpiresAt: time.Now().Add(time.Minute),
	}
	if err := Validate(base, caps, time.Now()); err == nil {
		t.Error("expected missing-reason rejection for COLLECT_BACKUP_DRYRUN")
	}
	base.Reason = "quarterly backup eligibility review"
	if err := Validate(base, caps, time.Now()); err != nil {
		t.Errorf("with reason, Validate should pass, got %v", err)
	}
	if !protocol.CommandCollectBackupDryRun.IsSensitive() {
		t.Error("COLLECT_BACKUP_DRYRUN must be sensitive")
	}
}
