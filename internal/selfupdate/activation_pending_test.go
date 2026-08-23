package selfupdate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// These tests pin the recovery lane for gitops#3483: an activation plan whose
// helper never ran (the measured case: Windows App Control rejected the staged
// helper exe) must be found again on later iterations — and a plan that would
// move a device BACKWARDS must never be.

const (
	pendingIDA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1"
	pendingIDB = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa2"
)

type pendingHighWaterStub struct {
	v   string
	err error
}

func (f pendingHighWaterStub) ReadMaxSeen(context.Context) (string, error) { return f.v, f.err }

// writePendingPlan fabricates a genuine plan through the package's own
// constructors, so these tests break loudly if the plan contract tightens.
func writePendingPlan(t *testing.T, root, id, targetVersion string, mod time.Time) {
	t.Helper()
	staged := filepath.Join(root, "staged-"+id+".bin")
	content := []byte("staged-binary-" + id)
	if err := os.WriteFile(staged, content, 0o600); err != nil {
		t.Fatalf("write staged: %v", err)
	}
	sum := sha256.Sum256(content)
	current := filepath.Join(root, "current-agent.exe")
	if err := os.WriteFile(current, []byte("current"), 0o700); err != nil {
		t.Fatalf("write current: %v", err)
	}
	ready := StageResult{
		StageStatus:            StageReady,
		StagingID:              id,
		ActivationPlanID:       id,
		TargetVersion:          targetVersion,
		ActualSha256:           hex.EncodeToString(sum[:]),
		ActualSignerThumbprint: strings.Repeat("AB", 20),
		SigningTier:            TierTrusted,
	}
	plan, code, reason := BuildActivationPlan(staged, current, "EndpointAgent", ready)
	if code != "" {
		t.Fatalf("BuildActivationPlan: %s %s", code, reason)
	}
	if err := WriteActivationPlan(context.Background(), plan); err != nil {
		t.Fatalf("WriteActivationPlan: %v", err)
	}
	if err := os.Chtimes(plan.ActivationPlanPath, mod, mod); err != nil {
		t.Fatalf("chtimes: %v", err)
	}
}

func findIn(t *testing.T, root, currentVersion string, hw HighWaterReader) (StageResult, bool) {
	t.Helper()
	return FindPendingActivation(context.Background(), root, 1<<20, currentVersion, hw)
}

func TestFindPendingActivation_FindsNewestEligiblePlan(t *testing.T) {
	root := t.TempDir()
	base := time.Now().Add(-time.Hour)
	writePendingPlan(t, root, pendingIDA, "0.3.28", base)
	writePendingPlan(t, root, pendingIDB, "0.3.30", base.Add(time.Minute))

	got, ok := findIn(t, root, "0.3.27", nil)
	if !ok {
		t.Fatal("expected a pending activation")
	}
	if got.ActivationPlanID != pendingIDB || got.TargetVersion != "0.3.30" {
		t.Fatalf("expected newest plan %s@0.3.30, got %s@%s", pendingIDB, got.ActivationPlanID, got.TargetVersion)
	}
	if got.StageStatus != StageReady {
		t.Fatalf("sweep must synthesize StageReady, got %s", got.StageStatus)
	}
}

func TestFindPendingActivation_SkipsConsumedPlan(t *testing.T) {
	root := t.TempDir()
	writePendingPlan(t, root, pendingIDA, "0.3.30", time.Now())
	outcome := filepath.Join(root, "activation-outcome-"+pendingIDA+".json")
	if err := os.WriteFile(outcome, []byte(`{"status":"ACTIVATED"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, ok := findIn(t, root, "0.3.27", nil); ok {
		t.Fatal("a plan with a recorded outcome must not be retried")
	}
}

func TestFindPendingActivation_SkipsWhenStagedBinaryGone(t *testing.T) {
	root := t.TempDir()
	writePendingPlan(t, root, pendingIDA, "0.3.30", time.Now())
	if err := os.Remove(filepath.Join(root, "staged-"+pendingIDA+".bin")); err != nil {
		t.Fatal(err)
	}
	if _, ok := findIn(t, root, "0.3.27", nil); ok {
		t.Fatal("a plan whose staged binary vanished must not be retried")
	}
}

// The reason the version floor exists: staging roots legitimately accumulate
// old plans, and "re-run the newest file" without a floor re-runs history.
func TestFindPendingActivation_NeverDowngradesOrReplays(t *testing.T) {
	root := t.TempDir()
	writePendingPlan(t, root, pendingIDA, "0.3.28", time.Now())

	if _, ok := findIn(t, root, "0.3.29", nil); ok {
		t.Fatal("plan older than the running version must be skipped (downgrade)")
	}
	if _, ok := findIn(t, root, "0.3.28", nil); ok {
		t.Fatal("plan equal to the running version must be skipped (replay)")
	}
	if _, ok := findIn(t, root, "0.3.27", nil); !ok {
		t.Fatal("plan newer than the running version must be found")
	}
}

func TestFindPendingActivation_FailsClosedOnBadCurrentVersion(t *testing.T) {
	root := t.TempDir()
	writePendingPlan(t, root, pendingIDA, "0.3.30", time.Now())
	if _, ok := findIn(t, root, "not-a-version", nil); ok {
		t.Fatal("an unparseable running version must disable the sweep, not bypass the guard")
	}
}

func TestFindPendingActivation_HighWaterFloor(t *testing.T) {
	root := t.TempDir()
	writePendingPlan(t, root, pendingIDA, "0.3.30", time.Now())

	if _, ok := findIn(t, root, "0.3.27", pendingHighWaterStub{v: "0.3.30"}); ok {
		t.Fatal("watermark at the plan's version must block the retry")
	}
	if _, ok := findIn(t, root, "0.3.27", pendingHighWaterStub{v: "0.3.29"}); !ok {
		t.Fatal("watermark below the plan's version must not block the retry")
	}
	if _, ok := findIn(t, root, "0.3.27", pendingHighWaterStub{err: errors.New("io")}); ok {
		t.Fatal("a watermark read error must fail closed")
	}
	if _, ok := findIn(t, root, "0.3.27", pendingHighWaterStub{v: ""}); !ok {
		t.Fatal("an absent watermark (first install) must not block the retry")
	}
}

func TestFindPendingActivation_IgnoresForeignFiles(t *testing.T) {
	root := t.TempDir()
	writePendingPlan(t, root, pendingIDA, "0.3.30", time.Now())
	for _, name := range []string{
		"activation-attempt-" + pendingIDA + ".json", // pacing marker: same prefix, longer id segment
		"activation-zzz.json",                        // invalid id
		"activation-helper-" + pendingIDA + ".exe",   // helper copy
		"unrelated.txt",
	} {
		if err := os.WriteFile(filepath.Join(root, name), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	got, ok := findIn(t, root, "0.3.27", nil)
	if !ok || got.ActivationPlanID != pendingIDA {
		t.Fatalf("foreign files must not hide or hijack the plan; got ok=%v id=%s", ok, got.ActivationPlanID)
	}
}

func TestActivationRetryThrottle(t *testing.T) {
	root := t.TempDir()
	now := time.Now()

	if !ShouldAttemptActivationRetry(root, pendingIDA, now, DefaultActivationRetryInterval) {
		t.Fatal("no marker yet: the first retry must be allowed")
	}
	RecordActivationAttempt(root, pendingIDA, now)
	if ShouldAttemptActivationRetry(root, pendingIDA, now.Add(time.Minute), DefaultActivationRetryInterval) {
		t.Fatal("a retry one minute after an attempt must be throttled")
	}
	if !ShouldAttemptActivationRetry(root, pendingIDA, now.Add(DefaultActivationRetryInterval+time.Second), DefaultActivationRetryInterval) {
		t.Fatal("a retry after the interval must be allowed")
	}

	// A corrupt pacing marker must never wedge the recovery lane shut.
	if err := os.WriteFile(activationAttemptNameFor(root, pendingIDA), []byte("{corrupt"), 0o600); err != nil {
		t.Fatal(err)
	}
	if !ShouldAttemptActivationRetry(root, pendingIDA, now, DefaultActivationRetryInterval) {
		t.Fatal("corrupt marker: retry must still be allowed")
	}

	RecordActivationAttempt(root, pendingIDA, now)
	RecordActivationAttempt(root, pendingIDA, now.Add(time.Minute))
	raw, err := os.ReadFile(activationAttemptNameFor(root, pendingIDA))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"attempts":2`) {
		t.Fatalf("attempt count must accumulate, got %s", raw)
	}
}
