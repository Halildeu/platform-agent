package selfupdate

// Pending-activation recovery (gitops#3483).
//
// The activation hook fires exactly once, at the moment staging completes. If
// the spawned helper never runs — the measured case was Windows App Control
// rejecting the staged helper exe on 2026-08-02 — nothing ever returns to the
// plan: the server's UPDATE_AGENT command already reported success, so no new
// command arrives, and the staged update rots in the staging root while the
// fleet reports healthy heartbeats on the old version. That exact shape held a
// device three versions behind for 21 days, invisibly. The block itself had
// lifted within days; the agent simply never asked again.
//
// This file is the asking-again. Each runner iteration may call the sweep,
// which re-launches the activation hook for the newest still-valid,
// still-unconsumed plan — throttled so a persistently blocked helper retries
// on the order of minutes, not per poll, forever (a policy can be lifted weeks
// later, so the retry deliberately never gives up).

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// DefaultActivationRetryInterval spaces retry attempts for one plan. Poll
// cycles are tens of seconds; forking a doomed helper that often would smear
// the log and the process table for nothing. Minutes-apart keeps the lane
// self-healing without the noise.
const DefaultActivationRetryInterval = 15 * time.Minute

// HighWaterReader reports the highest version this host has ever activated.
// Satisfied by FileHighWaterStore. The sweep treats it as a secondary guard
// and tolerates its absence — the deployed activation path does not maintain
// the watermark (the runner launches the helper without --high-water-path).
type HighWaterReader interface {
	ReadMaxSeen(ctx context.Context) (string, error)
}

func activationAttemptNameFor(root, stagingID string) string {
	return filepath.Join(root, "activation-attempt-"+stagingID+".json")
}

type activationAttemptRecord struct {
	SchemaVersion    int    `json:"schemaVersion"`
	ActivationPlanID string `json:"activationPlanId"`
	LastAttemptUnix  int64  `json:"lastAttemptUnix"`
	Attempts         int    `json:"attempts"`
}

// FindPendingActivation returns a StageReady-shaped StageResult for the newest
// activation plan in root that was written, never produced an outcome, and
// still verifies end to end (plan valid, staged binary present, hash intact).
//
// Guards, fail-closed on ambiguity because this function's output restarts a
// service and swaps its binary:
//
//   - currentVersion must parse, and a plan is eligible only if its target is
//     STRICTLY newer. This is what stops a stale July plan from downgrading a
//     device that has since moved on — the staging root legitimately
//     accumulates old plans, and "re-run the newest file" without a version
//     floor would eventually re-run history.
//   - highWater, when readable and non-empty, must also be exceeded. The
//     watermark survives binary swaps, so it additionally covers the window
//     where a plan targets the version that is mid-activation.
//   - A high-water READ ERROR aborts the sweep (no retry this cycle) rather
//     than proceeding without the guard; state.go documents why an ambiguous
//     watermark is treated as corruption, and this honors that posture.
func FindPendingActivation(ctx context.Context, root string, maxBytes int64, currentVersion string, highWater HighWaterReader) (StageResult, bool) {
	root = strings.TrimSpace(root)
	if root == "" {
		return StageResult{}, false
	}
	curV, err := ParseVersion(currentVersion)
	if err != nil {
		return StageResult{}, false
	}

	haveFloor := false
	var floor Version
	if highWater != nil {
		raw, err := highWater.ReadMaxSeen(ctx)
		if err != nil {
			return StageResult{}, false
		}
		if v := strings.TrimSpace(raw); v != "" {
			parsed, err := ParseVersion(v)
			if err != nil {
				return StageResult{}, false
			}
			floor, haveFloor = parsed, true
		}
	}

	entries, err := os.ReadDir(root)
	if err != nil {
		return StageResult{}, false
	}

	var best StageResult
	var bestMod time.Time
	found := false
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasPrefix(name, "activation-") || !strings.HasSuffix(name, ".json") {
			continue
		}
		id := strings.TrimSuffix(strings.TrimPrefix(name, "activation-"), ".json")
		// validStagingID (32 hex) also rejects the sibling artifacts that share
		// the prefix: activation-outcome-<id>.json, activation-attempt-<id>.json.
		if !validStagingID(id) {
			continue
		}
		if _, err := os.Lstat(activationOutcomeNameFor(root, id)); err == nil {
			continue // consumed: activation already ran to a recorded outcome
		}
		plan, code, _ := LoadActivationPlan(root, id)
		if code != "" {
			continue
		}
		if _, code, _ := VerifyActivationPlanReady(root, id, maxBytes); code != "" {
			continue
		}
		target, err := ParseVersion(plan.TargetVersion)
		if err != nil {
			continue
		}
		if Compare(target, curV) <= 0 {
			continue // never re-run history: downgrade / same-version replay
		}
		if haveFloor && Compare(target, floor) <= 0 {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		if !found || info.ModTime().After(bestMod) {
			found = true
			bestMod = info.ModTime()
			best = StageResult{
				StageStatus:      StageReady,
				StagingID:        id,
				ActivationPlanID: id,
				TargetVersion:    plan.TargetVersion,
				ActualSha256:     plan.ActualSha256,
			}
		}
	}
	return best, found
}

// ShouldAttemptActivationRetry reports whether enough time has passed since
// the last recorded attempt for this plan. A missing or unreadable marker
// means "yes": the marker is advisory pacing, and a corrupt pacing file must
// never be able to wedge the recovery lane shut.
func ShouldAttemptActivationRetry(root, stagingID string, now time.Time, minInterval time.Duration) bool {
	if !validStagingID(stagingID) {
		return false
	}
	raw, err := os.ReadFile(activationAttemptNameFor(strings.TrimSpace(root), stagingID))
	if err != nil {
		return true
	}
	var rec activationAttemptRecord
	if err := json.Unmarshal(stripUTF8BOM(raw), &rec); err != nil {
		return true
	}
	if rec.LastAttemptUnix <= 0 {
		return true
	}
	return now.Sub(time.Unix(rec.LastAttemptUnix, 0)) >= minInterval
}

// RecordActivationAttempt persists the attempt marker. Best-effort by design
// (plain WriteFile, errors dropped): the worst a lost marker causes is one
// extra retry a cycle later, while a strict marker could turn a full disk
// into a permanently silent update lane — the exact failure this file exists
// to remove.
func RecordActivationAttempt(root, stagingID string, now time.Time) {
	if !validStagingID(stagingID) {
		return
	}
	prev := 0
	path := activationAttemptNameFor(strings.TrimSpace(root), stagingID)
	if raw, err := os.ReadFile(path); err == nil {
		var rec activationAttemptRecord
		if json.Unmarshal(stripUTF8BOM(raw), &rec) == nil {
			prev = rec.Attempts
		}
	}
	rec := activationAttemptRecord{
		SchemaVersion:    1,
		ActivationPlanID: stagingID,
		LastAttemptUnix:  now.Unix(),
		Attempts:         prev + 1,
	}
	raw, err := json.Marshal(rec)
	if err != nil {
		return
	}
	_ = os.WriteFile(path, raw, 0o600)
}
