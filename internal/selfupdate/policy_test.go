package selfupdate

import "testing"

func goodPayload() UpdateAgentPayload {
	return UpdateAgentPayload{
		ReleaseID:     "rel-1",
		TargetVersion: "1.1.0",
		BinaryURL:     "https://github.com/Halildeu/platform-agent/releases/download/v1.1.0/agent.exe",
		ClaimedSha256: "deadbeef",
		SigningTier:   TierTrusted,
	}
}

func baseInput() PreflightInput {
	return PreflightInput{
		Platform:       "windows",
		CurrentVersion: "1.0.0",
		Payload:        goodPayload(),
		URLPolicy:      URLPolicy{AllowedHosts: []string{"github.com"}, MaxRedirects: 5},
		TierPolicy:     TierPolicy{},
	}
}

func TestEvaluatePreflight_HappyProceed(t *testing.T) {
	d := EvaluatePreflight(baseInput())
	if !d.Proceed || d.Noop {
		t.Fatalf("expected Proceed, got %+v", d)
	}
	if d.Result.TargetVersion != "1.1.0" || d.Result.OldVersion != "1.0.0" {
		t.Errorf("result evidence wrong: %+v", d.Result)
	}
}

func TestEvaluatePreflight_NonWindows(t *testing.T) {
	in := baseInput()
	in.Platform = "darwin"
	d := EvaluatePreflight(in)
	if d.Proceed || d.Result.ErrorCode != ErrUnsupportedPlatform {
		t.Errorf("non-windows must be unsupported: %+v", d)
	}
}

func TestEvaluatePreflight_Noop(t *testing.T) {
	in := baseInput()
	in.Payload.TargetVersion = "1.0.0"
	d := EvaluatePreflight(in)
	if !d.Noop || d.Result.StageStatus != StageNoopCurrent {
		t.Errorf("equal version must be noop: %+v", d)
	}
}

func TestEvaluatePreflight_DowngradeRefused(t *testing.T) {
	in := baseInput()
	in.Payload.TargetVersion = "0.9.0"
	d := EvaluatePreflight(in)
	if d.Proceed || d.Result.ErrorCode != ErrVersionDowngrade {
		t.Errorf("downgrade must be refused: %+v", d)
	}
}

func TestEvaluatePreflight_BadURLRefused(t *testing.T) {
	in := baseInput()
	in.Payload.BinaryURL = "https://evil.example/agent.exe"
	d := EvaluatePreflight(in)
	if d.Proceed || d.Result.ErrorCode != ErrURLRejected {
		t.Errorf("off-allowlist url must be refused: %+v", d)
	}
}

// TestEvaluatePreflight_LabConsentInPayloadIgnored is THE security invariant:
// a backend payload that sets acceptLabOnlySigning=true on a LAB_ONLY_EVIDENCE
// release does NOT obtain lab consent — only a LOCAL opt-in can (Codex
// 019e94fd). A compromised backend cannot self-authorize a lab-tier update.
func TestEvaluatePreflight_LabConsentInPayloadIgnored(t *testing.T) {
	in := baseInput()
	in.Payload.SigningTier = TierLabOnlyEvidence
	in.Payload.ClaimedAcceptLabOnly = true // payload tries to consent
	in.TierPolicy = TierPolicy{AllowLabOnly: false}
	d := EvaluatePreflight(in)
	if d.Proceed || d.Result.ErrorCode != ErrLabTierRefused {
		t.Errorf("payload acceptLabOnlySigning must NOT grant lab consent: %+v", d)
	}
}

// TestEvaluatePreflight_LabLocalOptInOnNonDomain confirms the ONLY lab path:
// a LOCAL opt-in on a non-domain-joined host.
func TestEvaluatePreflight_LabLocalOptInOnNonDomain(t *testing.T) {
	in := baseInput()
	in.Payload.SigningTier = TierLabOnlyEvidence
	in.TierPolicy = TierPolicy{AllowLabOnly: true, DomainJoined: false}
	d := EvaluatePreflight(in)
	if !d.Proceed {
		t.Errorf("local opt-in on non-domain host must proceed: %+v", d)
	}
}

// TestEvaluatePreflight_OrderTierBeforeVersion pins the evaluation order: a
// payload that is BOTH lab-refused AND a downgrade fails on tier first.
func TestEvaluatePreflight_OrderTierBeforeVersion(t *testing.T) {
	in := baseInput()
	in.CurrentVersion = "2.0.0"
	in.Payload.SigningTier = TierLabOnlyEvidence // refused (no opt-in)
	in.Payload.TargetVersion = "1.0.0"           // also a downgrade
	in.TierPolicy = TierPolicy{}
	d := EvaluatePreflight(in)
	if d.Result.ErrorCode != ErrLabTierRefused {
		t.Errorf("tier must be evaluated before version, got %q", d.Result.ErrorCode)
	}
}
