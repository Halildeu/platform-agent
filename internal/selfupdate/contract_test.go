package selfupdate

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestValidateShape(t *testing.T) {
	ok := UpdateAgentPayload{TargetVersion: "1.2.3", BinaryURL: "https://github.com/x", ClaimedSha256: "abc", SigningTier: TierTrusted}
	if code, _ := ok.ValidateShape(); code != "" {
		t.Errorf("valid payload rejected: %q", code)
	}
	cases := []struct {
		name string
		p    UpdateAgentPayload
		code ErrorCode
	}{
		{"missing target", UpdateAgentPayload{BinaryURL: "https://x", ClaimedSha256: "a", SigningTier: TierTrusted}, ErrVersionUnparseable},
		{"missing url", UpdateAgentPayload{TargetVersion: "1.0.0", ClaimedSha256: "a", SigningTier: TierTrusted}, ErrURLRejected},
		{"missing sha", UpdateAgentPayload{TargetVersion: "1.0.0", BinaryURL: "https://x", SigningTier: TierTrusted}, ErrHashMismatch},
		{"unknown tier", UpdateAgentPayload{TargetVersion: "1.0.0", BinaryURL: "https://x", ClaimedSha256: "a", SigningTier: SigningTier("X")}, ErrLabTierRefused},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if code, _ := c.p.ValidateShape(); code != c.code {
				t.Errorf("got %q want %q", code, c.code)
			}
		})
	}
}

// TestStageResult_NoPathOnWire pins Codex 019e94fd checklist #5: the wire
// result must carry opaque correlation handles + bounded evidence, never a
// filesystem path.
func TestStageResult_NoPathOnWire(t *testing.T) {
	r := StageResult{
		StageStatus:            StageReady,
		StagingID:              "req-123",
		ActivationPlanID:       "plan-123",
		OldVersion:             "1.0.0",
		TargetVersion:          "1.1.0",
		ActualSha256:           "deadbeef",
		ActualSignerThumbprint: "ABCDEF",
		SigningTier:            TierTrusted,
		Reason:                 "preflight policy clean",
	}
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	low := strings.ToLower(string(b))
	for _, forbidden := range []string{"path", "stagedpath", "c:\\", "programdata"} {
		if strings.Contains(low, forbidden) {
			t.Errorf("StageResult wire JSON leaks %q: %s", forbidden, b)
		}
	}
}

func TestStageResult_JSONRoundTrip(t *testing.T) {
	in := StageResult{StageStatus: StageFailed, ErrorCode: ErrSignerNotAllowed, TargetVersion: "1.1.0", Reason: "x"}
	b, _ := json.Marshal(in)
	var out StageResult
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out.StageStatus != in.StageStatus || out.ErrorCode != in.ErrorCode || out.TargetVersion != in.TargetVersion {
		t.Errorf("round-trip mismatch: %+v vs %+v", in, out)
	}
}

func TestErrorCodeSetStable(t *testing.T) {
	codes := AllErrorCodes()
	if len(codes) != 15 {
		t.Fatalf("expected 15 error codes, got %d", len(codes))
	}
	seen := map[ErrorCode]bool{}
	for _, c := range codes {
		if seen[c] {
			t.Errorf("duplicate error code %q", c)
		}
		seen[c] = true
		if !IsKnownErrorCode(c) {
			t.Errorf("IsKnownErrorCode(%q) = false", c)
		}
		if !strings.HasPrefix(string(c), "POLICY_") && !isOperationalCode(c) {
			t.Errorf("unexpected error code shape %q", c)
		}
	}
	if IsKnownErrorCode("BOGUS_CODE") {
		t.Errorf("IsKnownErrorCode(BOGUS_CODE) = true")
	}
}

func isOperationalCode(c ErrorCode) bool {
	switch c {
	case ErrDownloadFailed, ErrDownloadTooLarge, ErrHashMismatch, ErrSignatureInvalid,
		ErrSignerNotAllowed, ErrCatalogMismatch, ErrCredentialPreflight, ErrStagingIO, ErrActivationPlanWrite:
		return true
	}
	return false
}

func TestIsKnownTier(t *testing.T) {
	if !IsKnownTier(TierTrusted) || !IsKnownTier(TierLabOnlyEvidence) {
		t.Errorf("known tiers misreported")
	}
	if IsKnownTier(SigningTier("NOPE")) {
		t.Errorf("unknown tier reported as known")
	}
}
