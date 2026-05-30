//go:build windows

package inventory

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestDiagnosticsProbeResultSchemaVersion(t *testing.T) {
	result := runDiagnosticsProbeReal(context.Background(), "https://api.example.com", "1.0.0")
	if result.SchemaVersion != DiagnosticsSchemaVersion {
		t.Errorf("SchemaVersion = %d; want %d", result.SchemaVersion, DiagnosticsSchemaVersion)
	}
}

func TestDiagnosticsProbeResultSupported(t *testing.T) {
	result := runDiagnosticsProbeReal(context.Background(), "https://api.example.com", "1.0.0")
	if !result.Supported {
		t.Error("Supported should be true on Windows")
	}
}

func TestDiagnosticsProbeResultConfigHashNotEmpty(t *testing.T) {
	result := runDiagnosticsProbeReal(context.Background(), "https://api.example.com", "1.0.0")
	if result.ConfigHash == "" || result.ConfigHash == "unknown" {
		t.Errorf("ConfigHash = %q; want non-empty", result.ConfigHash)
	}
}

func TestDiagnosticsProbeResultConfigHashStable(t *testing.T) {
	r1 := runDiagnosticsProbeReal(context.Background(), "https://api.example.com", "1.0.0")
	r2 := runDiagnosticsProbeReal(context.Background(), "https://api.example.com", "1.0.0")
	if r1.ConfigHash != r2.ConfigHash {
		t.Errorf("ConfigHash not stable: %q vs %q", r1.ConfigHash, r2.ConfigHash)
	}
}

func TestDiagnosticsProbeResultConfigHashDiffersByVersion(t *testing.T) {
	r1 := runDiagnosticsProbeReal(context.Background(), "https://api.example.com", "1.0.0")
	r2 := runDiagnosticsProbeReal(context.Background(), "https://api.example.com", "2.0.0")
	if r1.ConfigHash == r2.ConfigHash {
		t.Error("ConfigHash should differ between versions")
	}
}

func TestDiagnosticsProbeResultProbeDurationMs(t *testing.T) {
	result := runDiagnosticsProbeReal(context.Background(), "https://api.example.com", "1.0.0")
	if result.ProbeDurationMs <= 0 {
		t.Errorf("ProbeDurationMs = %d; want > 0", result.ProbeDurationMs)
	}
}

func TestDiagnosticsProbeResultLastErrorNil(t *testing.T) {
	result := runDiagnosticsProbeReal(context.Background(), "https://api.example.com", "1.0.0")
	if result.LastError != nil {
		t.Errorf("LastError = %+v; want nil", result.LastError)
	}
}

func TestDiagnosticsProbeResultProbeErrorsEmpty(t *testing.T) {
	result := runDiagnosticsProbeReal(context.Background(), "https://api.example.com", "1.0.0")
	if len(result.ProbeErrors) != 0 {
		t.Errorf("ProbeErrors = %v; want empty", result.ProbeErrors)
	}
}

func TestRunDiagnosticsProbeReal_PollLatency(t *testing.T) {
	orig := getLastPollLatencyMs
	t.Cleanup(func() { getLastPollLatencyMs = orig })

	getLastPollLatencyMs = func() int { return 999 }

	result := runDiagnosticsProbeReal(context.Background(), "https://api.example.com", "1.0.0")
	if result.LastPollLatencyMs != 999 {
		t.Errorf("LastPollLatencyMs = %d; want 999", result.LastPollLatencyMs)
	}

	getLastPollLatencyMs = func() int { return 0 }
}

func TestRunDiagnosticsProbeReal_ProbeCompleteTrue(t *testing.T) {
	result := runDiagnosticsProbeReal(context.Background(), "https://api.example.com", "1.0.0")
	if !result.ProbeComplete {
		t.Error("ProbeComplete should be true when no errors")
	}
}

func TestRunDiagnosticsProbeReal_InvalidURLNoCrash(t *testing.T) {
	// Should not panic even with unparseable URL; host becomes ""
	result := runDiagnosticsProbeReal(context.Background(), "://invalid", "1.0.0")
	if result.SchemaVersion != DiagnosticsSchemaVersion {
		t.Errorf("SchemaVersion = %d; want %d", result.SchemaVersion, DiagnosticsSchemaVersion)
	}
	if result.ProbeComplete {
		t.Error("ProbeComplete should be false when URL unparseable (no host)")
	}
}

func TestProbeDiagnostics_NilCtx(t *testing.T) {
	result := ProbeDiagnostics(nil, time.Now)
	if result.SchemaVersion != DiagnosticsSchemaVersion {
		t.Errorf("SchemaVersion = %d; want %d", result.SchemaVersion, DiagnosticsSchemaVersion)
	}
	if !result.Supported {
		t.Error("Supported should be true on Windows")
	}
}

func TestProbeDiagnostics_NilNow(t *testing.T) {
	result := ProbeDiagnostics(context.Background(), nil)
	if result.ProbeDurationMs <= 0 {
		t.Errorf("ProbeDurationMs = %d; want > 0", result.ProbeDurationMs)
	}
}

func TestRunDiagnosticsProbeReal_GetProbeConfigSeam(t *testing.T) {
	orig := getProbeConfig
	t.Cleanup(func() { getProbeConfig = orig })

	getProbeConfig = func() probeConfig {
		return probeConfig{
			AgentVersion: "9.9.9-test",
			APIURL:       "https://diag.test.local",
			CredentialID: "cred-id-should-not-appear-on-wire",
		}
	}

	result := runDiagnosticsProbeReal(context.Background(), "https://api.example.com", "1.0.0")
	if result.AgentVersion != "9.9.9-test" {
		t.Errorf("AgentVersion = %q; want %q", result.AgentVersion, "9.9.9-test")
	}
	// Verify credentialID does NOT appear in JSON output
	bytes, _ := json.Marshal(result)
	if containsStr(string(bytes), "cred-id-should-not-appear-on-wire") {
		t.Error("JSON output contains credentialID — wire boundary violation")
	}
}

func TestRunDiagnosticsProbeReal_EmptyAPIURL(t *testing.T) {
	orig := getProbeConfig
	t.Cleanup(func() { getProbeConfig = orig })

	getProbeConfig = func() probeConfig {
		return probeConfig{
			AgentVersion: "1.0.0",
			APIURL:       "",
		}
	}

	result := runDiagnosticsProbeReal(context.Background(), "", "1.0.0")
	// Empty API URL → no host → DNS/TLS checks skipped, but probe still completes
	if result.ProbeComplete {
		t.Error("ProbeComplete should be false when no host (empty API URL)")
	}
}

func TestDiagnosticsResult_LastErrorOnNil(t *testing.T) {
	result := runDiagnosticsProbeReal(context.Background(), "https://api.example.com", "1.0.0")
	if result.LastError != nil {
		t.Errorf("LastError = %+v; want nil", result.LastError)
	}
}

func containsStr(s, substr string) bool {
	return len(s) > 0 && len(substr) > 0 && len(s) >= len(substr) &&
		(strings.Contains(s, substr) || len(s) > 0 && containsSubstr(s, substr))
}

func containsSubstr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}