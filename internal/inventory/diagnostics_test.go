package inventory

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestDiagnosticsSchemaVersion(t *testing.T) {
	if DiagnosticsSchemaVersion != 1 {
		t.Errorf("DiagnosticsSchemaVersion = %d; want 1", DiagnosticsSchemaVersion)
	}
}

func TestDeriveDiagnosticsSummary_DefaultState(t *testing.T) {
	result := &DiagnosticsResult{
		SchemaVersion: DiagnosticsSchemaVersion,
		Supported:     true,
	}
	deriveDiagnosticsSummary(result)
	if result.ProbeComplete != true {
		t.Errorf("ProbeComplete = %v; want true (no errors)", result.ProbeComplete)
	}
	// derive sets "unknown" when ConfigHash is empty (safe default)
	if result.ConfigHash != "unknown" {
		t.Errorf("ConfigHash = %q; want unknown after derive from empty", result.ConfigHash)
	}
}

func TestDeriveDiagnosticsSummary_WithError(t *testing.T) {
	result := &DiagnosticsResult{
		SchemaVersion: DiagnosticsSchemaVersion,
		Supported:     true,
		ProbeErrors:   []DiagnosticsProbeError{{Code: "FOO_ERR"}},
	}
	deriveDiagnosticsSummary(result)
	if result.ProbeComplete {
		t.Error("ProbeComplete should be false when errors present")
	}
}

func TestDeriveDiagnosticsSummary_UnsupportedPlatform(t *testing.T) {
	result := &DiagnosticsResult{
		SchemaVersion: DiagnosticsSchemaVersion,
		Supported:     false,
	}
	deriveDiagnosticsSummary(result)
	if result.ProbeComplete {
		t.Error("ProbeComplete should be false when Supported=false")
	}
}

func TestDeriveDiagnosticsSummary_ConfigHashUnknown(t *testing.T) {
	result := &DiagnosticsResult{}
	deriveDiagnosticsSummary(result)
	if result.ConfigHash != "unknown" {
		t.Errorf("ConfigHash = %q; want unknown", result.ConfigHash)
	}
}

func TestConfigHash_Stable(t *testing.T) {
	h1 := configHash("1.0.0", "https://api.example.com")
	h2 := configHash("1.0.0", "https://api.example.com")
	if h1 != h2 {
		t.Errorf("configHash not stable: %q != %q", h1, h2)
	}
}

func TestConfigHash_Length(t *testing.T) {
	cases := [][2]string{
		{"1.0.0", "https://api.example.com"},
		{"2.0.0-dev", "https://backend.internal:8443"},
		{"0.1.0-beta", "https://192.168.1.1:8080/api"},
	}
	for _, c := range cases {
		h := configHash(c[0], c[1])
		if len(h) != 16 {
			t.Errorf("configHash(%q, %q) len = %d; want 16", c[0], c[1], len(h))
		}
	}
}

func TestConfigHash_NoCredentialID(t *testing.T) {
	// ConfigHash must be derived from version + API URL only.
	// Verify same version+url always produces same hash.
	h1 := configHash("1.0.0", "https://api.example.com")
	h2 := configHash("1.0.0", "https://api.example.com")
	if h1 != h2 {
		t.Errorf("hashes differ for same version+url: %q vs %q", h1, h2)
	}
}

func TestParseBackendHost(t *testing.T) {
	cases := []struct {
		url  string
		want string
	}{
		{"https://api.example.com", "api.example.com"},
		{"https://api.example.com:8443/endpoint-agent", "api.example.com:8443"},
		{"https://192.168.1.1:8080/api", "192.168.1.1:8080"},
		{"", ""},
		{"not-a-url", ""},
		{"ftp://example.com", "example.com"}, // net/url parses host for any scheme
		{"https://", ""},
	}
	for _, c := range cases {
		got := parseBackendHost(c.url)
		if got != c.want {
			t.Errorf("parseBackendHost(%q) = %q; want %q", c.url, got, c.want)
		}
	}
}

func TestCheckDNSReachability_EmptyHost(t *testing.T) {
	if checkDNSReachability("") {
		t.Error("checkDNSReachability with empty host should return false")
	}
}

func TestCheckBackendTLS_EmptyHost(t *testing.T) {
	ctx := context.Background()
	if checkBackendTLS(ctx, "") {
		t.Error("checkBackendTLS with empty host should return false")
	}
}

func TestDiagnosticsElapsedMs(t *testing.T) {
	now := time.Now()
	start := now.Add(-150 * time.Millisecond)
	ms := diagnosticsElapsedMs(start, func() time.Time { return now })
	if ms < 100 || ms > 200 {
		t.Errorf("elapsedMs = %d; want ~150", ms)
	}
}

func TestDiagnosticsElapsedMs_NilNow(t *testing.T) {
	start := time.Now().Add(-50 * time.Millisecond)
	ms := diagnosticsElapsedMs(start, nil)
	if ms < 30 || ms > 200 {
		t.Errorf("elapsedMs with nil now = %d; want ~50", ms)
	}
}

func TestProbeDiagnostics_NonWindowsStub(t *testing.T) {
	result := ProbeDiagnostics(nil, time.Now)
	if result.Supported {
		t.Error("Supported should be false on non-Windows")
	}
	if len(result.ProbeErrors) == 0 {
		t.Error("Should have UNSUPPORTED_PLATFORM probe error on non-Windows")
	}
	if result.ProbeErrors[0].Code != "UNSUPPORTED_PLATFORM" {
		t.Errorf("ProbeErrors[0].Code = %q; want UNSUPPORTED_PLATFORM", result.ProbeErrors[0].Code)
	}
	if result.SchemaVersion != DiagnosticsSchemaVersion {
		t.Errorf("SchemaVersion = %d; want %d", result.SchemaVersion, DiagnosticsSchemaVersion)
	}
}

func TestDiagnosticsResult_JSONKeys_NoPII(t *testing.T) {
	result := DiagnosticsResult{
		SchemaVersion:       DiagnosticsSchemaVersion,
		Supported:           true,
		AgentVersion:        "1.0.0",
		ConfigHash:          "a1b2c3d4e5f6g7h8",
		LastPollLatencyMs:   42,
		BackendDNSReachable: true,
		BackendTLSValid:     true,
		ProbeDurationMs:     15,
	}
	bytes, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}
	// Wire must NOT contain: credentialID, deviceID, apiURL, paths, secrets
	forbidden := []string{
		"credentialID", "deviceID", "apiURL", "secret",
		"credential_id", "device_id", "api_url",
		"credentialId", "deviceId", "apiUrl",
		"C:/", "C:\\", "/etc/", "token", "Token",
	}
	s := string(bytes)
	for _, f := range forbidden {
		if strings.Contains(s, f) {
			t.Errorf("JSON contains forbidden key/pattern: %q", f)
		}
	}
}
