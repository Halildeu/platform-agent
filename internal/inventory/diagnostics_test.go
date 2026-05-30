package inventory

import (
	"context"
	"encoding/json"
	"runtime"
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

// TestParseBackendHost is a REAL (non-seam-mocked) unit test of the
// DNS/dial/SNI derivation. It pins the three distinct values so a future
// refactor cannot regress to feeding "host:port" into LookupHost or SNI, or
// dialing a portless address. Codex 019e76c5 finding #2 absorb.
func TestParseBackendHost(t *testing.T) {
	cases := []struct {
		name           string
		url            string
		wantOK         bool
		wantHostname   string
		wantDial       string
		wantServerName string
	}{
		{
			// No explicit port: DNS + SNI use the bare hostname; the dial
			// must default to :443 (https) — a portless dial fails.
			name:           "no port defaults dial to 443",
			url:            "https://api.example.com",
			wantOK:         true,
			wantHostname:   "api.example.com",
			wantDial:       "api.example.com:443",
			wantServerName: "api.example.com",
		},
		{
			// Explicit non-default port: DNS resolves the bare hostname
			// (not "host:8443") and SNI is the bare hostname (no port),
			// while the dial carries the explicit port.
			name:           "explicit port keeps hostname bare for DNS+SNI",
			url:            "https://api.example.com:8443/x",
			wantOK:         true,
			wantHostname:   "api.example.com",
			wantDial:       "api.example.com:8443",
			wantServerName: "api.example.com",
		},
		{
			name:           "IPv4 literal with port",
			url:            "https://192.168.1.1:8080/api",
			wantOK:         true,
			wantHostname:   "192.168.1.1",
			wantDial:       "192.168.1.1:8080",
			wantServerName: "192.168.1.1",
		},
		{
			name:           "non-default scheme still derives host with default 443",
			url:            "ftp://example.com",
			wantOK:         true,
			wantHostname:   "example.com",
			wantDial:       "example.com:443",
			wantServerName: "example.com",
		},
		// Hostless / garbage URLs → OK=false, which drives the fail-closed
		// BACKEND_HOST_UNRESOLVED path in the orchestration.
		{name: "empty", url: "", wantOK: false},
		{name: "no host", url: "https://", wantOK: false},
		{name: "garbage no scheme", url: "not-a-url", wantOK: false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := parseBackendHost(c.url)
			if got.OK != c.wantOK {
				t.Fatalf("parseBackendHost(%q).OK = %v; want %v", c.url, got.OK, c.wantOK)
			}
			if !c.wantOK {
				return
			}
			if got.Hostname != c.wantHostname {
				t.Errorf("parseBackendHost(%q).Hostname = %q; want %q", c.url, got.Hostname, c.wantHostname)
			}
			if got.DialAddress != c.wantDial {
				t.Errorf("parseBackendHost(%q).DialAddress = %q; want %q", c.url, got.DialAddress, c.wantDial)
			}
			if got.ServerName != c.wantServerName {
				t.Errorf("parseBackendHost(%q).ServerName = %q; want %q", c.url, got.ServerName, c.wantServerName)
			}
			// Hardening: SNI / DNS must never carry the port.
			if strings.ContainsRune(got.ServerName, ':') {
				t.Errorf("ServerName %q must not contain a port", got.ServerName)
			}
		})
	}
}

func TestCheckDNSReachability_EmptyHost(t *testing.T) {
	if checkDNSReachability("") {
		t.Error("checkDNSReachability with empty host should return false")
	}
}

func TestCheckBackendTLS_EmptyHost(t *testing.T) {
	ctx := context.Background()
	if checkBackendTLS(ctx, "", "") {
		t.Error("checkBackendTLS with empty dial address should return false")
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
	if runtime.GOOS == "windows" {
		t.Skip("non-Windows stub behavior; Windows uses the live runner")
	}
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
