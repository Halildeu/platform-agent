package config

import (
	"os"
	"testing"
	"time"
)

func TestLoadFromEnvOverridesDefaults(t *testing.T) {
	t.Setenv("ENDPOINT_AGENT_API_URL", "https://agent.example.test/api/")
	t.Setenv("ENDPOINT_AGENT_CREDENTIAL_ID", "cred-1")
	t.Setenv("ENDPOINT_AGENT_SECRET", "secret")
	t.Setenv("ENDPOINT_AGENT_DEVICE_ID", "device-1")
	t.Setenv("ENDPOINT_AGENT_LOG_DIR", "/tmp/endpoint-agent-test-logs")
	t.Setenv("ENDPOINT_AGENT_HEARTBEAT_INTERVAL", "15s")
	t.Setenv("ENDPOINT_AGENT_JITTER_PERCENT", "12")

	cfg := LoadFromEnv()

	if cfg.APIURL != "https://agent.example.test/api" {
		t.Fatalf("APIURL = %q", cfg.APIURL)
	}
	if cfg.CredentialID != "cred-1" || cfg.Secret != "secret" || cfg.DeviceID != "device-1" {
		t.Fatalf("device identity not loaded: %#v", cfg)
	}
	if cfg.HeartbeatInterval != 15*time.Second {
		t.Fatalf("HeartbeatInterval = %s", cfg.HeartbeatInterval)
	}
	if cfg.LogDir != "/tmp/endpoint-agent-test-logs" {
		t.Fatalf("LogDir = %q", cfg.LogDir)
	}
	if cfg.JitterPercent != 12 {
		t.Fatalf("JitterPercent = %d", cfg.JitterPercent)
	}
}

func TestLoadFromEnvSigningPathPrefix(t *testing.T) {
	t.Setenv("ENDPOINT_AGENT_SIGNING_PATH_PREFIX", "/api/v1/agent")
	cfg := LoadFromEnv()
	if cfg.SigningPathPrefix != "/api/v1/agent" {
		t.Fatalf("SigningPathPrefix = %q", cfg.SigningPathPrefix)
	}
}

func TestLoadFromEnv_AutoEnrollOverrides(t *testing.T) {
	t.Setenv("ENDPOINT_AGENT_AUTO_ENROLL_API_URL", "https://mtls.testai.acik.com/api/v1/endpoint-agent/")
	t.Setenv("ENDPOINT_AGENT_AUTO_ENROLL_CONFIG_PATH", `C:\ProgramData\EndpointAgent\config\auto-enroll.dpapi`)
	t.Setenv("ENDPOINT_AGENT_AUTO_ENROLL_CERT_SUBJECT_SUFFIX", ".acik.local")
	t.Setenv("ENDPOINT_AGENT_AUTO_ENROLL_CERT_SAN_URI_PREFIX", "adcomputer:")

	cfg := LoadFromEnv()
	if cfg.AutoEnrollAPIURL != "https://mtls.testai.acik.com/api/v1/endpoint-agent" {
		t.Fatalf("AutoEnrollAPIURL = %q (trailing slash should be trimmed)", cfg.AutoEnrollAPIURL)
	}
	if cfg.AutoEnrollConfigPath != `C:\ProgramData\EndpointAgent\config\auto-enroll.dpapi` {
		t.Fatalf("AutoEnrollConfigPath = %q", cfg.AutoEnrollConfigPath)
	}
	if cfg.AutoEnrollCertSubjectSuffix != ".acik.local" {
		t.Fatalf("AutoEnrollCertSubjectSuffix = %q", cfg.AutoEnrollCertSubjectSuffix)
	}
	if cfg.AutoEnrollCertSANURIPrefix != "adcomputer:" {
		t.Fatalf("AutoEnrollCertSANURIPrefix = %q", cfg.AutoEnrollCertSANURIPrefix)
	}
}

func TestLoadFromEnv_AutoEnrollDefaultsEmpty(t *testing.T) {
	// An explicit blank is an operator-controlled fail-closed disable and must
	// not be replaced by the managed self-update migration fallback.
	t.Setenv("ENDPOINT_AGENT_AUTO_ENROLL_API_URL", "")
	cfg := LoadFromEnv()
	if cfg.AutoEnrollAPIURL != "" {
		t.Fatalf("expected explicit blank AutoEnrollAPIURL to remain empty, got %q", cfg.AutoEnrollAPIURL)
	}
}

func TestLoadFromEnv_MigratesKnownManagedEndpointTPMRenewalPolicy(t *testing.T) {
	unsetEnvForTest(t, "ENDPOINT_AGENT_AUTO_ENROLL_API_URL")
	unsetEnvForTest(t, "ENDPOINT_AGENT_AUTO_ENROLL_CERT_SUBJECT_SUFFIX")
	unsetEnvForTest(t, "ENDPOINT_AGENT_AUTO_ENROLL_CERT_SAN_URI_PREFIX")
	t.Setenv("ENDPOINT_AGENT_API_URL", "https://testai.acik.com/api/v1/endpoint-agent")

	cfg := LoadFromEnv()

	if cfg.AutoEnrollAPIURL != "https://testai.acik.com/api/v1/endpoint-agent" {
		t.Fatalf("AutoEnrollAPIURL = %q", cfg.AutoEnrollAPIURL)
	}
	if cfg.AutoEnrollCertSANURIPrefix != "adcomputer:" {
		t.Fatalf("AutoEnrollCertSANURIPrefix = %q", cfg.AutoEnrollCertSANURIPrefix)
	}
}

func TestManagedTPMRenewalFallbackIsBoundedAndFailClosed(t *testing.T) {
	tests := []struct {
		name       string
		apiURL     string
		wantURL    string
		wantPrefix string
		wantOK     bool
	}{
		{
			name:       "test",
			apiURL:     "https://testai.acik.com/api/v1/endpoint-agent",
			wantURL:    "https://testai.acik.com/api/v1/endpoint-agent",
			wantPrefix: "adcomputer:",
			wantOK:     true,
		},
		{
			name:       "production",
			apiURL:     "https://ai.acik.com/api/v1/endpoint-agent",
			wantURL:    "https://ai.acik.com/api/v1/endpoint-agent",
			wantPrefix: "adcomputer:",
			wantOK:     true,
		},
		{name: "unknown tenant", apiURL: "https://customer.example/api/v1/endpoint-agent"},
		{name: "plaintext", apiURL: "http://testai.acik.com/api/v1/endpoint-agent"},
		{name: "unexpected path", apiURL: "https://testai.acik.com/api/v2/endpoint-agent"},
		{name: "userinfo", apiURL: "https://user@testai.acik.com/api/v1/endpoint-agent"},
		{name: "query", apiURL: "https://testai.acik.com/api/v1/endpoint-agent?unsafe=1"},
		{name: "custom port", apiURL: "https://testai.acik.com:8443/api/v1/endpoint-agent"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotURL, gotPrefix, gotOK := managedTPMRenewalFallback(tc.apiURL)
			if gotURL != tc.wantURL || gotPrefix != tc.wantPrefix || gotOK != tc.wantOK {
				t.Fatalf("managedTPMRenewalFallback(%q) = (%q, %q, %t), want (%q, %q, %t)",
					tc.apiURL, gotURL, gotPrefix, gotOK, tc.wantURL, tc.wantPrefix, tc.wantOK)
			}
		})
	}
}

func TestTPMRenewalAPIURLPrefersCertificateLessProductOrigin(t *testing.T) {
	cfg := Config{
		APIURL:           "https://testai.acik.com/api/v1/endpoint-agent",
		AutoEnrollAPIURL: "https://mtls.testai.acik.com/api/v1/endpoint-agent",
	}
	if got := cfg.TPMRenewalAPIURL(); got != cfg.APIURL {
		t.Fatalf("TPMRenewalAPIURL() = %q, want %q", got, cfg.APIURL)
	}
}

func TestTPMRenewalAPIURLFallsBackToAutoEnrollOrigin(t *testing.T) {
	cfg := Config{
		APIURL:           "https://localhost:8080/api/v1/agent",
		AutoEnrollAPIURL: "https://bootstrap.customer.example/api/v1/endpoint-agent/",
	}
	if got := cfg.TPMRenewalAPIURL(); got != "https://bootstrap.customer.example/api/v1/endpoint-agent" {
		t.Fatalf("TPMRenewalAPIURL() = %q", got)
	}
}

func unsetEnvForTest(t *testing.T, key string) {
	t.Helper()
	previous, existed := os.LookupEnv(key)
	if err := os.Unsetenv(key); err != nil {
		t.Fatalf("unset %s: %v", key, err)
	}
	t.Cleanup(func() {
		if existed {
			_ = os.Setenv(key, previous)
			return
		}
		_ = os.Unsetenv(key)
	})
}

// AG-027 (Codex 019e6c0d iter-2 absorb) — INSTALL_SOFTWARE needs a
// longer effective timeout than the lightweight 120s default
// CommandTimeout. Default ships at 30 min; the env override is
// honoured.
func TestDefault_InstallCommandTimeoutIs30Minutes(t *testing.T) {
	cfg := Default()
	want := 30 * time.Minute
	if cfg.InstallCommandTimeout != want {
		t.Fatalf("InstallCommandTimeout default = %s, want %s",
			cfg.InstallCommandTimeout, want)
	}
}

func TestLoadFromEnv_InstallCommandTimeoutEnvOverride(t *testing.T) {
	t.Setenv("ENDPOINT_AGENT_INSTALL_COMMAND_TIMEOUT", "45m")
	cfg := LoadFromEnv()
	if cfg.InstallCommandTimeout != 45*time.Minute {
		t.Fatalf("InstallCommandTimeout = %s, want 45m", cfg.InstallCommandTimeout)
	}
}

func TestLoadFromEnv_SelfUpdatePolicy(t *testing.T) {
	t.Setenv("ENDPOINT_AGENT_SELF_UPDATE_ENABLED", "true")
	t.Setenv("ENDPOINT_AGENT_SELF_UPDATE_ALLOWED_HOSTS", "github.com, objects.githubusercontent.com ")
	t.Setenv("ENDPOINT_AGENT_SELF_UPDATE_SIGNER_THUMBPRINTS", "AA:BB,ccddee")
	t.Setenv("ENDPOINT_AGENT_SELF_UPDATE_ALLOW_LAB_ONLY_SIGNING", "1")
	t.Setenv("ENDPOINT_AGENT_SELF_UPDATE_HARD_MAX_BYTES", "12345")
	t.Setenv("ENDPOINT_AGENT_SELF_UPDATE_MAX_REDIRECTS", "4")
	t.Setenv("ENDPOINT_AGENT_SELF_UPDATE_COMMAND_TIMEOUT", "40m")
	t.Setenv("ENDPOINT_AGENT_SELF_UPDATE_AUTO_ACTIVATE", "true")
	t.Setenv("ENDPOINT_AGENT_SELF_UPDATE_ACTIVATION_TIMEOUT", "3m")
	t.Setenv("ENDPOINT_AGENT_SELF_UPDATE_SERVICE_NAME", "EndpointAgentTest")

	cfg := LoadFromEnv()

	if !cfg.SelfUpdateEnabled || !cfg.SelfUpdateAllowLabOnlySigning {
		t.Fatalf("self-update bool env not loaded: %#v", cfg)
	}
	if len(cfg.SelfUpdateAllowedHosts) != 2 || cfg.SelfUpdateAllowedHosts[1] != "objects.githubusercontent.com" {
		t.Fatalf("SelfUpdateAllowedHosts = %#v", cfg.SelfUpdateAllowedHosts)
	}
	if len(cfg.SelfUpdateSignerThumbprints) != 2 || cfg.SelfUpdateSignerThumbprints[0] != "AA:BB" {
		t.Fatalf("SelfUpdateSignerThumbprints = %#v", cfg.SelfUpdateSignerThumbprints)
	}
	if cfg.SelfUpdateHardMaxBytes != 12345 || cfg.SelfUpdateMaxRedirects != 4 {
		t.Fatalf("self-update numeric policy not loaded: maxBytes=%d redirects=%d", cfg.SelfUpdateHardMaxBytes, cfg.SelfUpdateMaxRedirects)
	}
	if cfg.SelfUpdateCommandTimeout != 40*time.Minute {
		t.Fatalf("SelfUpdateCommandTimeout = %s", cfg.SelfUpdateCommandTimeout)
	}
	if !cfg.SelfUpdateAutoActivate || cfg.SelfUpdateActivationTimeout != 3*time.Minute || cfg.SelfUpdateServiceName != "EndpointAgentTest" {
		t.Fatalf("self-update activation env not loaded: auto=%t timeout=%s service=%q", cfg.SelfUpdateAutoActivate, cfg.SelfUpdateActivationTimeout, cfg.SelfUpdateServiceName)
	}
	if !cfg.SelfUpdateCapabilityEnabled() {
		t.Fatal("complete local self-update policy should enable capability advertisement")
	}
}

func TestSelfUpdateCapabilityRequiresLocalTrustPolicy(t *testing.T) {
	cfg := Default()
	cfg.SelfUpdateEnabled = true
	if cfg.SelfUpdateCapabilityEnabled() {
		t.Fatal("enabled=true alone must not advertise UPDATE_AGENT")
	}
	cfg.SelfUpdateAllowedHosts = []string{"github.com"}
	cfg.SelfUpdateSignerThumbprints = []string{"AABB"}
	if !cfg.SelfUpdateCapabilityEnabled() {
		t.Fatal("complete local policy should advertise UPDATE_AGENT")
	}
	cfg.SelfUpdateMaxRedirects = -1
	if cfg.SelfUpdateCapabilityEnabled() {
		t.Fatal("negative redirect cap must disable UPDATE_AGENT advertisement")
	}
}
