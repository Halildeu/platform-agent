package main

import (
	"testing"

	"platform-agent/internal/autoenroll"
	"platform-agent/internal/config"
)

// stubRegistry implements the small interface resolveAutoEnrollAPIURL
// reads from. Production code uses winregistry.New(); tests want a
// drop-in that can serve fixed values without touching HKLM.
type stubRegistry struct {
	intMap    map[string]int
	stringMap map[string]string
}

func (s stubRegistry) ReadInt(_, _ string, def int) int { return def }
func (s stubRegistry) ReadString(key, value, def string) string {
	if v, ok := s.stringMap[key+"|"+value]; ok {
		return v
	}
	return def
}

func TestHostnameOnly_AcceptsHTTPS(t *testing.T) {
	got, err := hostnameOnly("https://endpoint-agent-mtls.testai.acik.com/api/v1/endpoint-admin")
	if err != nil {
		t.Fatalf("hostnameOnly: %v", err)
	}
	if got != "endpoint-agent-mtls.testai.acik.com" {
		t.Fatalf("got %q", got)
	}
}

func TestHostnameOnly_StripsPort(t *testing.T) {
	got, err := hostnameOnly("https://endpoint-agent-mtls.testai.acik.com:8443/api/v1/endpoint-admin")
	if err != nil {
		t.Fatalf("hostnameOnly: %v", err)
	}
	if got != "endpoint-agent-mtls.testai.acik.com" {
		t.Fatalf("got %q", got)
	}
}

func TestHostnameOnly_HandlesIPv6Brackets(t *testing.T) {
	got, err := hostnameOnly("https://[fd00::1]:8443/api")
	if err != nil {
		t.Fatalf("hostnameOnly: %v", err)
	}
	if got != "fd00::1" {
		t.Fatalf("got %q, want fd00::1 (brackets stripped)", got)
	}
}

func TestHostnameOnly_RejectsEmpty(t *testing.T) {
	if _, err := hostnameOnly(""); err == nil {
		t.Fatal("expected error for empty url")
	}
}

func TestHostnameOnly_RejectsNoHost(t *testing.T) {
	if _, err := hostnameOnly("/api/v1/endpoint-admin"); err == nil {
		t.Fatal("expected error for path-only url")
	}
}

func TestResolveAutoEnrollAPIURL_PrecedenceCLIFirst(t *testing.T) {
	cfg := config.Config{AutoEnrollAPIURL: "https://env.example/api"}
	reg := stubRegistry{stringMap: map[string]string{
		`HKLM:\SOFTWARE\EndpointAgent|ApiUrl`: "https://reg.example/api",
	}}
	got := resolveAutoEnrollAPIURL(cfg, "https://cli.example/api", reg, "https://baked.example/api")
	if got != "https://cli.example/api" {
		t.Fatalf("CLI should win: got %q", got)
	}
}

func TestResolveAutoEnrollAPIURL_PrecedenceEnvOverRegistry(t *testing.T) {
	cfg := config.Config{AutoEnrollAPIURL: "https://env.example/api"}
	reg := stubRegistry{stringMap: map[string]string{
		`HKLM:\SOFTWARE\EndpointAgent|ApiUrl`: "https://reg.example/api",
	}}
	got := resolveAutoEnrollAPIURL(cfg, "", reg, "https://baked.example/api")
	if got != "https://env.example/api" {
		t.Fatalf("env should beat registry: got %q", got)
	}
}

func TestResolveAutoEnrollAPIURL_PrecedenceRegistryOverBaked(t *testing.T) {
	cfg := config.Config{}
	reg := stubRegistry{stringMap: map[string]string{
		`HKLM:\SOFTWARE\EndpointAgent|ApiUrl`: "https://reg.example/api",
	}}
	got := resolveAutoEnrollAPIURL(cfg, "", reg, "https://baked.example/api")
	if got != "https://reg.example/api" {
		t.Fatalf("registry should beat baked: got %q", got)
	}
}

func TestResolveAutoEnrollAPIURL_BakedFallback(t *testing.T) {
	cfg := config.Config{}
	reg := stubRegistry{}
	got := resolveAutoEnrollAPIURL(cfg, "", reg, "https://baked.example/api")
	if got != "https://baked.example/api" {
		t.Fatalf("baked default should win when nothing else set: got %q", got)
	}
}

func TestResolveMode_FlagWins(t *testing.T) {
	if got := resolveMode(true, false, config.Config{}); got != modeAutoEnroll {
		t.Fatalf("flag should win: got %q", got)
	}
}

func TestResolveMode_FlagOffNoRegistry(t *testing.T) {
	// On non-Windows, registry.Reader returns def for ReadString, so the
	// fallback is HMAC mode.
	if got := resolveMode(false, false, config.Config{}); got != modeHMAC {
		t.Fatalf("default should be HMAC: got %q", got)
	}
}

// #108 (live pilot MKR-A1): a stale Mode=auto-enroll registry value must not
// strand a fully-provisioned HMAC service config, while the legitimate
// MSI/auto-enroll flow (which ships ENDPOINT_AGENT_AUTO_ENROLL_API_URL) stays
// unaffected.
func TestDecideMode(t *testing.T) {
	hmac := config.Config{APIURL: "https://h/api", EnrollmentToken: "tok"}
	autoEnroll := config.Config{AutoEnrollAPIURL: "https://ae/api"}
	bothCreds := config.Config{APIURL: "https://h/api", EnrollmentToken: "tok", AutoEnrollAPIURL: "https://ae/api"}
	partialHMAC := config.Config{APIURL: "https://h/api"} // enrollment token missing

	cases := []struct {
		name    string
		flagSet bool
		regMode string
		cfg     config.Config
		want    string
	}{
		{"flag wins over everything", true, modeAutoEnroll, hmac, modeAutoEnroll},
		{"#108 stale regkey overridden by unambiguous HMAC config", false, modeAutoEnroll, hmac, modeHMAC},
		{"MSI auto-enroll honoured (auto-enroll URL present)", false, modeAutoEnroll, autoEnroll, modeAutoEnroll},
		{"ambiguous config (both creds) defers to regkey", false, modeAutoEnroll, bothCreds, modeAutoEnroll},
		{"incomplete HMAC config does not override regkey", false, modeAutoEnroll, partialHMAC, modeAutoEnroll},
		{"no creds at all honours stale regkey", false, modeAutoEnroll, config.Config{}, modeAutoEnroll},
		{"empty regkey is HMAC", false, "", hmac, modeHMAC},
		{"non-auto-enroll regkey is HMAC", false, "hmac", autoEnroll, modeHMAC},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := decideMode(tc.flagSet, tc.regMode, tc.cfg); got != tc.want {
				t.Fatalf("decideMode(%v, %q, cfg)=%q want %q", tc.flagSet, tc.regMode, got, tc.want)
			}
		})
	}
}

func TestValidateAutoEnrollCertFilter_RejectsBroadDefault(t *testing.T) {
	err := validateAutoEnrollCertFilter(autoenroll.CertFilter{})
	if err == nil {
		t.Fatal("expected broad auto-enroll cert filter to fail closed")
	}
}

func TestValidateAutoEnrollCertFilter_AcceptsSubjectSuffix(t *testing.T) {
	err := validateAutoEnrollCertFilter(autoenroll.CertFilter{SubjectSuffix: ".acik.local"})
	if err != nil {
		t.Fatalf("subject suffix should be accepted: %v", err)
	}
}

func TestValidateAutoEnrollCertFilter_AcceptsSANURIPrefix(t *testing.T) {
	err := validateAutoEnrollCertFilter(autoenroll.CertFilter{SANURIPrefix: "adcomputer:"})
	if err != nil {
		t.Fatalf("SAN URI prefix should be accepted: %v", err)
	}
}
