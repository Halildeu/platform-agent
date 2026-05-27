package main

import (
	"testing"

	"platform-agent/internal/config"
)

// stubRegistry implements the small interface resolveAutoEnrollAPIURL
// reads from. Production code uses winregistry.New(); tests want a
// drop-in that can serve fixed values without touching HKLM.
type stubRegistry struct {
	intMap    map[string]int
	stringMap map[string]string
}

func (s stubRegistry) ReadInt(_, _ string, def int) int        { return def }
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
	if got := resolveMode(true, false); got != modeAutoEnroll {
		t.Fatalf("flag should win: got %q", got)
	}
}

func TestResolveMode_FlagOffNoRegistry(t *testing.T) {
	// On non-Windows, registry.Reader returns def for ReadString, so the
	// fallback is HMAC mode.
	if got := resolveMode(false, false); got != modeHMAC {
		t.Fatalf("default should be HMAC: got %q", got)
	}
}
