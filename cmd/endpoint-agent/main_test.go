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
	got, err := hostnameOnly("https://mtls.testai.acik.com/api/v1/endpoint-agent")
	if err != nil {
		t.Fatalf("hostnameOnly: %v", err)
	}
	if got != "mtls.testai.acik.com" {
		t.Fatalf("got %q", got)
	}
}

func TestHostnameOnly_StripsPort(t *testing.T) {
	got, err := hostnameOnly("https://mtls.testai.acik.com:8443/api/v1/endpoint-agent")
	if err != nil {
		t.Fatalf("hostnameOnly: %v", err)
	}
	if got != "mtls.testai.acik.com" {
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
	if got := resolveMode(true, false, config.Config{}, ""); got != modeAutoEnroll {
		t.Fatalf("flag should win: got %q", got)
	}
}

func TestResolveMode_FlagOffNoRegistry(t *testing.T) {
	// On non-Windows, registry.Reader returns def for ReadString, so the
	// fallback is HMAC mode.
	if got := resolveMode(false, false, config.Config{}, ""); got != modeHMAC {
		t.Fatalf("default should be HMAC: got %q", got)
	}
}

// #108 (live pilot MKR-A1): a stale Mode=auto-enroll registry value must not
// strand a fully-provisioned HMAC host, while the legitimate MSI/auto-enroll
// flow (which ships ENDPOINT_AGENT_AUTO_ENROLL_API_URL or --api-url) stays
// unaffected. Signals are SOURCE-aware (Codex 019ea886 must-fix) so a non-empty
// config DEFAULT (baked localhost APIURL) never counts as an explicit HMAC
// choice; credential presence — env token OR a valid DPAPI-persisted credential
// — is the durable HMAC signal, because install.ps1 clears the env token after
// a successful enroll.
func TestDecideMode(t *testing.T) {
	// envTokenHost: explicit API URL env + env enrollment token still present
	// (mid-install, before install.ps1 clears the token).
	envTokenHost := modeSignals{hmacAPIURLExplicit: true, hmacCredentialPresent: true}
	// persistedCredHost: the NORMAL healthy post-install HMAC host — explicit
	// API URL env + a valid DPAPI-persisted credential, but NO env token (cleared
	// by install.ps1). At the pure-decision layer this collapses to the same two
	// booleans as envTokenHost, which is the point: provenance of the credential
	// does not change the decision (Codex 019ea886 P1 — this host MUST be rescued).
	persistedCredHost := modeSignals{hmacAPIURLExplicit: true, hmacCredentialPresent: true}
	autoEnrollExplicit := modeSignals{autoEnrollURLExplicit: true}
	bothExplicit := modeSignals{hmacAPIURLExplicit: true, hmacCredentialPresent: true, autoEnrollURLExplicit: true}
	credOnlyDefaultURL := modeSignals{hmacCredentialPresent: true} // default APIURL, env API URL not set
	apiURLNoCred := modeSignals{hmacAPIURLExplicit: true}

	cases := []struct {
		name    string
		flagSet bool
		regMode string
		sig     modeSignals
		want    string
	}{
		{"flag wins over everything", true, modeAutoEnroll, envTokenHost, modeAutoEnroll},
		{"#108 stale regkey overridden by explicit HMAC (env token)", false, modeAutoEnroll, envTokenHost, modeHMAC},
		{"#108 stale regkey overridden by persisted HMAC cred, no env token (Codex P1)", false, modeAutoEnroll, persistedCredHost, modeHMAC},
		{"MSI auto-enroll honoured (auto-enroll URL present)", false, modeAutoEnroll, autoEnrollExplicit, modeAutoEnroll},
		{"explicit auto-enroll URL blocks HMAC override (both present)", false, modeAutoEnroll, bothExplicit, modeAutoEnroll},
		{"credential present + DEFAULT APIURL is NOT explicit HMAC", false, modeAutoEnroll, credOnlyDefaultURL, modeAutoEnroll},
		{"explicit API URL but no credential does not override regkey", false, modeAutoEnroll, apiURLNoCred, modeAutoEnroll},
		{"no signals at all honours stale regkey", false, modeAutoEnroll, modeSignals{}, modeAutoEnroll},
		{"empty regkey is HMAC", false, "", envTokenHost, modeHMAC},
		{"non-auto-enroll regkey is HMAC", false, "hmac", autoEnrollExplicit, modeHMAC},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := decideMode(tc.flagSet, tc.regMode, tc.sig); got != tc.want {
				t.Fatalf("decideMode(%v, %q, %+v)=%q want %q", tc.flagSet, tc.regMode, tc.sig, got, tc.want)
			}
		})
	}
}

// hmacCredentialPersisted must fail closed: when no valid credential is
// persisted the probe returns false and never blindly flips a stale auto-enroll
// host to HMAC (Codex 019ea886 must-fix). On non-Windows the store returns
// ErrUnsupportedOS; on Windows the same false-closed contract holds for
// ErrEmpty / ErrInvalid / I/O errors. Only a successful validated Read is true.
//
// Hermetic: point ProgramData (which DefaultPath() uses to build the store
// location) at an empty temp dir so the test is deterministic on EVERY platform
// — even a Windows host that has a real agent + valid credential installed
// (Codex 019ea886 non-blocking note).
func TestHMACCredentialPersisted_FailsClosed(t *testing.T) {
	t.Setenv("ProgramData", t.TempDir())
	if hmacCredentialPersisted() {
		t.Fatalf("expected false on a host with no valid persisted HMAC credential")
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
