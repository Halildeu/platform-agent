package config

import (
	"testing"
	"time"
)

func TestRemoteBridgeDefaultsDisabled(t *testing.T) {
	cfg := Default()
	if cfg.RemoteBridgeEnabled {
		t.Fatal("RemoteBridgeEnabled must default to false (disabled-by-default)")
	}
	if cfg.RemoteBridgeBrokerAddr != "" {
		t.Fatalf("RemoteBridgeBrokerAddr default %q, want empty", cfg.RemoteBridgeBrokerAddr)
	}
	if cfg.RemoteBridgeInsecurePlaintext {
		t.Fatal("RemoteBridgeInsecurePlaintext must default to false (TLS default)")
	}
	if cfg.RemoteBridgeFirstHeartbeatDeadline != 15*time.Second {
		t.Errorf("FirstHeartbeatDeadline default %s", cfg.RemoteBridgeFirstHeartbeatDeadline)
	}
	if cfg.RemoteBridgeHeartbeatMissFactor != 3 {
		t.Errorf("HeartbeatMissFactor default %d", cfg.RemoteBridgeHeartbeatMissFactor)
	}
	if cfg.RemoteBridgeBackoffMin != time.Second || cfg.RemoteBridgeBackoffMax != 5*time.Minute {
		t.Errorf("backoff defaults %s/%s", cfg.RemoteBridgeBackoffMin, cfg.RemoteBridgeBackoffMax)
	}
	if cfg.RemoteBridgeOperationsEnabled {
		t.Fatal("remote-bridge operations must default to false")
	}
	if cfg.RemoteBridgePilotAutoConsent {
		t.Fatal("remote-bridge pilot auto-consent must default to false")
	}
	if cfg.RemoteBridgePermitBrokerPublicKeyB64 != "" || cfg.RemoteBridgePermitKeyID != "" {
		t.Fatal("remote-bridge broker permit trust anchors must default empty")
	}
	if cfg.RemoteBridgeAttestationEvidenceB64 != "" {
		t.Fatal("remote-bridge attestation evidence must default empty")
	}
}

func TestRemoteBridgeEnvOverrides(t *testing.T) {
	t.Setenv("ENDPOINT_AGENT_REMOTE_BRIDGE_ENABLED", "true")
	t.Setenv("ENDPOINT_AGENT_REMOTE_BRIDGE_BROKER_ADDR", "broker.example:8443")
	t.Setenv("ENDPOINT_AGENT_REMOTE_BRIDGE_INSECURE_PLAINTEXT", "true")
	t.Setenv("ENDPOINT_AGENT_REMOTE_BRIDGE_FIRST_HEARTBEAT_DEADLINE", "20s")
	t.Setenv("ENDPOINT_AGENT_REMOTE_BRIDGE_HEARTBEAT_MISS_FACTOR", "5")
	t.Setenv("ENDPOINT_AGENT_REMOTE_BRIDGE_BACKOFF_MIN", "2s")
	t.Setenv("ENDPOINT_AGENT_REMOTE_BRIDGE_BACKOFF_MAX", "10m")
	t.Setenv("ENDPOINT_AGENT_REMOTE_BRIDGE_OPERATIONS_ENABLED", "true")
	t.Setenv("ENDPOINT_AGENT_REMOTE_BRIDGE_PERMIT_BROKER_PUBLIC_KEY_B64", "pub")
	t.Setenv("ENDPOINT_AGENT_REMOTE_BRIDGE_PERMIT_KEY_ID", "kid-1")
	t.Setenv("ENDPOINT_AGENT_REMOTE_BRIDGE_PILOT_AUTO_CONSENT", "true")
	t.Setenv("ENDPOINT_AGENT_REMOTE_BRIDGE_TLS_SERVER_NAME", "bridge.example")
	t.Setenv("ENDPOINT_AGENT_REMOTE_BRIDGE_MTLS_CERT_SUBJECT_SUFFIX", ".acik.local")
	t.Setenv("ENDPOINT_AGENT_REMOTE_BRIDGE_MTLS_CERT_SAN_URI_PREFIX", "adcomputer:")
	t.Setenv("ENDPOINT_AGENT_REMOTE_BRIDGE_ATTESTATION_EVIDENCE_B64", "ZGlnZXN0fGJ1aWxkZXJ8cG9saWN5fHNpZw==")
	cfg := LoadFromEnv()
	if !cfg.RemoteBridgeEnabled || cfg.RemoteBridgeBrokerAddr != "broker.example:8443" ||
		!cfg.RemoteBridgeInsecurePlaintext ||
		cfg.RemoteBridgeFirstHeartbeatDeadline != 20*time.Second ||
		cfg.RemoteBridgeHeartbeatMissFactor != 5 ||
		cfg.RemoteBridgeBackoffMin != 2*time.Second ||
		cfg.RemoteBridgeBackoffMax != 10*time.Minute ||
		!cfg.RemoteBridgeOperationsEnabled ||
		cfg.RemoteBridgePermitBrokerPublicKeyB64 != "pub" ||
		cfg.RemoteBridgePermitKeyID != "kid-1" ||
		!cfg.RemoteBridgePilotAutoConsent ||
		cfg.RemoteBridgeTLSServerName != "bridge.example" ||
		cfg.RemoteBridgeMTLSCertSubjectSuffix != ".acik.local" ||
		cfg.RemoteBridgeMTLSCertSANURIPrefix != "adcomputer:" ||
		cfg.RemoteBridgeAttestationEvidenceB64 != "ZGlnZXN0fGJ1aWxkZXJ8cG9saWN5fHNpZw==" {
		t.Fatalf("env overrides not applied: %+v", cfg)
	}
}
