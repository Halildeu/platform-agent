package config

import (
	"testing"
	"time"
)

func TestLoadFromEnvOverridesDefaults(t *testing.T) {
	t.Setenv("ENDPOINT_AGENT_API_URL", "https://agent.example.test/api/")
	t.Setenv("ENDPOINT_AGENT_ID", "agent-1")
	t.Setenv("ENDPOINT_AGENT_SECRET", "secret")
	t.Setenv("ENDPOINT_AGENT_LOG_DIR", "/tmp/endpoint-agent-test-logs")
	t.Setenv("ENDPOINT_AGENT_HEARTBEAT_INTERVAL", "15s")
	t.Setenv("ENDPOINT_AGENT_JITTER_PERCENT", "12")

	cfg := LoadFromEnv()

	if cfg.APIURL != "https://agent.example.test/api" {
		t.Fatalf("APIURL = %q", cfg.APIURL)
	}
	if cfg.AgentID != "agent-1" || cfg.AgentSecret != "secret" {
		t.Fatalf("identity not loaded: %#v", cfg)
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
