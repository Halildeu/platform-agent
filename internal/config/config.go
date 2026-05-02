package config

import (
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	AgentName              string
	APIURL                 string
	AgentID                string
	AgentSecret            string
	InstallID              string
	EnrollmentToken        string
	AgentVersion           string
	LogDir                 string
	HeartbeatInterval      time.Duration
	CommandPollInterval    time.Duration
	InventoryInterval      time.Duration
	JitterPercent          int
	CommandTimeout         time.Duration
	NonceSkewWindow        time.Duration
	NonceReplayCacheWindow time.Duration
}

func Default() Config {
	return Config{
		AgentName:              "endpoint-agent",
		APIURL:                 "https://localhost/api/v1/endpoint-agent",
		AgentVersion:           "0.1.0-dev",
		HeartbeatInterval:      60 * time.Second,
		CommandPollInterval:    30 * time.Second,
		InventoryInterval:      60 * time.Minute,
		JitterPercent:          20,
		CommandTimeout:         120 * time.Second,
		NonceSkewWindow:        5 * time.Minute,
		NonceReplayCacheWindow: 10 * time.Minute,
	}
}

func LoadFromEnv() Config {
	cfg := Default()
	cfg.AgentName = envString("ENDPOINT_AGENT_NAME", cfg.AgentName)
	cfg.APIURL = strings.TrimRight(envString("ENDPOINT_AGENT_API_URL", cfg.APIURL), "/")
	cfg.AgentID = envString("ENDPOINT_AGENT_ID", cfg.AgentID)
	cfg.AgentSecret = envString("ENDPOINT_AGENT_SECRET", cfg.AgentSecret)
	cfg.InstallID = envString("ENDPOINT_AGENT_INSTALL_ID", cfg.InstallID)
	cfg.EnrollmentToken = envString("ENDPOINT_AGENT_ENROLLMENT_TOKEN", cfg.EnrollmentToken)
	cfg.AgentVersion = envString("ENDPOINT_AGENT_VERSION", cfg.AgentVersion)
	cfg.LogDir = envString("ENDPOINT_AGENT_LOG_DIR", cfg.LogDir)
	cfg.HeartbeatInterval = envDuration("ENDPOINT_AGENT_HEARTBEAT_INTERVAL", cfg.HeartbeatInterval)
	cfg.CommandPollInterval = envDuration("ENDPOINT_AGENT_COMMAND_POLL_INTERVAL", cfg.CommandPollInterval)
	cfg.InventoryInterval = envDuration("ENDPOINT_AGENT_INVENTORY_INTERVAL", cfg.InventoryInterval)
	cfg.CommandTimeout = envDuration("ENDPOINT_AGENT_COMMAND_TIMEOUT", cfg.CommandTimeout)
	cfg.NonceSkewWindow = envDuration("ENDPOINT_AGENT_NONCE_SKEW_WINDOW", cfg.NonceSkewWindow)
	cfg.NonceReplayCacheWindow = envDuration("ENDPOINT_AGENT_NONCE_REPLAY_CACHE_WINDOW", cfg.NonceReplayCacheWindow)
	cfg.JitterPercent = envInt("ENDPOINT_AGENT_JITTER_PERCENT", cfg.JitterPercent)
	return cfg
}

func envString(key string, fallback string) string {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	return value
}

func envDuration(key string, fallback time.Duration) time.Duration {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	parsed, err := time.ParseDuration(value)
	if err != nil {
		return fallback
	}
	return parsed
}

func envInt(key string, fallback int) int {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return fallback
	}
	return parsed
}
