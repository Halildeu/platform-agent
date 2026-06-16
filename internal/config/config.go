package config

import (
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	AgentName string
	APIURL    string
	// SigningPathPrefix is the backend-visible path prefix used for HMAC
	// signing. Empty means derive it from APIURL (endpoint-agent -> agent).
	SigningPathPrefix string
	// CredentialID + Secret are the device credential (X-Device-Credential-Id
	// and the HMAC key) issued by enrollment. DeviceID is the enrolled device.
	CredentialID        string
	Secret              string
	DeviceID            string
	InstallID           string
	EnrollmentToken     string
	AgentVersion        string
	LogDir              string
	HeartbeatInterval   time.Duration
	CommandPollInterval time.Duration
	InventoryInterval   time.Duration
	JitterPercent       int
	CommandTimeout      time.Duration
	// InstallCommandTimeout overrides CommandTimeout specifically for
	// the AG-027 INSTALL_SOFTWARE command type. The default 120s
	// CommandTimeout was sized for quick read-only commands (inventory,
	// user listing) and is too aggressive for WinGet installs that
	// routinely take 30s–5min and occasionally longer for vendor MSI
	// bundles. Codex 019e6c0d iter-2 P1 absorb: bound effective install
	// timeout at the documented 30-min hard cap so the agent and the
	// docs/COMMAND-CONTRACT.md §11.5 narrative agree.
	InstallCommandTimeout time.Duration
	// UninstallCommandTimeout overrides CommandTimeout for the AG-028
	// (Faz 22.5.6) UNINSTALL_SOFTWARE command type. MSI uninstall paths
	// can run repair / custom-action / network wait phases that push
	// past the 5-min install median; the 30-min ceiling matches the
	// install hard cap (Codex 019e8de2 iter-1 absorb: keep parity, do
	// not optimise downward without LIVE evidence).
	UninstallCommandTimeout time.Duration
	// SelfUpdateCommandTimeout caps AG-029 UPDATE_AGENT staging. It
	// mirrors install/uninstall's long-running command budget because a
	// signed binary download + verification + protected staging can exceed
	// the lightweight 120s command timeout.
	SelfUpdateCommandTimeout time.Duration
	NonceSkewWindow          time.Duration
	NonceReplayCacheWindow   time.Duration

	// AutoEnrollAPIURL is the full canonical mTLS base path used by the
	// --auto-enroll mode (ADR-0029 Katman 3). Empty means use the
	// production default baked into autoenroll.Defaults().
	AutoEnrollAPIURL string
	// AutoEnrollConfigPath is the on-disk location of the DPAPI-encrypted
	// PersistedConfig the auto-enroll runner reads/writes. Empty means
	// the Windows default under %ProgramData%\EndpointAgent\config.
	AutoEnrollConfigPath string
	// AutoEnrollCertSubjectSuffix narrows the cert-store query when the
	// LocalMachine\My store carries multiple Client Authentication certs
	// (e.g. corp PCs with both AD machine cert and a third-party VPN
	// cert). Optional.
	AutoEnrollCertSubjectSuffix string
	// AutoEnrollCertSANURIPrefix similarly narrows the cert-store query
	// by URI SAN prefix. ADR-0029 Katman 1 mints
	// URI:adcomputer:{objectGUID} so "adcomputer:" is the production
	// suffix.
	AutoEnrollCertSANURIPrefix string

	// AG-029 signed self-update local policy. Capability advertisement is
	// opt-in: UPDATE_AGENT is reported only when SelfUpdateEnabled is true.
	// The backend payload cannot widen these local trust anchors.
	SelfUpdateEnabled             bool
	SelfUpdateAllowedHosts        []string
	SelfUpdateSignerThumbprints   []string
	SelfUpdateAllowLabOnlySigning bool
	SelfUpdateHardMaxBytes        int64
	SelfUpdateMaxRedirects        int
	// SelfUpdateAutoActivate controls whether a successful UPDATE_AGENT staging
	// result launches the local activation helper after SubmitResult succeeds.
	// Default is false; production/pilot installs must opt in explicitly.
	SelfUpdateAutoActivate      bool
	SelfUpdateActivationTimeout time.Duration
	SelfUpdateServiceName       string

	// Faz 22.6 T-3 remote-bridge idle transport harness (ADR-0038). All of
	// this is INERT unless RemoteBridgeEnabled is explicitly set — the agent
	// never auto-connects on start (disabled-by-default until the
	// owner-gated pilot, ADR-0034 §13/D10). T-3 carries NO capture/PTY: the
	// harness only maintains the outbound CONTROL stream (AgentHello +
	// heartbeat-obey + KILL-obey).
	RemoteBridgeEnabled bool
	// RemoteBridgeBrokerAddr is the broker gRPC target (host:port).
	RemoteBridgeBrokerAddr string
	// RemoteBridgeInsecurePlaintext dials without TLS — lab/loopback ONLY
	// (enforced: harness.New refuses a non-loopback broker when this is set);
	// default is TLS with system roots (real mTLS identity lands in T-4).
	RemoteBridgeInsecurePlaintext bool
	// RemoteBridgeFirstHeartbeatDeadline bounds initial stream silence;
	// RemoteBridgeHeartbeatMissFactor × the server-announced interval is the
	// steady-state watchdog timeout (the agent-side missed-heartbeat policy
	// T-2b deliberately left to T-3).
	RemoteBridgeFirstHeartbeatDeadline time.Duration
	RemoteBridgeHeartbeatMissFactor    int
	// RemoteBridgeBackoffMin/Max bound the jittered exponential reconnect.
	RemoteBridgeBackoffMin time.Duration
	RemoteBridgeBackoffMax time.Duration
	// RemoteBridgeIdentityPollInterval is the wait cadence while the device
	// identity is not yet enrolled (the harness never dials without it).
	RemoteBridgeIdentityPollInterval time.Duration
	// RemoteBridgeDialTimeout caps a single transport connect attempt.
	RemoteBridgeDialTimeout time.Duration
}

// BuildVersion is overridden at build time via
// `-ldflags "-X platform-agent/internal/config.BuildVersion=v0.1.0-lab.1"`
// by the release workflow. Working-tree builds keep the "dev" sentinel
// so the env override path (ENDPOINT_AGENT_VERSION) still wins for
// hand-testing. (Codex 019e8284 must_fix: build-time var + env override.)
var BuildVersion = "dev"

func defaultAgentVersion() string {
	if BuildVersion != "" && BuildVersion != "dev" {
		return BuildVersion
	}
	return "0.1.0-dev"
}

func Default() Config {
	return Config{
		AgentName:                   "endpoint-agent",
		APIURL:                      "https://localhost/api/v1/endpoint-agent",
		AgentVersion:                defaultAgentVersion(),
		HeartbeatInterval:           60 * time.Second,
		CommandPollInterval:         30 * time.Second,
		InventoryInterval:           60 * time.Minute,
		JitterPercent:               20,
		CommandTimeout:              120 * time.Second,
		InstallCommandTimeout:       30 * time.Minute,
		UninstallCommandTimeout:     30 * time.Minute,
		SelfUpdateCommandTimeout:    30 * time.Minute,
		NonceSkewWindow:             5 * time.Minute,
		NonceReplayCacheWindow:      10 * time.Minute,
		SelfUpdateHardMaxBytes:      100 * 1024 * 1024,
		SelfUpdateMaxRedirects:      5,
		SelfUpdateActivationTimeout: 2 * time.Minute,
		SelfUpdateServiceName:       "EndpointAgent",

		// Remote-bridge harness (T-3): disabled by default, no broker addr.
		RemoteBridgeEnabled:                false,
		RemoteBridgeFirstHeartbeatDeadline: 15 * time.Second,
		RemoteBridgeHeartbeatMissFactor:    3,
		RemoteBridgeBackoffMin:             time.Second,
		RemoteBridgeBackoffMax:             5 * time.Minute,
		RemoteBridgeIdentityPollInterval:   5 * time.Second,
		RemoteBridgeDialTimeout:            10 * time.Second,
	}
}

func LoadFromEnv() Config {
	cfg := Default()
	cfg.AgentName = envString("ENDPOINT_AGENT_NAME", cfg.AgentName)
	cfg.APIURL = strings.TrimRight(envString("ENDPOINT_AGENT_API_URL", cfg.APIURL), "/")
	cfg.SigningPathPrefix = envString("ENDPOINT_AGENT_SIGNING_PATH_PREFIX", cfg.SigningPathPrefix)
	cfg.CredentialID = envString("ENDPOINT_AGENT_CREDENTIAL_ID", cfg.CredentialID)
	cfg.Secret = envString("ENDPOINT_AGENT_SECRET", cfg.Secret)
	cfg.DeviceID = envString("ENDPOINT_AGENT_DEVICE_ID", cfg.DeviceID)
	cfg.InstallID = envString("ENDPOINT_AGENT_INSTALL_ID", cfg.InstallID)
	cfg.EnrollmentToken = envString("ENDPOINT_AGENT_ENROLLMENT_TOKEN", cfg.EnrollmentToken)
	cfg.AgentVersion = envString("ENDPOINT_AGENT_VERSION", cfg.AgentVersion)
	cfg.LogDir = envString("ENDPOINT_AGENT_LOG_DIR", cfg.LogDir)
	cfg.HeartbeatInterval = envDuration("ENDPOINT_AGENT_HEARTBEAT_INTERVAL", cfg.HeartbeatInterval)
	cfg.CommandPollInterval = envDuration("ENDPOINT_AGENT_COMMAND_POLL_INTERVAL", cfg.CommandPollInterval)
	cfg.InventoryInterval = envDuration("ENDPOINT_AGENT_INVENTORY_INTERVAL", cfg.InventoryInterval)
	cfg.CommandTimeout = envDuration("ENDPOINT_AGENT_COMMAND_TIMEOUT", cfg.CommandTimeout)
	cfg.InstallCommandTimeout = envDuration("ENDPOINT_AGENT_INSTALL_COMMAND_TIMEOUT", cfg.InstallCommandTimeout)
	cfg.UninstallCommandTimeout = envDuration("ENDPOINT_AGENT_UNINSTALL_COMMAND_TIMEOUT", cfg.UninstallCommandTimeout)
	cfg.SelfUpdateCommandTimeout = envDuration("ENDPOINT_AGENT_SELF_UPDATE_COMMAND_TIMEOUT", cfg.SelfUpdateCommandTimeout)
	cfg.NonceSkewWindow = envDuration("ENDPOINT_AGENT_NONCE_SKEW_WINDOW", cfg.NonceSkewWindow)
	cfg.NonceReplayCacheWindow = envDuration("ENDPOINT_AGENT_NONCE_REPLAY_CACHE_WINDOW", cfg.NonceReplayCacheWindow)
	cfg.JitterPercent = envInt("ENDPOINT_AGENT_JITTER_PERCENT", cfg.JitterPercent)
	cfg.AutoEnrollAPIURL = strings.TrimRight(envString("ENDPOINT_AGENT_AUTO_ENROLL_API_URL", cfg.AutoEnrollAPIURL), "/")
	cfg.AutoEnrollConfigPath = envString("ENDPOINT_AGENT_AUTO_ENROLL_CONFIG_PATH", cfg.AutoEnrollConfigPath)
	cfg.AutoEnrollCertSubjectSuffix = envString("ENDPOINT_AGENT_AUTO_ENROLL_CERT_SUBJECT_SUFFIX", cfg.AutoEnrollCertSubjectSuffix)
	cfg.AutoEnrollCertSANURIPrefix = envString("ENDPOINT_AGENT_AUTO_ENROLL_CERT_SAN_URI_PREFIX", cfg.AutoEnrollCertSANURIPrefix)
	cfg.SelfUpdateEnabled = envBool("ENDPOINT_AGENT_SELF_UPDATE_ENABLED", cfg.SelfUpdateEnabled)
	cfg.SelfUpdateAllowedHosts = envCSV("ENDPOINT_AGENT_SELF_UPDATE_ALLOWED_HOSTS", cfg.SelfUpdateAllowedHosts)
	cfg.SelfUpdateSignerThumbprints = envCSV("ENDPOINT_AGENT_SELF_UPDATE_SIGNER_THUMBPRINTS", cfg.SelfUpdateSignerThumbprints)
	cfg.SelfUpdateAllowLabOnlySigning = envBool("ENDPOINT_AGENT_SELF_UPDATE_ALLOW_LAB_ONLY_SIGNING", cfg.SelfUpdateAllowLabOnlySigning)
	cfg.SelfUpdateHardMaxBytes = envInt64("ENDPOINT_AGENT_SELF_UPDATE_HARD_MAX_BYTES", cfg.SelfUpdateHardMaxBytes)
	cfg.SelfUpdateMaxRedirects = envInt("ENDPOINT_AGENT_SELF_UPDATE_MAX_REDIRECTS", cfg.SelfUpdateMaxRedirects)
	cfg.SelfUpdateAutoActivate = envBool("ENDPOINT_AGENT_SELF_UPDATE_AUTO_ACTIVATE", cfg.SelfUpdateAutoActivate)
	cfg.SelfUpdateActivationTimeout = envDuration("ENDPOINT_AGENT_SELF_UPDATE_ACTIVATION_TIMEOUT", cfg.SelfUpdateActivationTimeout)
	cfg.SelfUpdateServiceName = envString("ENDPOINT_AGENT_SELF_UPDATE_SERVICE_NAME", cfg.SelfUpdateServiceName)
	cfg.RemoteBridgeEnabled = envBool("ENDPOINT_AGENT_REMOTE_BRIDGE_ENABLED", cfg.RemoteBridgeEnabled)
	cfg.RemoteBridgeBrokerAddr = envString("ENDPOINT_AGENT_REMOTE_BRIDGE_BROKER_ADDR", cfg.RemoteBridgeBrokerAddr)
	cfg.RemoteBridgeInsecurePlaintext = envBool("ENDPOINT_AGENT_REMOTE_BRIDGE_INSECURE_PLAINTEXT", cfg.RemoteBridgeInsecurePlaintext)
	cfg.RemoteBridgeFirstHeartbeatDeadline = envDuration("ENDPOINT_AGENT_REMOTE_BRIDGE_FIRST_HEARTBEAT_DEADLINE", cfg.RemoteBridgeFirstHeartbeatDeadline)
	cfg.RemoteBridgeHeartbeatMissFactor = envInt("ENDPOINT_AGENT_REMOTE_BRIDGE_HEARTBEAT_MISS_FACTOR", cfg.RemoteBridgeHeartbeatMissFactor)
	cfg.RemoteBridgeBackoffMin = envDuration("ENDPOINT_AGENT_REMOTE_BRIDGE_BACKOFF_MIN", cfg.RemoteBridgeBackoffMin)
	cfg.RemoteBridgeBackoffMax = envDuration("ENDPOINT_AGENT_REMOTE_BRIDGE_BACKOFF_MAX", cfg.RemoteBridgeBackoffMax)
	cfg.RemoteBridgeIdentityPollInterval = envDuration("ENDPOINT_AGENT_REMOTE_BRIDGE_IDENTITY_POLL_INTERVAL", cfg.RemoteBridgeIdentityPollInterval)
	cfg.RemoteBridgeDialTimeout = envDuration("ENDPOINT_AGENT_REMOTE_BRIDGE_DIAL_TIMEOUT", cfg.RemoteBridgeDialTimeout)
	return cfg
}

func (cfg Config) SelfUpdateCapabilityEnabled() bool {
	// Timeout is intentionally not part of this gate: it has a safe default.
	// SelfUpdateMaxRedirects=0 is valid and means "no redirects".
	return cfg.SelfUpdateEnabled &&
		len(cfg.SelfUpdateAllowedHosts) > 0 &&
		len(cfg.SelfUpdateSignerThumbprints) > 0 &&
		cfg.SelfUpdateHardMaxBytes > 0 &&
		cfg.SelfUpdateMaxRedirects >= 0
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

func envInt64(key string, fallback int64) int64 {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return fallback
	}
	return parsed
}

func envBool(key string, fallback bool) bool {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	switch strings.ToLower(value) {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		return fallback
	}
}

func envCSV(key string, fallback []string) []string {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}
