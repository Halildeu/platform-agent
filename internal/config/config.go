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
	// SelfUpdate* fields gate AG-029 UPDATE_AGENT advertisement and
	// source-side staging. They are local trust configuration: the backend
	// command payload cannot widen hosts, signer thumbprints, or lab-tier
	// consent. Empty signer/host/staging/current-binary values mean disabled.
	SelfUpdateEnabled           bool
	SelfUpdateStagingRoot       string
	SelfUpdateCurrentBinaryPath string
	SelfUpdateServiceName       string
	SelfUpdateAllowedHosts      []string
	SelfUpdateMaxRedirects      int
	SelfUpdateSignerThumbprints []string
	SelfUpdateAllowLabOnly      bool
	SelfUpdateDomainJoined      bool
	SelfUpdateMaxSeenVersion    string
	// SelfUpdateAutoActivate controls whether the runner launches the local
	// service-safe activation helper after a successful UPDATE_AGENT staging
	// result has been submitted to the backend. It is opt-in because Windows
	// live smoke must prove service stop/swap/start and heartbeat acceptance.
	SelfUpdateAutoActivate      bool
	SelfUpdateActivationTimeout time.Duration
	NonceSkewWindow             time.Duration
	NonceReplayCacheWindow      time.Duration

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
		SelfUpdateServiceName:       "EndpointAgent",
		SelfUpdateMaxRedirects:      5,
		SelfUpdateActivationTimeout: 2 * time.Minute,
		NonceSkewWindow:             5 * time.Minute,
		NonceReplayCacheWindow:      10 * time.Minute,
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
	cfg.SelfUpdateEnabled = envBool("ENDPOINT_AGENT_SELF_UPDATE_ENABLED", cfg.SelfUpdateEnabled)
	cfg.SelfUpdateStagingRoot = envString("ENDPOINT_AGENT_SELF_UPDATE_STAGING_ROOT", cfg.SelfUpdateStagingRoot)
	cfg.SelfUpdateCurrentBinaryPath = envString("ENDPOINT_AGENT_SELF_UPDATE_CURRENT_BINARY_PATH", cfg.SelfUpdateCurrentBinaryPath)
	cfg.SelfUpdateServiceName = envString("ENDPOINT_AGENT_SELF_UPDATE_SERVICE_NAME", cfg.SelfUpdateServiceName)
	cfg.SelfUpdateAllowedHosts = envStringList("ENDPOINT_AGENT_SELF_UPDATE_ALLOWED_HOSTS", cfg.SelfUpdateAllowedHosts)
	cfg.SelfUpdateMaxRedirects = envInt("ENDPOINT_AGENT_SELF_UPDATE_MAX_REDIRECTS", cfg.SelfUpdateMaxRedirects)
	cfg.SelfUpdateSignerThumbprints = envStringList("ENDPOINT_AGENT_SELF_UPDATE_SIGNER_THUMBPRINTS", cfg.SelfUpdateSignerThumbprints)
	cfg.SelfUpdateAllowLabOnly = envBool("ENDPOINT_AGENT_SELF_UPDATE_ALLOW_LAB_ONLY", cfg.SelfUpdateAllowLabOnly)
	cfg.SelfUpdateDomainJoined = envBool("ENDPOINT_AGENT_SELF_UPDATE_DOMAIN_JOINED", cfg.SelfUpdateDomainJoined)
	cfg.SelfUpdateMaxSeenVersion = envString("ENDPOINT_AGENT_SELF_UPDATE_MAX_SEEN_VERSION", cfg.SelfUpdateMaxSeenVersion)
	cfg.SelfUpdateAutoActivate = envBool("ENDPOINT_AGENT_SELF_UPDATE_AUTO_ACTIVATE", cfg.SelfUpdateAutoActivate)
	cfg.SelfUpdateActivationTimeout = envDuration("ENDPOINT_AGENT_SELF_UPDATE_ACTIVATION_TIMEOUT", cfg.SelfUpdateActivationTimeout)
	cfg.NonceSkewWindow = envDuration("ENDPOINT_AGENT_NONCE_SKEW_WINDOW", cfg.NonceSkewWindow)
	cfg.NonceReplayCacheWindow = envDuration("ENDPOINT_AGENT_NONCE_REPLAY_CACHE_WINDOW", cfg.NonceReplayCacheWindow)
	cfg.JitterPercent = envInt("ENDPOINT_AGENT_JITTER_PERCENT", cfg.JitterPercent)
	cfg.AutoEnrollAPIURL = strings.TrimRight(envString("ENDPOINT_AGENT_AUTO_ENROLL_API_URL", cfg.AutoEnrollAPIURL), "/")
	cfg.AutoEnrollConfigPath = envString("ENDPOINT_AGENT_AUTO_ENROLL_CONFIG_PATH", cfg.AutoEnrollConfigPath)
	cfg.AutoEnrollCertSubjectSuffix = envString("ENDPOINT_AGENT_AUTO_ENROLL_CERT_SUBJECT_SUFFIX", cfg.AutoEnrollCertSubjectSuffix)
	cfg.AutoEnrollCertSANURIPrefix = envString("ENDPOINT_AGENT_AUTO_ENROLL_CERT_SAN_URI_PREFIX", cfg.AutoEnrollCertSANURIPrefix)
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

func envBool(key string, fallback bool) bool {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	switch strings.ToLower(value) {
	case "1", "true", "yes", "y", "on":
		return true
	case "0", "false", "no", "n", "off":
		return false
	default:
		return fallback
	}
}

func envStringList(key string, fallback []string) []string {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	parts := strings.FieldsFunc(value, func(r rune) bool {
		return r == ',' || r == ';' || r == '\n' || r == '\t'
	})
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if trimmed := strings.TrimSpace(p); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	if len(out) == 0 {
		return fallback
	}
	return out
}
