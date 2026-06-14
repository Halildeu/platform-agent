package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"platform-agent/internal/app"
	"platform-agent/internal/autoenroll"
	"platform-agent/internal/commands"
	"platform-agent/internal/config"
	"platform-agent/internal/hmacstore"
	"platform-agent/internal/identity"
	"platform-agent/internal/inventory"
	agentlog "platform-agent/internal/logging"
	"platform-agent/internal/mtls"
	"platform-agent/internal/platform/windows/certstore"
	"platform-agent/internal/platform/windows/dpapi"
	winregistry "platform-agent/internal/platform/windows/registry"
	winservice "platform-agent/internal/platform/windows/service"
	"platform-agent/internal/protocol"
	"platform-agent/internal/security"
	"platform-agent/internal/software"
	"platform-agent/internal/state"
	"platform-agent/internal/users"
	"platform-agent/internal/winget"
)

func main() {
	once := flag.Bool("once", false, "run one enroll/heartbeat/command iteration and exit")
	version := flag.Bool("version", false, "print agent version and exit")
	serviceRunName := flag.String("service-run-name", winservice.DefaultName, "internal Windows service name")
	autoEnrollFlag := flag.Bool("auto-enroll", false, "run in mTLS auto-enroll mode (ADR-0029 Faz 22.3 Katman 3); requires Windows")
	autoEnrollAPIURL := flag.String("api-url", "", "auto-enroll API base URL override (full canonical path, e.g. https://mtls.testai.acik.com/api/v1/endpoint-agent)")
	dryRun := flag.Bool("dry-run", false, "auto-enroll only: load cert + build TLS config + validate persisted config without making HTTP calls")
	// AG-026B: operator escape hatch for the HMAC enrollment token.
	// The PRODUCTION install path (install.ps1, AG-026C) writes the
	// token into the service-specific Environment regkey and the
	// runner reads it via ENDPOINT_AGENT_ENROLLMENT_TOKEN; the AG-026D
	// DPAPI store keeps the issued credential across service
	// restarts so the env token is normally only consumed once and
	// then cleared. This flag lets a debugging operator pass a token
	// directly without rewriting the regkey — useful when the
	// service is being run in the foreground for diagnostics. It is
	// HMAC-only (rejected in --auto-enroll mode below) and takes
	// PRECEDENCE over the env value when non-empty. The argv leak
	// surface is acknowledged: the installer DOES NOT use this flag;
	// it is only ever set by a human at an interactive elevated
	// prompt.
	enrollmentToken := flag.String("enrollment-token", "", "HMAC enrollment token (operator escape hatch; takes precedence over ENDPOINT_AGENT_ENROLLMENT_TOKEN; mutually exclusive with --auto-enroll)")
	flag.Parse()

	cfg := config.LoadFromEnv()
	if strings.TrimSpace(*enrollmentToken) != "" {
		cfg.EnrollmentToken = strings.TrimSpace(*enrollmentToken)
	}
	if *version {
		fmt.Printf("%s %s\n", cfg.AgentName, cfg.AgentVersion)
		return
	}
	if len(flag.Args()) > 0 && flag.Args()[0] == "service" {
		handleServiceCommand(flag.Args()[1:])
		return
	}
	if len(flag.Args()) > 0 && flag.Args()[0] == "self-update" {
		handleSelfUpdateCommand(flag.Args()[1:])
		return
	}
	if len(flag.Args()) > 0 && flag.Args()[0] == "diagnose" {
		handleDiagnoseCommand(flag.Args()[1:])
		return
	}

	runningAsService, err := winservice.IsWindowsService()
	if err != nil {
		log.Fatalf("service detection failed: %v", err)
	}
	loggerBundle, err := agentlog.New(agentlog.Options{
		AgentName:     cfg.AgentName,
		LogDir:        cfg.LogDir,
		IncludeStdout: !runningAsService,
	})
	if err != nil {
		log.Fatalf("logger init failed: %v", err)
	}
	defer loggerBundle.Close()
	logger := loggerBundle.Logger
	logger.Printf("logger initialized logPath=%s serviceMode=%t", loggerBundle.LogPath, runningAsService)

	mode := resolveMode(*autoEnrollFlag, *dryRun, cfg, *autoEnrollAPIURL)
	logger.Printf("agent mode=%s", mode)

	// AG-026B: fail-closed if the operator combines --enrollment-token
	// with --auto-enroll. The auto-enroll path uses an mTLS cert as
	// the identity bootstrapper (no HMAC token consumed), so a token
	// supplied here would never be redeemed and would silently
	// linger in the process env / argv. Codex 019e7314 must_fix #6.
	if strings.TrimSpace(*enrollmentToken) != "" && mode == modeAutoEnroll {
		logger.Fatalf("--enrollment-token is HMAC-only; combining it with --auto-enroll is rejected (Codex 019e7314 must_fix #6)")
	}

	if mode == modeAutoEnroll {
		if *dryRun {
			if err := runAutoEnrollDryRun(cfg, *autoEnrollAPIURL, logger); err != nil {
				logger.Fatalf("auto-enroll dry-run failed: %v", err)
			}
			return
		}
		if runningAsService {
			if err := winservice.Run(*serviceRunName, func(ctx context.Context) error {
				runner, err := newAutoEnrollRunner(cfg, *autoEnrollAPIURL, logger)
				if err != nil {
					return err
				}
				return runner.RunLoop(ctx)
			}); err != nil {
				logger.Fatalf("auto-enroll service run failed: %v", err)
			}
			return
		}
		runner, err := newAutoEnrollRunner(cfg, *autoEnrollAPIURL, logger)
		if err != nil {
			logger.Fatalf("auto-enroll init failed: %v", err)
		}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		if *once {
			if err := runner.RunOnce(ctx); err != nil {
				logger.Fatalf("auto-enroll run failed: %v", err)
			}
			return
		}
		if err := runner.RunLoop(ctx); err != nil && err != context.Canceled {
			logger.Fatalf("auto-enroll loop failed: %v", err)
		}
		return
	}

	// Default HMAC-signed mode (mevcut app.Runner).
	if *dryRun {
		logger.Fatalf("--dry-run requires --auto-enroll (HMAC mode has no dry-run semantic)")
	}
	if runningAsService {
		if err := winservice.Run(*serviceRunName, func(ctx context.Context) error {
			runner, err := newRunner(cfg, logger)
			if err != nil {
				return err
			}
			// Faz 22.6 T-3: inert unless ENDPOINT_AGENT_REMOTE_BRIDGE_ENABLED
			// is explicitly set; never dials before enrollment populates the
			// device identity. Auto-enroll mode wiring waits for T-4 (its
			// mTLS identity IS the T-4 transport credential).
			app.StartRemoteBridge(ctx, cfg, runner.Client.DeviceID, logger)
			return runner.RunLoop(ctx)
		}); err != nil {
			logger.Fatalf("service run failed: %v", err)
		}
		return
	}

	runner, err := newRunner(cfg, logger)
	if err != nil {
		logger.Fatalf("agent init failed: %v", err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if *once {
		// --once is a one-shot diagnostic pass; the long-lived remote-bridge
		// harness is loop-mode only.
		if err := runner.RunOnce(ctx); err != nil {
			logger.Fatalf("agent run failed: %v", err)
		}
		return
	}
	app.StartRemoteBridge(ctx, cfg, runner.Client.DeviceID, logger)
	if err := runner.RunLoop(ctx); err != nil && err != context.Canceled {
		logger.Fatalf("agent loop failed: %v", err)
	}
}

const (
	modeHMAC       = "hmac"
	modeAutoEnroll = "auto-enroll"
)

// resolveMode picks between the existing HMAC-signed mode and the
// ADR-0029 mTLS auto-enroll mode. Precedence:
//
//  1. --auto-enroll flag wins outright.
//  2. Otherwise the Windows registry value HKLM\SOFTWARE\EndpointAgent\Mode
//     decides — MSI installers ship "auto-enroll" there to flip the binary
//     when the service starts without explicit CLI args (Codex F9 + B
//     absorb).
//  3. Otherwise HMAC mode.
//
// On non-Windows builds the registry reader silently returns the default,
// so the function reduces to "honour the flag". --dry-run alone is NOT a
// valid mode trigger (Codex iter-3 guardrail): it requires either the flag
// or the registry to put us in auto-enroll mode first.
func resolveMode(flagSet bool, dryRunFlag bool, cfg config.Config, autoEnrollAPIURLFlag string) string {
	reader := winregistry.New()
	regMode := reader.ReadString(`HKLM:\SOFTWARE\EndpointAgent`, "Mode", "")
	_ = dryRunFlag // see comment on dry-run validation above; main() enforces.
	// Codex 019ea886 must-fix: the mode decision must be SOURCE-aware (which
	// provisioning channels are present), not value-aware. cfg.APIURL has a
	// baked default (config.Default -> https://localhost/...), so
	// `cfg.APIURL != ""` is ALWAYS true and would mistake the default for an
	// explicit HMAC choice. We read each signal from its real source:
	//   - the HMAC API URL from the env var presence,
	//   - HMAC credential presence from the env enrollment token OR a valid
	//     DPAPI-persisted device credential. install.ps1 REMOVES the env
	//     token after a successful enroll, so a healthy post-install HMAC
	//     host has ONLY the persisted credential — gating on the env token
	//     alone would miss exactly the #108 host we must rescue,
	//   - the auto-enroll URL from the --api-url flag OR its env var.
	sig := modeSignals{
		hmacAPIURLExplicit:    strings.TrimSpace(os.Getenv("ENDPOINT_AGENT_API_URL")) != "",
		hmacCredentialPresent: strings.TrimSpace(cfg.EnrollmentToken) != "" || hmacCredentialPersisted(),
		autoEnrollURLExplicit: strings.TrimSpace(autoEnrollAPIURLFlag) != "" || strings.TrimSpace(cfg.AutoEnrollAPIURL) != "",
	}
	return decideMode(flagSet, regMode, sig)
}

// hmacCredentialPersisted reports whether a VALID HMAC device credential is
// persisted on disk (AG-026D DPAPI store). It is true ONLY on a successful,
// validated Read: ErrEmpty (first run), ErrUnsupportedOS (non-Windows),
// ErrInvalid (corrupt/zeroed blob) and any I/O error all yield false — a
// missing or tampered credential must never blindly flip a stale auto-enroll
// host to HMAC (Codex 019ea886 must-fix; hmacstore tamper-protection
// 019e7314 #4). Mirrors the production store construction in main()
// (New("", nil): default %ProgramData% path, nil entropy) so the probe reads
// the same blob the runner will later hydrate.
func hmacCredentialPersisted() bool {
	_, err := hmacstore.New("", nil).Read(context.Background())
	return err == nil
}

// modeSignals captures the SOURCE-aware provisioning signals that drive the
// HMAC-vs-auto-enroll decision. Using sources (env-var presence / CLI flag /
// a valid persisted credential) instead of loaded config values prevents a
// non-empty config DEFAULT — e.g. the baked localhost APIURL — from being
// mistaken for an explicit operator HMAC choice (Codex 019ea886 must-fix).
type modeSignals struct {
	hmacAPIURLExplicit    bool // ENDPOINT_AGENT_API_URL env var was set
	hmacCredentialPresent bool // env enrollment token OR a valid DPAPI-persisted HMAC device credential
	autoEnrollURLExplicit bool // --api-url flag OR ENDPOINT_AGENT_AUTO_ENROLL_API_URL env was set
}

// decideMode is the pure (registry-free, OS-free) mode decision so it is unit
// testable on any platform. Precedence: --auto-enroll flag, then registry
// HKLM\SOFTWARE\EndpointAgent\Mode, then HMAC — plus the #108 stale-registry
// defence.
//
// #108 (live pilot MKR-A1): the FIRST auto-enroll install writes
// Mode=auto-enroll. A later HMAC install must clear it (install.ps1 now does),
// but a stale value from ANY source (manual edit, MSI leftover, a future
// installer regression) would otherwise strand the agent in auto-enroll despite
// a fully-provisioned HMAC service env — on a host with no eligible mTLS cert it
// then hangs and the service never reaches RUNNING.
//
// Defence-in-depth: override the stale registry ONLY when the operator
// UNAMBIGUOUSLY provisioned HMAC — explicit API URL env + an HMAC credential
// (env enrollment token OR a valid DPAPI-persisted device credential) AND no
// auto-enroll URL (neither --api-url nor the auto-enroll env). A healthy
// post-install HMAC host has the persisted credential but NO env token
// (install.ps1 clears it), so credential presence — not the transient env
// token — is the durable HMAC signal. The legitimate MSI/auto-enroll flow
// ships ENDPOINT_AGENT_AUTO_ENROLL_API_URL (and no HMAC creds), so it is
// unaffected; ambiguous/incomplete configs defer to the registry hint.
func decideMode(flagSet bool, regMode string, sig modeSignals) string {
	if flagSet {
		return modeAutoEnroll
	}
	if regMode == modeAutoEnroll {
		if sig.hmacAPIURLExplicit && sig.hmacCredentialPresent && !sig.autoEnrollURLExplicit {
			return modeHMAC
		}
		return modeAutoEnroll
	}
	return modeHMAC
}

// resolveAutoEnrollAPIURL applies the documented precedence:
// CLI flag > ENDPOINT_AGENT_AUTO_ENROLL_API_URL env > HKLM registry
// ApiUrl > baked default — Codex F8 absorb. The registry fallback is
// what the MSI installer (ADR-0029 Katman 4) writes when it deploys the
// service.
func resolveAutoEnrollAPIURL(cfg config.Config, apiURLOverride string, reader winregistry.Reader, baked string) string {
	if apiURLOverride != "" {
		return apiURLOverride
	}
	if cfg.AutoEnrollAPIURL != "" {
		return cfg.AutoEnrollAPIURL
	}
	if regVal := reader.ReadString(`HKLM:\SOFTWARE\EndpointAgent`, "ApiUrl", ""); regVal != "" {
		return regVal
	}
	return baked
}

// newAutoEnrollRunner wires up the autoenroll.Runner with the production
// providers (certstore + registry + DPAPI). Non-Windows builds get the
// same wiring but the providers refuse all calls with ErrUnsupportedOS, so
// the runner returns immediately and main() prints a clear error.
func newAutoEnrollRunner(cfg config.Config, apiURLOverride string, logger *log.Logger) (*autoenroll.Runner, error) {
	if runtime.GOOS != "windows" {
		return nil, fmt.Errorf("auto-enroll requires Windows (current GOOS=%s)", runtime.GOOS)
	}
	aeCfg := autoenroll.Defaults()
	registryReader := winregistry.New()
	aeCfg.APIURL = resolveAutoEnrollAPIURL(cfg, apiURLOverride, registryReader, aeCfg.APIURL)
	aeCfg.AgentVersion = cfg.AgentVersion
	if cfg.HeartbeatInterval > 0 {
		aeCfg.HeartbeatInterval = cfg.HeartbeatInterval
	}
	if cfg.CommandPollInterval > 0 {
		aeCfg.CommandPollInterval = cfg.CommandPollInterval
	}
	if cfg.CommandTimeout > 0 {
		aeCfg.CommandTimeout = cfg.CommandTimeout
	}
	// AG-027 (Codex 019e6c0d iter-3 absorb): forward the per-command
	// INSTALL_SOFTWARE timeout so the auto-enroll runner pollAndExecute
	// honours the documented 30-min hard cap.
	if cfg.InstallCommandTimeout > 0 {
		aeCfg.InstallCommandTimeout = cfg.InstallCommandTimeout
	}
	// AG-028 (Codex 019e8de2 iter-3 absorb): same propagation for
	// UNINSTALL_SOFTWARE. Without this the auto-enroll path falls back
	// to the 120s CommandTimeout and the 30-min RunUninstall budget is
	// truncated by the parent context.
	if cfg.UninstallCommandTimeout > 0 {
		aeCfg.UninstallCommandTimeout = cfg.UninstallCommandTimeout
	}
	if cfg.SelfUpdateCommandTimeout > 0 {
		aeCfg.SelfUpdateCommandTimeout = cfg.SelfUpdateCommandTimeout
	}
	aeCfg.CertFilter.SubjectSuffix = cfg.AutoEnrollCertSubjectSuffix
	aeCfg.CertFilter.SANURIPrefix = cfg.AutoEnrollCertSANURIPrefix
	if err := validateAutoEnrollCertFilter(aeCfg.CertFilter); err != nil {
		return nil, err
	}

	certProvider := certstore.New()
	configStore := dpapi.New(cfg.AutoEnrollConfigPath, nil)
	tracker := state.NewTracker(state.StateStarting)
	executor := newCommandExecutor(cfg)

	return autoenroll.NewRunner(aeCfg, certProvider, registryReader, configStore, executor, tracker, logger)
}

// runAutoEnrollDryRun proves the cert + TLS config + persisted config path
// works without making any HTTP call. Exits non-zero on any failure so
// CI/operator smoke can rely on the exit code.
func runAutoEnrollDryRun(cfg config.Config, apiURLOverride string, logger *log.Logger) error {
	if runtime.GOOS != "windows" {
		return fmt.Errorf("auto-enroll dry-run requires Windows (current GOOS=%s)", runtime.GOOS)
	}
	aeCfg := autoenroll.Defaults()
	registryReader := winregistry.New()
	aeCfg.APIURL = resolveAutoEnrollAPIURL(cfg, apiURLOverride, registryReader, aeCfg.APIURL)
	aeCfg.CertFilter.SubjectSuffix = cfg.AutoEnrollCertSubjectSuffix
	aeCfg.CertFilter.SANURIPrefix = cfg.AutoEnrollCertSANURIPrefix
	if err := validateAutoEnrollCertFilter(aeCfg.CertFilter); err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	provider := certstore.New()
	material, err := provider.LoadEligibleCert(ctx, aeCfg.CertFilter)
	if err != nil {
		return fmt.Errorf("cert load: %w", err)
	}
	defer func() {
		if c, ok := material.TLSCertificate.PrivateKey.(interface{ Close() }); ok {
			c.Close()
		}
	}()
	logger.Printf("dry-run cert: subject=%q thumbprint_sha256=%s not_after=%s",
		material.Leaf.Subject.CommonName, material.ThumbprintSHA256, material.Leaf.NotAfter.Format(time.RFC3339))

	serverName, err := hostnameOnly(aeCfg.APIURL)
	if err != nil {
		return fmt.Errorf("derive server name from api url: %w", err)
	}
	tlsCfg, err := mtls.TLSConfigFor(mtls.Options{
		Cert:       material.TLSCertificate,
		ServerName: serverName,
		MinVersion: tls.VersionTLS12,
	})
	if err != nil {
		return fmt.Errorf("tls config: %w", err)
	}
	logger.Printf("dry-run tls config: server_name=%s min_version=%#x certs=%d",
		tlsCfg.ServerName, tlsCfg.MinVersion, len(tlsCfg.Certificates))

	store := dpapi.New(cfg.AutoEnrollConfigPath, nil)
	persisted, err := store.Read(ctx)
	if err != nil && !autoenroll.IsEmptyStore(err) {
		return fmt.Errorf("persisted config read: %w", err)
	}
	if autoenroll.IsEmptyStore(err) {
		logger.Printf("dry-run persisted config: empty store (first-run path would enroll)")
	} else {
		logger.Printf("dry-run persisted config: device_id=%s thumbprint_sha256=%s expires_at=%s",
			persisted.DeviceID, persisted.CertThumbprintSHA256, persisted.TokenExpiresAt.Format(time.RFC3339))
	}
	logger.Printf("dry-run OK — no HTTP call made")
	return nil
}

func validateAutoEnrollCertFilter(filter autoenroll.CertFilter) error {
	if strings.TrimSpace(filter.SubjectSuffix) == "" && strings.TrimSpace(filter.SANURIPrefix) == "" {
		return fmt.Errorf("auto-enroll cert filter requires ENDPOINT_AGENT_AUTO_ENROLL_CERT_SUBJECT_SUFFIX or ENDPOINT_AGENT_AUTO_ENROLL_CERT_SAN_URI_PREFIX")
	}
	return nil
}

// hostnameOnly extracts the host portion (without port) of a URL via
// net/url so IPv6 brackets, userinfo, and other URL edge-cases stay
// well-defined — Codex F9 absorb. Returns an error when the URL
// parses but carries no host, so the caller can fail fast rather than
// proceeding with an empty SNI value.
func hostnameOnly(raw string) (string, error) {
	if raw == "" {
		return "", fmt.Errorf("hostname: url is empty")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("hostname: parse %q: %w", raw, err)
	}
	host := u.Hostname()
	if host == "" {
		return "", fmt.Errorf("hostname: url %q has no host", raw)
	}
	return host, nil
}

func newRunner(cfg config.Config, logger *log.Logger) (*app.Runner, error) {
	client, err := protocol.NewClient(cfg.APIURL, cfg.SigningPathPrefix, &http.Client{Timeout: cfg.CommandTimeout})
	if err != nil {
		return nil, fmt.Errorf("client init failed: %w", err)
	}
	client.SetIdentity(cfg.CredentialID, cfg.Secret, cfg.DeviceID)
	runner := app.NewRunner(cfg, client, logger)
	// AG-026D: wire the HMAC credential store on every build. On
	// non-Windows builds the Read/Write methods return
	// hmacstore.ErrUnsupportedOS, which the runner treats as
	// "persistence disabled — fall through to env-token enroll" rather
	// than as a hard failure. This keeps cross-platform CI green
	// (Codex 019e7314 constraint #2) while production Windows agents
	// get the SCM-env-cache-immune restart path.
	runner.CredStore = hmacstore.New("", nil)
	configureSelfUpdateActivationHook(runner, cfg, logger)
	return runner, nil
}

func newCommandExecutor(cfg config.Config) *commands.LocalExecutor {
	return commands.NewPolicyAwareExecutor(
		cfg.AgentVersion,
		cfg.SelfUpdateCapabilityEnabled(),
		commands.UpdateAgentStagerOptions{
			AllowedHosts:        cfg.SelfUpdateAllowedHosts,
			SignerThumbprints:   cfg.SelfUpdateSignerThumbprints,
			AllowLabOnlySigning: cfg.SelfUpdateAllowLabOnlySigning,
			MaxRedirects:        cfg.SelfUpdateMaxRedirects,
			HardMaxBytes:        cfg.SelfUpdateHardMaxBytes,
		},
	)
}

func handleServiceCommand(args []string) {
	if len(args) == 0 {
		printServiceUsage()
		os.Exit(2)
	}

	action := args[0]
	options := winservice.DefaultOptions()
	flags := flag.NewFlagSet("service "+action, flag.ExitOnError)
	flags.StringVar(&options.Name, "name", options.Name, "Windows service name")
	flags.StringVar(&options.DisplayName, "display-name", options.DisplayName, "Windows service display name")
	flags.StringVar(&options.Description, "description", options.Description, "Windows service description")
	maintenanceToken := flags.String("maintenance-token", "", "maintenance token for stop/uninstall when ENDPOINT_AGENT_MAINTENANCE_TOKEN_SHA256 is configured")
	maintenanceTokenHash := flags.String("maintenance-token-sha256", "", "expected maintenance token sha256 hash override")
	if err := flags.Parse(args[1:]); err != nil {
		log.Fatalf("service command parse failed: %v", err)
	}

	var err error
	switch action {
	case "install":
		err = winservice.Install(options)
	case "uninstall":
		err = requireMaintenanceToken(*maintenanceToken, *maintenanceTokenHash)
		if err != nil {
			break
		}
		err = winservice.Uninstall(options)
	case "start":
		err = winservice.Start(options)
	case "stop":
		err = requireMaintenanceToken(*maintenanceToken, *maintenanceTokenHash)
		if err != nil {
			break
		}
		err = winservice.Stop(options)
	case "status":
		var status winservice.StatusSnapshot
		status, err = winservice.QueryStatus(options)
		if err == nil {
			fmt.Println(status.String())
		}
	default:
		printServiceUsage()
		os.Exit(2)
	}
	if err != nil {
		log.Fatalf("service %s failed: %v", action, err)
	}
	if action != "status" {
		fmt.Printf("service %s ok: %s\n", action, options.Normalized().Name)
	}
}

func printServiceUsage() {
	fmt.Fprintln(os.Stderr, "usage: endpoint-agent service <install|uninstall|start|stop|status> [--name name] [--display-name label] [--description text] [--maintenance-token token]")
}

func requireMaintenanceToken(token string, hashOverride string) error {
	expectedHash := hashOverride
	if expectedHash == "" {
		expectedHash = os.Getenv("ENDPOINT_AGENT_MAINTENANCE_TOKEN_SHA256")
	}
	if err := security.RequireMaintenanceToken(token, expectedHash); err != nil {
		return fmt.Errorf("%w: stop/uninstall requires --maintenance-token", err)
	}
	return nil
}

func handleDiagnoseCommand(args []string) {
	if len(args) == 0 {
		printDiagnoseUsage()
		os.Exit(2)
	}

	switch args[0] {
	case "identity":
		snapshot := identity.Collect(time.Now())
		if err := json.NewEncoder(os.Stdout).Encode(snapshot); err != nil {
			log.Fatalf("diagnose identity encode failed: %v", err)
		}
	case "local-users":
		localUsers, err := users.ListLocal()
		if err != nil {
			log.Fatalf("diagnose local-users failed: %v", err)
		}
		if err := json.NewEncoder(os.Stdout).Encode(localUsers); err != nil {
			log.Fatalf("diagnose local-users encode failed: %v", err)
		}
	case "local-admins":
		// READ-ONLY Gate-0 (Codex 019ea719): the machine account-domain SID and
		// the local-vs-domain classification of every Administrators-alias member,
		// so the last-enabled-local-admin lockout discriminator can be verified on
		// a domain-joined host WITHOUT any SAM write. Mutates nothing; on a correct
		// member workstation Domain Admins / domain members show
		// localUnderMachineDomain=false + a "*-skipped" classification.
		diag, err := users.DiagnoseLocalAdmins()
		if err != nil {
			log.Fatalf("diagnose local-admins failed: %v", err)
		}
		if err := json.NewEncoder(os.Stdout).Encode(diag); err != nil {
			log.Fatalf("diagnose local-admins encode failed: %v", err)
		}
	case "software":
		// Software inventory and winget readiness are deliberately
		// split into separate subcommands so a slow / hung winget
		// probe (LocalSystem can stall behind msstore source
		// agreements) does not stop an operator from getting at
		// the registry-only software snapshot. ProbeErrors on the
		// snapshot are visible in stdout JSON; exit code is 0
		// regardless so error isolation lives in the data, not the
		// exit status.
		snapshot := software.Collect(time.Now(), software.CollectOptions{})
		if err := json.NewEncoder(os.Stdout).Encode(snapshot); err != nil {
			log.Fatalf("diagnose software encode failed: %v", err)
		}
	case "winget":
		readiness := winget.Detect(time.Now())
		if err := json.NewEncoder(os.Stdout).Encode(readiness); err != nil {
			log.Fatalf("diagnose winget encode failed: %v", err)
		}
	case "winget-egress":
		// AG-026A — WinGet source/egress readiness preflight.
		//
		// Read-only: invokes `winget source list` and a fixed
		// `winget show --id 7zip.7zip` query (no install, no
		// upgrade, no source mutation), then runs DNS / TCP /
		// HTTPS reachability checks against the hard-coded
		// DefaultEgressTargets list. The subcommand is split
		// from `diagnose winget` so a slow / hung source listing
		// or stalled egress probe (proxied environments, blocked
		// CDN) does not stop an operator from getting at the
		// `--version` readiness via the older command.
		//
		// Exit code is 0 regardless of probe outcome — error
		// isolation lives in the JSON payload (ProbeError,
		// PackageQuery.ErrorReason, Egress.{DNS,TCP,HTTPS}[*].
		// ErrorReason), not the exit status. This matches the
		// AG-026 `winget` subcommand contract.
		readiness := winget.DetectSourceEgress(time.Now())
		if err := json.NewEncoder(os.Stdout).Encode(readiness); err != nil {
			log.Fatalf("diagnose winget-egress encode failed: %v", err)
		}
	case "hardware":
		// AG-035 — hardware probe (Codex 019e709c iter-1 must-fix:
		// diagnose hardware sub-command for field smoke).
		//
		// Read-only: invokes PowerShell + Get-CimInstance on
		// Windows (Win32_ComputerSystem, Win32_OperatingSystem,
		// Win32_Processor, Win32_BIOS, Win32_LogicalDisk,
		// Win32_NetworkAdapterConfiguration); returns
		// Supported=false with the UNSUPPORTED_PLATFORM probe
		// error on every other runtime. The output mirrors the
		// COLLECT_INVENTORY payload exactly (canonical Hardware
		// shape with the same schemaVersion the backend's
		// HardwareInventoryPayloadPolicy validates), so operators
		// can diff a live probe against a stored snapshot when
		// triaging preflight BLOCKs.
		//
		// Exit code is 0 regardless of probe outcome — error
		// isolation lives in the JSON payload (ProbeErrors[]
		// {code, summary}), not the exit status.
		snapshot := inventory.CollectHardware(time.Now())
		if err := json.NewEncoder(os.Stdout).Encode(snapshot); err != nil {
			log.Fatalf("diagnose hardware encode failed: %v", err)
		}
	case "services":
		// AG-039 — critical services inventory probe (field smoke).
		//
		// Read-only: opens each allowlisted service via the SCM with a
		// query-only access mask (SERVICE_QUERY_STATUS|SERVICE_QUERY_CONFIG)
		// and reports {name, present, state, startupMode} plus typed probe
		// errors. Mirrors the COLLECT_INVENTORY details.inventory.services
		// payload exactly, so an operator can diff a live probe against a
		// stored snapshot when triaging a hidden "Hizmetler" table or a
		// probeComplete=false fail-closed state.
		//
		// Exit code is 0 regardless of probe outcome — error isolation lives
		// in the JSON payload (probeComplete + probeErrors[]), not the exit
		// status (same contract as diagnose hardware/software).
		result := inventory.ProbeServices(context.Background(), time.Now)
		if err := json.NewEncoder(os.Stdout).Encode(result); err != nil {
			log.Fatalf("diagnose services encode failed: %v", err)
		}
	default:
		printDiagnoseUsage()
		os.Exit(2)
	}
}

func printDiagnoseUsage() {
	fmt.Fprintln(os.Stderr, "usage: endpoint-agent diagnose <identity|local-users|local-admins|software|winget|winget-egress|hardware|services>")
}
