package autoenroll

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"platform-agent/internal/commands"
	"platform-agent/internal/inventory"
	"platform-agent/internal/mtls"
	"platform-agent/internal/protocol"
	"platform-agent/internal/state"
)

// CertProvider returns the currently eligible machine certificate for the
// auto-enroll wire. The Windows implementation (internal/platform/windows/certstore)
// fetches it from LocalMachine\My; non-Windows builds return ErrUnsupportedOS.
type CertProvider interface {
	LoadEligibleCert(ctx context.Context, filter CertFilter) (CertMaterial, error)
}

// RegistryReader reads values out of HKLM. Used for the
// EnrollmentJitterSeconds knob and the Mode=auto-enroll service-mode
// fallback. Non-Windows implementations may return defaults silently
// (Codex F9 absorb: non-Windows silent ignore).
type RegistryReader interface {
	ReadInt(key, value string, def int) int
	ReadString(key, value, def string) string
}

// Runner drives the auto-enroll flow. It is intentionally separate from
// internal/app.Runner — the HMAC and mTLS wires share no auth state, and
// mixing them in one Runner makes regression in the HMAC path likely
// (Codex Q3 absorb).
type Runner struct {
	Config       Config
	CertProvider CertProvider
	Registry     RegistryReader
	ConfigStore  ConfigStore
	StateTracker *state.Tracker
	Executor     *commands.LocalExecutor
	Logger       *log.Logger

	// httpClient and wireClient are built lazily on first use, because
	// constructing them requires loading the cert (which may fail on the
	// retry loop).
	httpClient *http.Client
	wireClient *Client

	// loadedCert is the cert material currently driving the mTLS handshake.
	// Rotated whenever the cert thumbprint changes.
	loadedCert CertMaterial
}

// Config groups the knobs the Runner reads at construction. Values come
// from internal/config plus the registry; secrets do NOT belong here
// (Codex F3 absorb).
type Config struct {
	// AgentVersion advertised to the backend.
	AgentVersion string

	// APIURL is the full canonical base path the Runner dials, e.g.
	// https://endpoint-agent-mtls.testai.acik.com/api/v1/endpoint-agent
	// — Codex F4 + iter-4 F1 absorb: full base path, not host only.
	APIURL string

	// CertFilter applied to the cert store query.
	CertFilter CertFilter

	// HeartbeatInterval between heartbeat ticks.
	HeartbeatInterval time.Duration
	// CommandPollInterval between command poll ticks.
	CommandPollInterval time.Duration
	// CommandTimeout caps individual command execution time.
	CommandTimeout time.Duration
	// InstallCommandTimeout overrides CommandTimeout specifically for
	// the AG-027 INSTALL_SOFTWARE command type. WinGet installs
	// routinely exceed the lightweight 120s CommandTimeout. Default
	// 30 min — matches the agent-side hard cap in winget.RunInstall
	// (Codex 019e6c0d iter-3 absorb).
	InstallCommandTimeout time.Duration
	// UninstallCommandTimeout overrides CommandTimeout for the AG-028
	// UNINSTALL_SOFTWARE command type. MSI uninstall paths can run
	// repair / custom-action / network wait phases longer than the
	// 5-min install median; 30-min default matches the agent-side
	// hard cap in winget.RunUninstall (Codex 019e8de2 iter-3 absorb).
	UninstallCommandTimeout time.Duration
	// SelfUpdateCommandTimeout caps AG-029 UPDATE_AGENT staging.
	SelfUpdateCommandTimeout time.Duration
	// HTTPTimeout caps individual mTLS request time.
	HTTPTimeout time.Duration

	// TokenRefreshWindow triggers /service-token/refresh when the current
	// token's remaining TTL drops below this. Default 2h.
	TokenRefreshWindow time.Duration

	// CertRenewalWindow triggers proactive cert reload + idempotent
	// auto-enroll reissue when the current cert's remaining validity drops
	// below this. Default 7 days.
	CertRenewalWindow time.Duration

	// NoCertBackoff is the cap on the retry interval when the cert store
	// has no eligible cert yet (GPO race during first AD CS auto-enroll).
	NoCertBackoff time.Duration
}

// Defaults returns a Config populated with the production defaults agreed
// in the Codex iter-3 plan. Callers override only the fields they need
// (typically APIURL and AgentVersion).
func Defaults() Config {
	return Config{
		AgentVersion:             "0.2.0-dev",
		APIURL:                   "https://endpoint-agent-mtls.testai.acik.com/api/v1/endpoint-agent",
		CertFilter:               DefaultCertFilter(),
		HeartbeatInterval:        60 * time.Second,
		CommandPollInterval:      30 * time.Second,
		CommandTimeout:           120 * time.Second,
		InstallCommandTimeout:    30 * time.Minute,
		UninstallCommandTimeout:  30 * time.Minute,
		SelfUpdateCommandTimeout: 30 * time.Minute,
		HTTPTimeout:              30 * time.Second,
		TokenRefreshWindow:       2 * time.Hour,
		CertRenewalWindow:        7 * 24 * time.Hour,
		NoCertBackoff:            60 * time.Minute,
	}
}

// NewRunner constructs a Runner. The CertProvider, Registry, ConfigStore
// and Executor are all required — the Runner does not silently substitute
// defaults to avoid hiding a misconfigured caller. Logger may be nil; in
// that case messages are discarded.
func NewRunner(cfg Config, cert CertProvider, reg RegistryReader, store ConfigStore, exec *commands.LocalExecutor, tracker *state.Tracker, logger *log.Logger) (*Runner, error) {
	if cert == nil {
		return nil, fmt.Errorf("autoenroll: cert provider is required")
	}
	if reg == nil {
		return nil, fmt.Errorf("autoenroll: registry reader is required")
	}
	if store == nil {
		return nil, fmt.Errorf("autoenroll: config store is required")
	}
	if exec == nil {
		return nil, fmt.Errorf("autoenroll: command executor is required")
	}
	if tracker == nil {
		return nil, fmt.Errorf("autoenroll: state tracker is required")
	}
	if cfg.APIURL == "" {
		return nil, fmt.Errorf("autoenroll: api url is empty")
	}
	if _, err := url.Parse(cfg.APIURL); err != nil {
		return nil, fmt.Errorf("autoenroll: api url invalid: %w", err)
	}
	// AG-038: register the live agent config so the self-diagnostics probe
	// reports the REAL AgentVersion + a hash of the REAL APIURL. The
	// auto-enroll path authenticates with an mTLS cert + service token, not
	// an HMAC credential ID, so no credentialID is passed (and none would
	// ever reach the wire / hash anyway).
	inventory.SetDiagnosticsConfig(cfg.AgentVersion, cfg.APIURL, "")
	return &Runner{
		Config:       cfg,
		CertProvider: cert,
		Registry:     reg,
		ConfigStore:  store,
		Executor:     exec,
		StateTracker: tracker,
		Logger:       logger,
	}, nil
}

// RunOnce executes a single enroll/heartbeat/command iteration and returns.
// First-run jitter is applied only when the persisted store is empty.
func (r *Runner) RunOnce(ctx context.Context) error {
	persisted, err := r.ConfigStore.Read(ctx)
	if err != nil && !IsEmptyStore(err) {
		return fmt.Errorf("read persisted config: %w", err)
	}
	// Codex F11 absorb: validate decoded persisted state before using
	// it. A corrupt blob (missing cert_thumbprint, zero expiry, etc.)
	// must not silently propagate into the heartbeat / commands loop.
	if !persisted.IsZero() {
		if err := persisted.Validate(); err != nil {
			return fmt.Errorf("persisted config corrupted (operator intervention required): %w", err)
		}
	}

	if persisted.IsZero() {
		jitter := r.Registry.ReadInt(`HKLM:\SOFTWARE\EndpointAgent`, "EnrollmentJitterSeconds", 0)
		if jitter > 0 {
			d := Jitter(jitter)
			r.logf("auto-enroll jitter: sleeping %v (R26 mass enrollment storm mitigation)", d)
			if err := SleepWithContext(ctx, d); err != nil {
				return err
			}
		}
	}

	if err := r.ensureCert(ctx); err != nil {
		return err
	}

	persisted, err = r.reconcileEnrollment(ctx, persisted)
	if err != nil {
		return err
	}

	persisted, err = r.maybeRefreshToken(ctx, persisted)
	if err != nil {
		return err
	}

	if err := r.heartbeat(ctx, persisted); err != nil {
		return err
	}

	return r.pollAndExecute(ctx, persisted)
}

// RunLoop runs first RunOnce, then ticks at CommandPollInterval. Errors
// from a single iteration are logged and the loop continues; the only
// terminating returns are ctx.Done(), ErrAuthFailure (fail-closed), and
// "grace window expired".
func (r *Runner) RunLoop(ctx context.Context) error {
	// In the RunLoop path, an empty cert store is recoverable — the AD
	// CS auto-enrollment GPO may not have fired yet. waitForCert applies
	// the bounded backoff schedule (5/10/20/40/60 min capped) so the
	// service keeps the right cadence rather than re-hammering the store
	// every CommandPollInterval (Codex F5 absorb).
	if err := r.waitForCert(ctx); err != nil {
		return err
	}
	if err := r.RunOnce(ctx); err != nil {
		if r.isFatal(err) {
			return err
		}
		r.logf("auto-enroll iteration failed: %v", err)
	}

	ticker := time.NewTicker(r.Config.CommandPollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			r.StateTracker.Stop()
			return ctx.Err()
		case <-ticker.C:
			if err := r.iterate(ctx); err != nil {
				if r.isFatal(err) {
					return err
				}
				r.logf("auto-enroll iteration failed: %v", err)
			}
		}
	}
}

// iterate is RunOnce minus the first-run jitter — used by the ticker loop.
func (r *Runner) iterate(ctx context.Context) error {
	persisted, err := r.ConfigStore.Read(ctx)
	if err != nil && !IsEmptyStore(err) {
		return fmt.Errorf("read persisted config: %w", err)
	}
	if !persisted.IsZero() {
		if err := persisted.Validate(); err != nil {
			return fmt.Errorf("persisted config corrupted (operator intervention required): %w", err)
		}
	}

	if err := r.ensureCert(ctx); err != nil {
		return err
	}

	persisted, err = r.reconcileEnrollment(ctx, persisted)
	if err != nil {
		return err
	}

	persisted, err = r.maybeRefreshToken(ctx, persisted)
	if err != nil {
		return err
	}

	if err := r.heartbeat(ctx, persisted); err != nil {
		return err
	}

	return r.pollAndExecute(ctx, persisted)
}

// isFatal reports whether err must terminate the loop. ErrAuthFailure and
// grace-window-expired are both fail-closed; everything else is transient
// and gets a retry next tick.
func (r *Runner) isFatal(err error) bool {
	return errors.Is(err, ErrAuthFailure) || strings.Contains(err.Error(), "grace window expired")
}

// ensureCert loads the eligible cert and, when the thumbprint changes,
// rebuilds the mTLS client. RunOnce / --dry-run callers see the first
// error immediately (deterministic exit); the RunLoop path applies the
// no-cert backoff schedule through waitForCert before calling ensureCert
// again (Codex F5 absorb).
func (r *Runner) ensureCert(ctx context.Context) error {
	cert, err := r.CertProvider.LoadEligibleCert(ctx, r.Config.CertFilter)
	if err != nil {
		return err
	}

	if r.loadedCert.ThumbprintSHA256 == cert.ThumbprintSHA256 && r.wireClient != nil {
		// #147: LoadEligibleCert acquired a fresh private-key handle + cert
		// context for this redundant reload; release it so the service loop
		// does not leak a handle/context every CommandPollInterval.
		closeCertMaterialSigner(cert)
		return nil
	}

	// #147: if any client-build step below fails after we acquired this cert's
	// signer, release it so a misconfig retry loop does not leak handles.
	// Cleared once ownership transfers to r.loadedCert.
	committed := false
	defer func() {
		if !committed {
			closeCertMaterialSigner(cert)
		}
	}()

	host, err := serverNameFromURL(r.Config.APIURL)
	if err != nil {
		return err
	}
	httpClient, err := mtls.NewClient(mtls.Options{
		Cert:       cert.TLSCertificate,
		ServerName: host,
		Timeout:    r.Config.HTTPTimeout,
		MinVersion: tls.VersionTLS12,
	})
	if err != nil {
		return fmt.Errorf("build mtls client: %w", err)
	}
	wire, err := NewClient(r.Config.APIURL, httpClient)
	if err != nil {
		return fmt.Errorf("build wire client: %w", err)
	}

	// Release idle keep-alives bound to the previous cert before
	// replacing the transport — Codex F6 absorb. Without this the
	// old mTLS connections live another IdleConnTimeout (~90s) and
	// might serve requests under the old cert identity.
	previous := r.loadedCert
	if r.httpClient != nil {
		r.httpClient.CloseIdleConnections()
	}
	r.httpClient = httpClient
	r.wireClient = wire
	r.loadedCert = cert
	committed = true
	// #147: release the superseded cert's signer (key handle + context) once its
	// idle mTLS connections are closed and it is no longer referenced. No-op on
	// first load (zero CertMaterial) or for signers without Close.
	closeCertMaterialSigner(previous)
	r.logf("auto-enroll cert loaded: subject=%q thumbprint_sha256=%s not_after=%s",
		cert.Leaf.Subject.CommonName, cert.ThumbprintSHA256, cert.Leaf.NotAfter.Format(time.RFC3339))
	return nil
}

// closeCertMaterialSigner releases the private-key handle (and any owned
// platform resources) held by a CertMaterial's signer when it implements
// Close() — the Windows cngSigner does (#147). No-op on platforms / signers
// that do not (e.g. a zero CertMaterial, or non-Windows software keys).
func closeCertMaterialSigner(m CertMaterial) {
	if c, ok := m.TLSCertificate.PrivateKey.(interface{ Close() }); ok {
		c.Close()
	}
}

// noCertBackoffSchedule returns the bounded retry intervals used when
// the cert store is empty (AD CS auto-enrollment race). The cap stays
// at 60 minutes; the schedule is exposed so tests can shrink it.
func noCertBackoffSchedule() []time.Duration {
	return []time.Duration{
		5 * time.Minute,
		10 * time.Minute,
		20 * time.Minute,
		40 * time.Minute,
		60 * time.Minute,
	}
}

// waitForCert applies the bounded backoff schedule until either ctx is
// cancelled, a cert appears, or a non-ErrNoCertMatch error surfaces.
// Used by RunLoop only; RunOnce and --dry-run skip this and surface the
// first ErrNoCertMatch immediately (Codex F5 absorb).
func (r *Runner) waitForCert(ctx context.Context) error {
	schedule := noCertBackoffSchedule()
	attempt := 0
	for {
		_, err := r.CertProvider.LoadEligibleCert(ctx, r.Config.CertFilter)
		if err == nil {
			return nil
		}
		if !errors.Is(err, ErrNoCertMatch) {
			return err
		}
		d := schedule[len(schedule)-1]
		if attempt < len(schedule) {
			d = schedule[attempt]
		}
		// Small additive jitter (up to 30s) avoids a synchronized fleet
		// retry storm when AD CS comes back up.
		d += Jitter(30)
		r.logf("no eligible cert (attempt=%d), retry in %v", attempt+1, d)
		if err := SleepWithContext(ctx, d); err != nil {
			return err
		}
		attempt++
	}
}

// reconcileEnrollment makes the persisted state match the currently
// loaded cert. The decision tree:
//
//   - empty store → POST /endpoint-enrollments/auto, persist response.
//   - cert thumbprint changed → idempotent reissue via auto-enroll, persist.
//   - cert thumbprint same + token already expired locally → idempotent
//     reissue via auto-enroll (refresh would 401 because bearer is dead).
//   - otherwise → leave persisted as-is.
func (r *Runner) reconcileEnrollment(ctx context.Context, persisted PersistedConfig) (PersistedConfig, error) {
	now := time.Now()
	current := r.loadedCert.ThumbprintSHA256

	needsReissue := persisted.IsZero() ||
		persisted.CertThumbprintChanged(current) ||
		persisted.TokenExpired(now)

	if !needsReissue {
		return persisted, nil
	}

	req := AutoEnrollRequest{
		OSInfo:       collectOSInfo(r.Config.AgentVersion),
		AgentVersion: r.Config.AgentVersion,
	}
	resp, err := r.wireClient.AutoEnroll(ctx, req)
	if err != nil {
		return persisted, fmt.Errorf("auto-enroll: %w", err)
	}

	cfg := PersistedConfig{
		DeviceID:             resp.DeviceID,
		ServiceToken:         resp.ServiceToken,
		TokenExpiresAt:       resp.TokenExpiresAt,
		CertThumbprintSHA256: current,
		CertThumbprintSHA1:   r.loadedCert.ThumbprintSHA1,
		Issued:               now,
	}
	if err := cfg.Validate(); err != nil {
		return persisted, fmt.Errorf("auto-enroll response invalid: %w", err)
	}
	if err := r.ConfigStore.Write(ctx, cfg); err != nil {
		return persisted, fmt.Errorf("persist enrollment: %w", err)
	}

	r.logf("auto-enroll reissue: device_id=%s existing=%t expires_at=%s",
		cfg.DeviceID, resp.IsExistingDevice, cfg.TokenExpiresAt.Format(time.RFC3339))
	return cfg, nil
}

// maybeRefreshToken triggers /service-token/refresh when the token TTL
// dips into the refresh window. Already-expired tokens are NOT refreshed
// here — reconcileEnrollment handled them with the auto-enroll reissue
// path (Codex F11 absorb).
func (r *Runner) maybeRefreshToken(ctx context.Context, persisted PersistedConfig) (PersistedConfig, error) {
	now := time.Now()
	if persisted.IsZero() || persisted.TokenExpired(now) {
		return persisted, nil
	}
	if !persisted.TokenExpiringWithin(now, r.Config.TokenRefreshWindow) {
		return persisted, nil
	}

	resp, err := r.wireClient.RefreshToken(ctx, persisted.ServiceToken)
	if err != nil {
		if errors.Is(err, ErrAuthFailure) {
			return persisted, err
		}
		// Transient refresh failure: keep the existing token; the next
		// loop iteration will try again, and once the token does expire
		// reconcileEnrollment will take the reissue path.
		r.logf("token refresh failed (will retry): %v", err)
		return persisted, nil
	}

	persisted.ServiceToken = resp.ServiceToken
	persisted.TokenExpiresAt = resp.TokenExpiresAt
	if err := persisted.Validate(); err != nil {
		return persisted, fmt.Errorf("token refresh response invalid: %w", err)
	}
	if err := r.ConfigStore.Write(ctx, persisted); err != nil {
		return persisted, fmt.Errorf("persist refreshed token: %w", err)
	}
	r.logf("token refreshed: expires_at=%s", persisted.TokenExpiresAt.Format(time.RFC3339))
	return persisted, nil
}

// heartbeat sends a single heartbeat and enforces the grace-window
// contract plus the accepted-false fail-closed contract (Codex F3
// absorb). 200 + accepted=false MUST stop the agent from polling
// commands — the backend uses this to signal "device disabled" or
// "device-state rejected" without dropping to 401/403, and the agent
// must respect that as terminal.
func (r *Runner) heartbeat(ctx context.Context, persisted PersistedConfig) error {
	snapshot := inventory.Collect(r.Config.AgentVersion, time.Now())
	currentState := r.StateTracker.RecordSuccess()
	caps := capabilityStrings(r.Executor.Capabilities)
	req := HeartbeatRequest{
		Hostname:     snapshot.Hostname,
		OSType:       string(snapshot.OSFamily),
		Architecture: snapshot.Architecture,
		AgentVersion: snapshot.AgentVersion,
		State:        string(currentState),
		Capabilities: caps,
		Timestamp:    time.Now(),
	}
	resp, err := r.wireClient.Heartbeat(ctx, persisted.ServiceToken, req)
	if err != nil {
		r.StateTracker.RecordFailure(time.Now())
		return err
	}
	if !resp.Accepted {
		r.StateTracker.RecordFailure(time.Now())
		return fmt.Errorf("%w: heartbeat accepted=false status=%q", ErrAuthFailure, resp.Status)
	}
	if resp.GraceWindow && resp.GraceUntil != nil {
		ref := resp.ServerTime
		if ref.IsZero() {
			ref = time.Now()
		}
		if ref.After(*resp.GraceUntil) {
			return fmt.Errorf("grace window expired (server_time=%s > grace_until=%s)",
				ref.Format(time.RFC3339), resp.GraceUntil.Format(time.RFC3339))
		}
		r.logf("backend grace window active until %s (CRL outage suspected); continuing",
			resp.GraceUntil.Format(time.RFC3339))
	}
	// Defense-in-depth: local NotAfter check independent of backend
	// (Codex Q4 absorb).
	if !r.loadedCert.Leaf.NotAfter.IsZero() && time.Now().After(r.loadedCert.Leaf.NotAfter) {
		return fmt.Errorf("local cert expired (not_after=%s)", r.loadedCert.Leaf.NotAfter.Format(time.RFC3339))
	}
	return nil
}

// pollAndExecute fetches one queued command (if any) and runs it.
func (r *Runner) pollAndExecute(ctx context.Context, persisted PersistedConfig) error {
	pollStart := time.Now()
	command, err := r.wireClient.NextCommand(ctx, persisted.ServiceToken)
	// AG-038: record the NextCommand round-trip so a subsequent
	// COLLECT_INVENTORY diagnostics probe reports the REAL last-poll latency.
	// Measured even on ErrNoCommand (204) — an empty poll is still a
	// representative backend round-trip.
	inventory.RecordPollLatency(int(time.Since(pollStart) / time.Millisecond))
	if errors.Is(err, ErrNoCommand) {
		r.logf("no command available")
		return nil
	}
	if err != nil {
		r.StateTracker.RecordFailure(time.Now())
		return err
	}

	// AG-027 (Codex 019e6c0d iter-3 absorb): per-command-type timeout
	// mirrored from internal/app/runner.go::RunOnce so the auto-enroll
	// path honours the documented 30-min INSTALL_SOFTWARE hard cap
	// instead of the lightweight 120s default that read-only commands
	// inherit.
	// AG-028 (Codex 019e8de2 iter-3 absorb): UNINSTALL_SOFTWARE also
	// gets a per-command-type timeout (30 min default), parity with
	// INSTALL_SOFTWARE. Without this branch the auto-enroll path
	// truncated uninstalls at 120s.
	commandTimeout := r.Config.CommandTimeout
	switch command.Type {
	case protocol.CommandInstallSoftware:
		if r.Config.InstallCommandTimeout > 0 {
			commandTimeout = r.Config.InstallCommandTimeout
		}
	case protocol.CommandUninstallSoftware:
		if r.Config.UninstallCommandTimeout > 0 {
			commandTimeout = r.Config.UninstallCommandTimeout
		}
	case protocol.CommandUpdateAgent:
		if r.Config.SelfUpdateCommandTimeout > 0 {
			commandTimeout = r.Config.SelfUpdateCommandTimeout
		}
	}
	commandCtx, cancel := context.WithTimeout(ctx, commandTimeout)
	defer cancel()
	result := r.Executor.Execute(commandCtx, command)
	if err := r.wireClient.SubmitResult(ctx, persisted.ServiceToken, result); err != nil {
		r.StateTracker.RecordFailure(time.Now())
		return err
	}
	r.logf("command %s finished with %s", command.CommandID, result.Status)
	return nil
}

func (r *Runner) logf(format string, args ...interface{}) {
	if r.Logger != nil {
		r.Logger.Printf(format, args...)
	}
}

// collectOSInfo packages the host self-description for the auto-enroll
// body. inventory.Collect is reused for parity with the HMAC path. The
// os_version field stays empty until inventory exposes a richer
// platform-version probe; the backend tolerates omitempty per
// AutoEnrollRequest schema.
func collectOSInfo(agentVersion string) OSInfo {
	snap := inventory.Collect(agentVersion, time.Now())
	return OSInfo{
		OSType:       string(snap.OSFamily),
		Architecture: snap.Architecture,
	}
}

// capabilityStrings maps protocol.CommandType slice to JSON-ready strings.
func capabilityStrings(in []protocol.CommandType) []string {
	out := make([]string, len(in))
	for i, t := range in {
		out[i] = string(t)
	}
	return out
}

// serverNameFromURL extracts the host portion (without port) for SNI.
func serverNameFromURL(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("parse api url: %w", err)
	}
	host := u.Hostname()
	if host == "" {
		return "", fmt.Errorf("api url missing host: %q", raw)
	}
	return host, nil
}
