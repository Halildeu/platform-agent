package app

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	"platform-agent/internal/commands"
	"platform-agent/internal/config"
	"platform-agent/internal/hmacstore"
	"platform-agent/internal/inventory"
	"platform-agent/internal/protocol"
	"platform-agent/internal/state"
)

// CredentialStore is the runner's view onto the persisted HMAC
// credential. Decoupled from internal/hmacstore so tests can swap in a
// memory-backed fake and so non-Windows builds can wire nil without
// importing dpapi. The concrete production implementation is
// *hmacstore.Store.
type CredentialStore interface {
	Read(ctx context.Context) (hmacstore.Credential, error)
	Write(ctx context.Context, cred hmacstore.Credential) error
	Invalidate(ctx context.Context) error
}

type Runner struct {
	Config       config.Config
	Client       *protocol.Client
	Executor     *commands.LocalExecutor
	StateTracker *state.Tracker
	Logger       *log.Logger
	// CredStore persists the HMAC device credential across service
	// restarts (AG-026D). On non-Windows builds the store returns
	// hmacstore.ErrUnsupportedOS for Read/Write; the runner treats
	// that as "persistence disabled — env-token enroll on every cold
	// start". Production Windows wiring populates this with
	// *hmacstore.Store.
	CredStore CredentialStore
	// credentialPersisted records whether the credential currently
	// held by Client was successfully written to the on-disk store
	// during the most recent enroll() call in THIS process lifetime.
	// Codex 019e7314 iter-1 must_fix #1: the "hmac credential
	// confirmed" sentinel the AG-026C installer gate keys on MUST
	// reflect "persisted AND heartbeat-accepted", not heartbeat
	// success alone. When false (hydrate-from-store cold start or
	// persist-failed enroll), heartbeat emits a degraded "credential
	// accepted (not persisted)" sentinel that the installer ignores.
	credentialPersisted bool
}

func NewRunner(cfg config.Config, client *protocol.Client, logger *log.Logger) *Runner {
	executor := newExecutor(cfg)
	// AG-038: register the live agent config so the self-diagnostics probe
	// reports the REAL AgentVersion + a hash of the REAL APIURL (not the
	// "unknown" placeholder). CredentialID is recorded for credential-presence
	// reasoning only — it is never emitted on the wire nor hashed.
	inventory.SetDiagnosticsConfig(cfg.AgentVersion, cfg.APIURL, cfg.CredentialID)
	return &Runner{
		Config:       cfg,
		Client:       client,
		Executor:     executor,
		StateTracker: state.NewTracker(state.StateStarting),
		Logger:       logger,
	}
}

func (r *Runner) RunOnce(ctx context.Context) error {
	if r.Client == nil {
		return fmt.Errorf("protocol client is required")
	}
	if r.Executor == nil {
		r.Executor = newExecutor(r.Config)
	}
	if r.StateTracker == nil {
		r.StateTracker = state.NewTracker(state.StateStarting)
	}

	// AG-026D cold-start hydration: before the first enrollment attempt
	// of this process, try to load a persisted credential from disk.
	// This is the path that bypasses the operator-bound "fresh
	// enrollment token on every service restart" friction the SRB
	// rollout hit in production.
	if !r.Client.IsEnrolled() && r.CredStore != nil {
		r.hydrateFromStore(ctx)
	}

	if !r.Client.IsEnrolled() {
		if err := r.enroll(ctx); err != nil {
			r.StateTracker.RecordFailure(time.Now())
			return err
		}
	}
	if err := r.heartbeat(ctx); err != nil {
		// AG-026D: backend rejected our signed heartbeat with 401 —
		// the persisted credential has been revoked / rotated /
		// expired. Take the controlled re-enroll path. Codex 019e7314
		// constraint #4: do NOT delete the persisted blob here;
		// either a successful re-enrollment will replace it atomically
		// via Write, or we leave the old blob in place and surface a
		// telemetry sentinel for the operator. Only an enrollment
		// token in env makes this path possible — without one we
		// surface the original 401 and fail-closed.
		if protocol.IsUnauthorized(err) && r.Config.EnrollmentToken != "" {
			r.logf("heartbeat 401 — persisted credential rejected; attempting controlled re-enroll")
			r.Client.SetIdentity("", "", "")
			if reEnrollErr := r.enroll(ctx); reEnrollErr != nil {
				r.StateTracker.RecordFailure(time.Now())
				return fmt.Errorf("re-enroll after 401 failed: %w", reEnrollErr)
			}
			if hbErr := r.heartbeat(ctx); hbErr != nil {
				r.StateTracker.RecordFailure(time.Now())
				return fmt.Errorf("heartbeat after re-enroll failed: %w", hbErr)
			}
		} else {
			r.StateTracker.RecordFailure(time.Now())
			return err
		}
	}

	pollStart := time.Now()
	command, err := r.Client.NextCommand(ctx)
	// AG-038: record the NextCommand round-trip so a subsequent
	// COLLECT_INVENTORY diagnostics probe reports the REAL last-poll
	// latency rather than 0. Measured even on ErrNoCommand (204) — an
	// empty poll is still a representative backend round-trip.
	inventory.RecordPollLatency(int(time.Since(pollStart) / time.Millisecond))
	if errors.Is(err, protocol.ErrNoCommand) {
		r.logf("no command available")
		return nil
	}
	if err != nil {
		r.StateTracker.RecordFailure(time.Now())
		return err
	}

	// AG-027 (Codex 019e6c0d iter-2): per-command-type timeout.
	// INSTALL_SOFTWARE needs a longer ceiling (30 min default) because
	// WinGet installs can run 30s–5min and occasionally longer for
	// vendor MSI bundles. AG-028 (Codex 019e8de2 iter-3 absorb):
	// UNINSTALL_SOFTWARE picks `UninstallCommandTimeout` (30 min
	// default). Without this branch the agent enforces 120s which
	// truncates MSI uninstall paths long before the 30-min hard cap
	// documented in uninstall_winget.go. Everything else stays on the
	// lightweight CommandTimeout.
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
	if err := r.Client.SubmitResult(ctx, result); err != nil {
		r.StateTracker.RecordFailure(time.Now())
		return err
	}
	r.logf("command %s finished with %s", command.CommandID, result.Status)
	if result.Status != protocol.CommandStatusSucceeded {
		r.logf("command %s detail: summary=%q details=%v", command.CommandID, result.Summary, result.Details)
	}
	return nil
}

func newExecutor(cfg config.Config) *commands.LocalExecutor {
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

func (r *Runner) RunLoop(ctx context.Context) error {
	if err := r.RunOnce(ctx); err != nil {
		r.logf("agent iteration failed: %v", err)
	}

	ticker := time.NewTicker(r.Config.CommandPollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			r.StateTracker.Stop()
			return ctx.Err()
		case <-ticker.C:
			if err := r.RunOnce(ctx); err != nil {
				r.logf("agent iteration failed: %v", err)
			}
		}
	}
}

// hydrateFromStore tries to load a persisted credential and install it
// on the protocol client. On ErrEmpty it returns silently; on ErrInvalid
// or any decryption / decode failure it logs a sentinel but does NOT
// touch the on-disk blob (Codex 019e7314 constraint #4) — the runner
// will fall through to the env-token enroll path and the operator can
// inspect the corrupt blob.
func (r *Runner) hydrateFromStore(ctx context.Context) {
	cred, err := r.CredStore.Read(ctx)
	if err != nil {
		if errors.Is(err, hmacstore.ErrEmpty) {
			return
		}
		if errors.Is(err, hmacstore.ErrUnsupportedOS) {
			// Non-Windows production-style wiring — defensive log;
			// real production runs only on Windows.
			r.logf("hmac credential store unsupported on this OS; falling back to env-token enroll")
			return
		}
		r.logf("hmac credential store read failed (keeping blob, falling through to enroll): %v", err)
		return
	}
	r.Client.SetIdentity(cred.CredentialKeyID, cred.Secret, cred.DeviceID)
	r.Config.CredentialID = cred.CredentialKeyID
	r.Config.Secret = cred.Secret
	r.Config.DeviceID = cred.DeviceID
	// Hydrate-from-store does NOT count as "persisted in this process":
	// the store wrote the blob in a previous process. credentialPersisted
	// stays false so the heartbeat sentinel does not double-confirm a
	// blob we did not produce. Codex 019e7314 iter-1 must_fix #1.
	r.credentialPersisted = false
	// AG-038: a cold-start hydrate populated CredentialID — refresh the
	// diagnostics provider so credential-presence reasoning is accurate.
	// CredentialID stays off the wire / out of the hash.
	inventory.SetDiagnosticsConfig(r.Config.AgentVersion, r.Config.APIURL, r.Config.CredentialID)
	r.logf("hmac credential loaded from store device=%s credential=%s", cred.DeviceID, cred.CredentialKeyID)
}

func (r *Runner) enroll(ctx context.Context) error {
	if r.Config.EnrollmentToken == "" {
		return fmt.Errorf("agent is not enrolled and ENDPOINT_AGENT_ENROLLMENT_TOKEN is empty")
	}
	snapshot := inventory.Collect(r.Config.AgentVersion, time.Now())
	response, err := r.Client.Enroll(ctx, protocol.EnrollRequest{
		EnrollmentToken:    r.Config.EnrollmentToken,
		Hostname:           snapshot.Hostname,
		OsType:             string(snapshot.OSFamily),
		AgentVersion:       r.Config.AgentVersion,
		MachineFingerprint: inventory.MachineFingerprint(),
	})
	if err != nil {
		return err
	}
	r.Config.CredentialID = response.CredentialKeyID
	r.Config.Secret = response.Secret
	r.Config.DeviceID = response.DeviceID
	// Reset before attempting persist — a previous successful enroll in
	// the same process must not leak its persisted state into the new
	// credential's sentinel.
	r.credentialPersisted = false
	r.logf("agent enrolled: device=%s credential=%s", response.DeviceID, response.CredentialKeyID)

	// AG-026D Codex 019e7314 constraint #5 (iter-1 must_fix #1
	// tightened): persist before returning so the first heartbeat
	// already runs against the on-disk record. A persistence failure is
	// NOT fatal — in-memory credentials still work for the current
	// process lifetime — but it MUST NOT promote to the "hmac
	// credential confirmed" sentinel that the AG-026C installer keys
	// the token-cleanup gate on; r.credentialPersisted stays false so
	// heartbeat falls back to the degraded sentinel below.
	if r.CredStore != nil {
		cred := hmacstore.Credential{
			DeviceID:        response.DeviceID,
			CredentialKeyID: response.CredentialKeyID,
			Secret:          response.Secret,
			ServerTime:      response.ServerTime,
			Issued:          time.Now(),
		}
		if err := r.CredStore.Write(ctx, cred); err != nil {
			if errors.Is(err, hmacstore.ErrUnsupportedOS) {
				r.logf("hmac credential persistence skipped: non-Windows build")
			} else {
				r.logf("hmac credential persist failed (in-memory only — next restart will need fresh token): %v", err)
			}
		} else {
			r.credentialPersisted = true
		}
	}
	return nil
}

func (r *Runner) heartbeat(ctx context.Context) error {
	snapshot := inventory.Collect(r.Config.AgentVersion, time.Now())
	currentState := r.StateTracker.RecordSuccess()
	response, err := r.Client.Heartbeat(ctx, protocol.HeartbeatRequest{
		InstallID:    r.Config.InstallID,
		Hostname:     snapshot.Hostname,
		OsType:       string(snapshot.OSFamily),
		Architecture: snapshot.Architecture,
		AgentVersion: snapshot.AgentVersion,
		State:        string(currentState),
		Capabilities: r.Executor.Capabilities,
		Timestamp:    time.Now(),
	})
	if err != nil {
		return err
	}
	// AG-026D Codex 019e7314 constraint #5 + iter-1 must_fix #2:
	// "credential confirmed" requires DPAPI write success in THIS
	// process + signed heartbeat HTTP 2xx + accepted=true +
	// (when present) deviceId match. Accept=false and device mismatch
	// are FAIL-CLOSED — the runner must NOT continue into command
	// poll when the backend has explicitly disowned this credential.
	// Aligned with the auto-enroll heartbeat contract.
	if !response.Accepted {
		return fmt.Errorf("backend rejected heartbeat: accepted=false (credential likely revoked)")
	}
	if response.DeviceID != "" && response.DeviceID != r.Config.DeviceID {
		return fmt.Errorf("backend heartbeat device_id mismatch local=%s backend=%s",
			r.Config.DeviceID, response.DeviceID)
	}
	if r.credentialPersisted {
		r.logf("hmac credential confirmed device=%s credential=%s", r.Config.DeviceID, r.Config.CredentialID)
	} else {
		// Hydrate-from-store path or persist-failed enroll. The
		// credential is valid in-memory but the AG-026C installer
		// token-cleanup gate keys on the "confirmed" sentinel above,
		// which we deliberately withhold here to avoid premature
		// cleanup based on an unpersisted credential.
		r.logf("hmac credential accepted (not persisted in this process) device=%s credential=%s",
			r.Config.DeviceID, r.Config.CredentialID)
	}
	return nil
}

func (r *Runner) logf(format string, args ...interface{}) {
	if r.Logger != nil {
		r.Logger.Printf(format, args...)
	}
}
