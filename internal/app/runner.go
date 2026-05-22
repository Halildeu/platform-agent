package app

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	"platform-agent/internal/commands"
	"platform-agent/internal/config"
	"platform-agent/internal/inventory"
	"platform-agent/internal/protocol"
	"platform-agent/internal/state"
)

type Runner struct {
	Config       config.Config
	Client       *protocol.Client
	Executor     *commands.LocalExecutor
	StateTracker *state.Tracker
	Logger       *log.Logger
}

func NewRunner(cfg config.Config, client *protocol.Client, logger *log.Logger) *Runner {
	capabilities := inventory.RuntimeCapabilities()
	return &Runner{
		Config:       cfg,
		Client:       client,
		Executor:     commands.NewLocalExecutor(capabilities, cfg.AgentVersion),
		StateTracker: state.NewTracker(state.StateStarting),
		Logger:       logger,
	}
}

func (r *Runner) RunOnce(ctx context.Context) error {
	if r.Client == nil {
		return fmt.Errorf("protocol client is required")
	}
	if r.Executor == nil {
		r.Executor = commands.NewLocalExecutor(inventory.RuntimeCapabilities(), r.Config.AgentVersion)
	}
	if r.StateTracker == nil {
		r.StateTracker = state.NewTracker(state.StateStarting)
	}

	if !r.Client.IsEnrolled() {
		if err := r.enroll(ctx); err != nil {
			r.StateTracker.RecordFailure(time.Now())
			return err
		}
	}
	if err := r.heartbeat(ctx); err != nil {
		r.StateTracker.RecordFailure(time.Now())
		return err
	}

	command, err := r.Client.NextCommand(ctx)
	if errors.Is(err, protocol.ErrNoCommand) {
		r.logf("no command available")
		return nil
	}
	if err != nil {
		r.StateTracker.RecordFailure(time.Now())
		return err
	}

	commandCtx, cancel := context.WithTimeout(ctx, r.Config.CommandTimeout)
	defer cancel()
	result := r.Executor.Execute(commandCtx, command)
	if err := r.Client.SubmitResult(ctx, result); err != nil {
		r.StateTracker.RecordFailure(time.Now())
		return err
	}
	r.logf("command %s finished with %s", command.CommandID, result.Status)
	return nil
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
	r.logf("agent enrolled: device=%s credential=%s", response.DeviceID, response.CredentialKeyID)
	return nil
}

func (r *Runner) heartbeat(ctx context.Context) error {
	snapshot := inventory.Collect(r.Config.AgentVersion, time.Now())
	currentState := r.StateTracker.RecordSuccess()
	_, err := r.Client.Heartbeat(ctx, protocol.HeartbeatRequest{
		InstallID:    r.Config.InstallID,
		Hostname:     snapshot.Hostname,
		OsType:       string(snapshot.OSFamily),
		Architecture: snapshot.Architecture,
		AgentVersion: snapshot.AgentVersion,
		State:        string(currentState),
		Capabilities: r.Executor.Capabilities,
		Timestamp:    time.Now(),
	})
	return err
}

func (r *Runner) logf(format string, args ...interface{}) {
	if r.Logger != nil {
		r.Logger.Printf(format, args...)
	}
}
