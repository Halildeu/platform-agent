package app

import (
	"context"
	"log"

	"platform-agent/internal/config"
	"platform-agent/internal/remotebridge/harness"
)

// StartRemoteBridge starts the Faz 22.6 T-3 remote-bridge idle harness when
// — and only when — the explicit config flag is set. Default off: the agent
// never auto-connects to a broker (ADR-0034 disabled-by-default discipline);
// with the flag off this returns nil and spawns nothing.
//
// deviceID is the live identity getter (protocol.Client.DeviceID for the
// HMAC runner): the harness polls it and never dials while it is empty, so
// an enabled flag cannot produce a stream before enrollment (Codex T-3
// revision #2). The returned harness is observational (counters/session
// state); lifecycle is owned by ctx.
func StartRemoteBridge(ctx context.Context, cfg config.Config, deviceID func() string, logger *log.Logger) *harness.Harness {
	if !cfg.RemoteBridgeEnabled {
		return nil
	}
	h, err := harness.New(harness.Config{
		BrokerAddr:             cfg.RemoteBridgeBrokerAddr,
		DeviceIDProvider:       deviceID,
		AgentVersion:           cfg.AgentVersion,
		InsecurePlaintext:      cfg.RemoteBridgeInsecurePlaintext,
		FirstHeartbeatDeadline: cfg.RemoteBridgeFirstHeartbeatDeadline,
		HeartbeatMissFactor:    cfg.RemoteBridgeHeartbeatMissFactor,
		BackoffMin:             cfg.RemoteBridgeBackoffMin,
		BackoffMax:             cfg.RemoteBridgeBackoffMax,
		IdentityPollInterval:   cfg.RemoteBridgeIdentityPollInterval,
		DialTimeout:            cfg.RemoteBridgeDialTimeout,
	}, logger)
	if err != nil {
		// Misconfiguration (e.g. enabled without a broker addr) refuses
		// loudly instead of half-starting.
		logger.Printf("remote-bridge: harness init refused: %v", err)
		return nil
	}
	go h.Run(ctx)
	return h
}
