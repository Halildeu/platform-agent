//go:build windows

package app

import (
	"context"
	"crypto/tls"
	"fmt"
	"os"
	"sync"
	"time"

	"platform-agent/internal/config"
	"platform-agent/internal/remotebridge/devkeysession"
	"platform-agent/internal/remotebridge/harness"
	pb "platform-agent/internal/remotebridge/pb"
	"platform-agent/internal/tpmenroll"
)

// newTPMDeviceKeySessionIdentity opens the Windows TPM ONCE and returns BOTH the
// remote-bridge mTLS *tls.Config and the #548 DeviceKeyChallenge responder, bound to the
// SAME device key.
//
//   - TLS leaf: the enrollment-issued device cert read from
//     %ProgramData%\EndpointAgent\tpm-client-cert.pem (tpmenroll.DeviceClientCertPath),
//     with the go-tpm device key as the private key (a crypto.Signer wrapped for locking).
//   - Responder: answers the broker challenge with the SAME device key.
//
// This is the runbook §3.1 "certstore/CNG association" follow-up done correctly: the
// device key is a deterministic transient primary (CreatePrimary), NOT a CNG key, so it
// can never be an acquirable LocalMachine\My cert. Presenting it via a go-tpm signer +
// the PEM leaf is the only way the LIVE mTLS leaf SPKI can equal the attested/persisted
// device-key SPKI (the broker's triple-SPKI equality). The certstore loader path is NOT
// used for this mode and there is no fallback to it (fail closed).
//
// The TLS handshake signer and the responder share ONE single-threaded TPM, so a single
// mutex serializes every TPM operation. The device is closed when ctx ends; the same
// mutex guards the close so no in-flight sign/respond races it. The responder calls the
// UNDERLYING (unlocked) signer via tpm.DeviceKeySigner() while already holding the mutex,
// so there is no re-entrant lock.
//
// HARDWARE-UNVERIFIED: this path is exercised only on a real attestation-capable Windows
// TPM at the step-7 live run (platform-k8s-gitops
// RB-faz22.6-548-device-key-session-live-run.md).
func newTPMDeviceKeySessionIdentity(ctx context.Context, cfg config.Config) (*tls.Config, harness.DeviceKeyResponder, error) {
	serverName, err := remoteBridgeServerName(cfg)
	if err != nil {
		return nil, nil, err
	}
	certPath := tpmenroll.DeviceClientCertPath()
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, nil, fmt.Errorf("read device client cert %q (enrollment must have issued it — re-enroll if missing): %w", certPath, err)
	}

	tpm, err := tpmenroll.NewWindowsTPMDevice()
	if err != nil {
		return nil, nil, err
	}
	mu := &sync.Mutex{}

	signer := &lockedSigner{inner: tpm.DeviceKeySigner(), mu: mu}
	tlsCfg, err := buildDeviceKeySessionTLSConfig(certPEM, signer, serverName, tls.VersionTLS12)
	if err != nil {
		// The ctx-close goroutine is not started yet, so close directly.
		_ = tpm.Close()
		return nil, nil, err
	}

	go func() {
		<-ctx.Done()
		mu.Lock()
		_ = tpm.Close()
		mu.Unlock()
	}()

	responder := func(_ context.Context, challenge *pb.DeviceKeyChallenge, sessionID string) (*pb.DeviceKeyAttestationResponse, error) {
		mu.Lock()
		defer mu.Unlock()
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return devkeysession.Respond(tpm, challenge, sessionID, time.Now().UnixMilli())
	}
	return tlsCfg, responder, nil
}
