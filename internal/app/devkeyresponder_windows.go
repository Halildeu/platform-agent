//go:build windows

package app

import (
	"context"
	"sync"
	"time"

	"platform-agent/internal/remotebridge/devkeysession"
	"platform-agent/internal/remotebridge/harness"
	pb "platform-agent/internal/remotebridge/pb"
	"platform-agent/internal/tpmenroll"
)

// newTPMDeviceKeyResponder opens the Windows TPM and returns a DeviceKeyResponder that signs the broker's #548
// device-key session challenge with the agent's TPM device key. The EK/AK/device-key are CreatePrimary-derived
// (deterministic from the TPM seed + a fixed template), so they match the keys this device enrolled with — the
// broker's triple-SPKI equality (attested == live mTLS leaf == persisted binding) holds without any persistent
// handle. Enrollment is a one-shot that closes its TPM before the long-lived bridge starts, so the two never
// hold overlapping transient primaries (which could exhaust the TPM's handle slots).
//
// TPM access is serialized (the TPM is single-threaded; the harness answers challenges off a goroutine) and the
// device is closed when ctx ends — the same mutex guards the close so no challenge races a closed device.
//
// HARDWARE-UNVERIFIED: this path is exercised only on a real attestation-capable Windows TPM at the step-7 live
// run (see docs/runbooks/RB-faz22.6-548-device-key-session-live-run.md in platform-k8s-gitops).
func newTPMDeviceKeyResponder(ctx context.Context) (harness.DeviceKeyResponder, error) {
	tpm, err := tpmenroll.NewWindowsTPMDevice()
	if err != nil {
		return nil, err
	}
	var mu sync.Mutex
	go func() {
		<-ctx.Done()
		mu.Lock()
		_ = tpm.Close()
		mu.Unlock()
	}()
	return func(_ context.Context, challenge *pb.DeviceKeyChallenge, sessionID string) (*pb.DeviceKeyAttestationResponse, error) {
		mu.Lock()
		defer mu.Unlock()
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return devkeysession.Respond(tpm, challenge, sessionID, time.Now().UnixMilli())
	}, nil
}
