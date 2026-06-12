package protocol

import (
	"net/http"
	"sync"
	"testing"
)

// TestIdentityConcurrentReadWrite is the -race regression for the Faz 22.6
// T-3 wiring (Codex 019ebb18 P1): the remote-bridge harness polls
// DeviceID/IsEnrolled from its own goroutine while the runner's
// enroll/hydrate path writes the same identity triple through SetIdentity.
// Before identityMu these were unsynchronized field accesses.
func TestIdentityConcurrentReadWrite(t *testing.T) {
	c, err := NewClient("https://localhost/api/v1/endpoint-agent", "", &http.Client{})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { // harness-style identity poller
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			_ = c.DeviceID()
			_ = c.CredentialID()
			_ = c.IsEnrolled()
		}
	}()
	for i := 0; i < 1_000; i++ { // runner-style enroll/re-enroll writer
		c.SetIdentity("cred-1", "secret-1", "device-1")
		c.SetIdentity("", "", "")
	}
	close(stop)
	wg.Wait()
	c.SetIdentity("cred-final", "secret-final", "device-final")
	if c.DeviceID() != "device-final" || !c.IsEnrolled() {
		t.Fatal("identity snapshot lost after concurrent churn")
	}
}
