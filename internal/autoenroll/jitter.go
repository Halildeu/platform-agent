package autoenroll

import (
	"context"
	"math/rand"
	"time"
)

// Jitter computes a random delay in [0, maxSeconds) for the first-run
// auto-enroll path. maxSeconds <= 0 disables jitter (returns 0). The MSI
// installer (ADR-0029 Katman 4) persists ENROLLMENTJITTERSECONDS to
// HKLM\SOFTWARE\EndpointAgent so the agent service-startup distributes
// requests across the wave — R26 mass-enrollment-storm mitigation.
//
// The randomness source is package-level math/rand which is seeded by the
// Go runtime since 1.20; for unit tests the caller can inject a rand.Rand
// via JitterFrom.
func Jitter(maxSeconds int) time.Duration {
	if maxSeconds <= 0 {
		return 0
	}
	return time.Duration(rand.Intn(maxSeconds)) * time.Second
}

// JitterFrom is the test-injectable form. r must be non-nil.
func JitterFrom(r *rand.Rand, maxSeconds int) time.Duration {
	if maxSeconds <= 0 {
		return 0
	}
	return time.Duration(r.Intn(maxSeconds)) * time.Second
}

// SleepWithContext sleeps for d unless ctx is cancelled first. Returns
// ctx.Err() on cancellation, nil on natural wake.
func SleepWithContext(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
