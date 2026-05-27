package autoenroll

import (
	"context"
	"math/rand"
	"testing"
	"time"
)

func TestJitter_DisabledWhenMaxNonPositive(t *testing.T) {
	for _, max := range []int{0, -1, -100} {
		if got := Jitter(max); got != 0 {
			t.Errorf("Jitter(%d) = %v, want 0", max, got)
		}
	}
}

func TestJitterFrom_BoundsRespected(t *testing.T) {
	r := rand.New(rand.NewSource(42))
	const maxSec = 30
	for i := 0; i < 1000; i++ {
		d := JitterFrom(r, maxSec)
		if d < 0 || d >= time.Duration(maxSec)*time.Second {
			t.Fatalf("JitterFrom returned %v outside [0,%ds)", d, maxSec)
		}
	}
}

func TestSleepWithContext_ReturnsImmediatelyOnZero(t *testing.T) {
	ctx := context.Background()
	start := time.Now()
	if err := SleepWithContext(ctx, 0); err != nil {
		t.Fatalf("SleepWithContext(0) returned %v", err)
	}
	if elapsed := time.Since(start); elapsed > 50*time.Millisecond {
		t.Fatalf("SleepWithContext(0) took %v, expected immediate return", elapsed)
	}
}

func TestSleepWithContext_HonoursCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := SleepWithContext(ctx, 5*time.Second); err == nil {
		t.Fatalf("SleepWithContext returned nil; expected ctx.Err()")
	}
}

func TestSleepWithContext_NaturalWake(t *testing.T) {
	ctx := context.Background()
	start := time.Now()
	if err := SleepWithContext(ctx, 20*time.Millisecond); err != nil {
		t.Fatalf("SleepWithContext returned %v", err)
	}
	if elapsed := time.Since(start); elapsed < 20*time.Millisecond {
		t.Fatalf("SleepWithContext returned in %v, expected >= 20ms", elapsed)
	}
}
