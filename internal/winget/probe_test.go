package winget

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestProbeMissingOptions(t *testing.T) {
	r := Probe(ProbeOptions{})
	if !r.Supported {
		t.Fatalf("Supported should default to true on Windows code path")
	}
	if r.AvailableInCurrentContext || r.SystemContextReady {
		t.Fatalf("missing options should produce no readiness")
	}
	if r.ProbeError == "" {
		t.Fatalf("ProbeError should report incomplete options")
	}
}

func TestProbeLocatorErrorMarksUnavailable(t *testing.T) {
	r := Probe(ProbeOptions{
		Locator: func() (string, error) { return "", ErrWinGetNotFound },
		Execute: func(ctx context.Context, path string, args ...string) ([]byte, error) {
			t.Fatalf("executor should not run when locator fails")
			return nil, nil
		},
		Now: nowSequence(0, 10),
	})
	if r.AvailableInCurrentContext || r.SystemContextReady {
		t.Fatalf("locator error should leave both flags false")
	}
	if r.ProbeError == "" {
		t.Fatalf("ProbeError should report locator failure")
	}
}

func TestProbeExecutorFailureMarksAvailableButNotReady(t *testing.T) {
	r := Probe(ProbeOptions{
		Locator: func() (string, error) { return `C:\WindowsApps\winget.exe`, nil },
		Execute: func(ctx context.Context, path string, args ...string) ([]byte, error) {
			return nil, errors.New("not registered")
		},
		Now: nowSequence(0, 50),
	})
	if !r.AvailableInCurrentContext {
		t.Fatalf("locator success should set AvailableInCurrentContext")
	}
	if r.SystemContextReady {
		t.Fatalf("executor failure should leave SystemContextReady false")
	}
	if r.ProbeError == "" {
		t.Fatalf("executor error should populate ProbeError")
	}
}

func TestProbeFixedArgsOnly(t *testing.T) {
	var capturedArgs []string
	_ = Probe(ProbeOptions{
		Locator: func() (string, error) { return `winget.exe`, nil },
		Execute: func(ctx context.Context, path string, args ...string) ([]byte, error) {
			capturedArgs = append([]string{}, args...)
			return []byte("v1.7.10861\n"), nil
		},
		Now: nowSequence(0, 5),
	})
	if len(capturedArgs) != 1 || capturedArgs[0] != "--version" {
		t.Fatalf("probe must pass exactly --version, got %#v", capturedArgs)
	}
}

func TestProbeSuccessExtractsVersion(t *testing.T) {
	r := Probe(ProbeOptions{
		Locator: func() (string, error) { return `winget.exe`, nil },
		Execute: func(ctx context.Context, path string, args ...string) ([]byte, error) {
			return []byte("v1.7.10861\n"), nil
		},
		Now: nowSequence(0, 100),
	})
	if !r.SystemContextReady {
		t.Fatalf("SystemContextReady should be true on success")
	}
	if r.Version != "1.7.10861" {
		t.Fatalf("Version = %q, want 1.7.10861", r.Version)
	}
	if r.ProbeDurationMs != 100 {
		t.Fatalf("Duration = %d, want 100ms (deterministic now mock)", r.ProbeDurationMs)
	}
}

func TestProbeTimeoutKeepsSystemContextFalse(t *testing.T) {
	r := Probe(ProbeOptions{
		Locator: func() (string, error) { return `winget.exe`, nil },
		Execute: func(ctx context.Context, path string, args ...string) ([]byte, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		},
		Timeout: 5 * time.Millisecond,
		Now:     nowSequence(0, 6),
	})
	if !r.AvailableInCurrentContext {
		t.Fatalf("Available should remain true (binary located)")
	}
	if r.SystemContextReady {
		t.Fatalf("SystemContextReady must be false on timeout")
	}
	if !r.Timeout {
		t.Fatalf("Timeout flag should be true")
	}
}

func TestProbeRedactsPathPII(t *testing.T) {
	r := Probe(ProbeOptions{
		Locator: func() (string, error) { return `C:\Users\halilkocoglu\AppData\Local\Microsoft\WindowsApps\winget.exe`, nil },
		Execute: func(ctx context.Context, path string, args ...string) ([]byte, error) {
			return []byte("1.7.0\n"), nil
		},
		Now: nowSequence(0, 1),
	})
	if strings.Contains(r.ExecutablePath, "halilkocoglu") {
		t.Fatalf("user segment leaked into ExecutablePath: %q", r.ExecutablePath)
	}
	if !strings.Contains(r.ExecutablePath, "[REDACTED]") {
		t.Fatalf("redaction sentinel missing: %q", r.ExecutablePath)
	}
}

func TestParseVersionTolerantToReleaseSuffix(t *testing.T) {
	tests := map[string]string{
		"v1.7.10861":           "1.7.10861",
		"1.7.10861":            "1.7.10861",
		"  v1.7.10861-preview": "1.7.10861-preview",
		"no version here":      "",
	}
	for input, want := range tests {
		got := parseVersion(input)
		if got != want {
			t.Fatalf("parseVersion(%q) = %q, want %q", input, got, want)
		}
	}
}

// nowSequence builds a deterministic time.Now stub that returns the
// provided millisecond offsets in order. Probe calls Now twice (start
// + duration record); deferred recording reads the second value, so
// pass two offsets per probe.
func nowSequence(offsetsMs ...int) func() time.Time {
	base := time.Date(2026, 5, 27, 12, 0, 0, 0, time.UTC)
	idx := 0
	return func() time.Time {
		var off int
		if idx < len(offsetsMs) {
			off = offsetsMs[idx]
		} else {
			off = offsetsMs[len(offsetsMs)-1]
		}
		idx++
		return base.Add(time.Duration(off) * time.Millisecond)
	}
}
