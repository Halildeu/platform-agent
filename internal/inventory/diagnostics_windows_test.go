//go:build windows

package inventory

// Windows-platform entry-point coverage for ProbeDiagnostics. The
// platform-neutral orchestration (runDiagnosticsProbeReal) is covered in the
// untagged diagnostics_realprobe_test.go so it runs on the linux CI host;
// this file only asserts the Windows wiring that sets Supported=true.

import (
	"context"
	"testing"
	"time"
)

func TestProbeDiagnostics_NilCtx(t *testing.T) {
	result := ProbeDiagnostics(nil, time.Now)
	if result.SchemaVersion != DiagnosticsSchemaVersion {
		t.Errorf("SchemaVersion = %d; want %d", result.SchemaVersion, DiagnosticsSchemaVersion)
	}
	if !result.Supported {
		t.Error("Supported should be true on Windows")
	}
}

func TestProbeDiagnostics_NilNow(t *testing.T) {
	// time.Now is wired internally; a nil now arg must not panic and the
	// Windows entry must still produce a supported result.
	result := ProbeDiagnostics(context.Background(), nil)
	if !result.Supported {
		t.Error("Supported should be true on Windows")
	}
	if result.ProbeDurationMs < 0 {
		t.Errorf("ProbeDurationMs = %d; want >= 0", result.ProbeDurationMs)
	}
}
