package ptyexec

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"platform-agent/internal/remotebridge/operation"
)

// conptyRunOutFlag switches the test binary into a ConPTY helper: it runs the allowlisted no-shell "hostname"
// in a pseudo-console and writes the CAPTURED output to the given path. The gold-proof launches THIS binary
// with the flag INTO the interactive session (where conhost has a window station — a pseudo-console in the
// headless Session-0 leaks the child's stdout instead of relaying it). Arg, not env, because
// CreateProcessAsUser hands the helper the USER's environment block.
const conptyRunOutFlag = "--conpty-run-out="

func TestMain(m *testing.M) {
	for _, a := range os.Args[1:] {
		if strings.HasPrefix(a, conptyRunOutFlag) {
			os.Exit(runConPTYHelper(strings.TrimPrefix(a, conptyRunOutFlag)))
		}
	}
	os.Exit(m.Run())
}

// runConPTYHelper builds the allowlisted no-shell plan for "hostname", runs it in a pseudo-console, and
// writes the captured output to outPath. Returns a process exit code (0 = ok). Runs wherever the launcher
// placed it (session 1 for the gold-proof).
func runConPTYHelper(outPath string) int {
	if outPath == "" {
		return 3
	}
	plan, err := BuildExecPlan(operation.ParseCommand("hostname"), DefaultAllowlist())
	if err != nil {
		return 4
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	out, code, err := RunConPTY(ctx, plan.ExePath, plan.CommandLine, 120, 30)
	if err != nil {
		return 5
	}
	if code != 0 {
		return 6
	}
	if werr := os.WriteFile(outPath, out, 0o600); werr != nil {
		return 7
	}
	return 0
}
