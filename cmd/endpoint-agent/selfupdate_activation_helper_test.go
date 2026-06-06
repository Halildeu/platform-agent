package main

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"platform-agent/internal/selfupdate"
)

func TestLaunchSelfUpdateActivationHelperStartsPathFreeHelper(t *testing.T) {
	root := t.TempDir()
	paths, code, reason := selfupdate.BuildStagingPaths(root, "cmd-launch-1")
	if code != "" {
		t.Fatalf("BuildStagingPaths code=%q reason=%q", code, reason)
	}

	var capturedExecutable string
	var capturedArgs []string
	oldStart := startActivationHelperProcess
	startActivationHelperProcess = func(_ context.Context, executable string, args []string) error {
		capturedExecutable = executable
		capturedArgs = append([]string(nil), args...)
		return nil
	}
	t.Cleanup(func() { startActivationHelperProcess = oldStart })

	outcome := launchSelfUpdateActivationHelper(context.Background(), "agent.exe", paths, 1234, 3*time.Minute)

	if outcome.Status != selfupdate.ActivationHelperStarted {
		t.Fatalf("status=%s reason=%q", outcome.Status, outcome.Reason)
	}
	if outcome.ActivationPlanID != "cmd-launch-1" {
		t.Fatalf("ActivationPlanID=%q", outcome.ActivationPlanID)
	}
	if capturedExecutable != "agent.exe" {
		t.Fatalf("executable=%q", capturedExecutable)
	}
	wantArgs := []string{
		"self-update", "activate",
		"--staging-root", paths.Root,
		"--staging-id", "cmd-launch-1",
		"--max-bytes", "1234",
		"--timeout", "3m0s",
	}
	if strings.Join(capturedArgs, "\n") != strings.Join(wantArgs, "\n") {
		t.Fatalf("args=%q, want %q", capturedArgs, wantArgs)
	}
	if strings.Contains(outcome.Reason, root) {
		t.Fatalf("outcome leaked staging root: %+v", outcome)
	}
}

func TestLaunchSelfUpdateActivationHelperFailsPathFreeOnLaunchError(t *testing.T) {
	root := t.TempDir()
	paths, code, reason := selfupdate.BuildStagingPaths(root, "cmd-launch-fail")
	if code != "" {
		t.Fatalf("BuildStagingPaths code=%q reason=%q", code, reason)
	}

	oldStart := startActivationHelperProcess
	startActivationHelperProcess = func(context.Context, string, []string) error {
		return errors.New("CreateProcess failed: C:\\ProgramData\\EndpointAgent\\updates\\cmd-launch-fail")
	}
	t.Cleanup(func() { startActivationHelperProcess = oldStart })

	outcome := launchSelfUpdateActivationHelper(context.Background(), "agent.exe", paths, 0, 0)

	if outcome.Status != selfupdate.ActivationFailed {
		t.Fatalf("status=%s reason=%q", outcome.Status, outcome.Reason)
	}
	if outcome.ActivationPlanID != "cmd-launch-fail" {
		t.Fatalf("ActivationPlanID=%q", outcome.ActivationPlanID)
	}
	if strings.Contains(outcome.Reason, root) || strings.Contains(outcome.Reason, "ProgramData") {
		t.Fatalf("failure reason leaked path: %q", outcome.Reason)
	}
}

func TestLaunchSelfUpdateActivationHelperRejectsEmptyExecutable(t *testing.T) {
	root := t.TempDir()
	paths, code, reason := selfupdate.BuildStagingPaths(root, "cmd-launch-empty-exe")
	if code != "" {
		t.Fatalf("BuildStagingPaths code=%q reason=%q", code, reason)
	}

	outcome := launchSelfUpdateActivationHelper(context.Background(), "", paths, 1024, time.Minute)

	if outcome.Status != selfupdate.ActivationFailed {
		t.Fatalf("status=%s reason=%q", outcome.Status, outcome.Reason)
	}
	if strings.Contains(outcome.Reason, root) {
		t.Fatalf("failure reason leaked staging root: %q", outcome.Reason)
	}
}
