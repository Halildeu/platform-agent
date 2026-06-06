package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"platform-agent/internal/selfupdate"
)

type activationHelperStartFunc func(ctx context.Context, executable string, args []string) error

var startActivationHelperProcess activationHelperStartFunc = startSelfUpdateActivationHelperProcess

func launchSelfUpdateActivationHelper(ctx context.Context, executable string, paths selfupdate.StagingPaths, maxBytes int64, timeout time.Duration) selfupdate.ActivationOutcome {
	if err := ctx.Err(); err != nil {
		return selfupdate.ActivationOutcome{Status: selfupdate.ActivationFailed, ActivationPlanID: paths.StagingID, Reason: "activation helper launch context cancelled"}
	}
	if executable == "" {
		return selfupdate.ActivationOutcome{Status: selfupdate.ActivationFailed, ActivationPlanID: paths.StagingID, Reason: "activation helper executable is empty"}
	}
	rebuilt, code, reason := selfupdate.BuildStagingPaths(paths.Root, paths.StagingID)
	if code != "" {
		return selfupdate.ActivationOutcome{Status: selfupdate.ActivationFailed, ActivationPlanID: paths.StagingID, Reason: reason}
	}
	if maxBytes <= 0 {
		maxBytes = selfupdate.DefaultMaxUpdateBytes
	}
	if timeout <= 0 {
		timeout = 2 * time.Minute
	}
	args := []string{
		"self-update", "activate",
		"--staging-root", rebuilt.Root,
		"--staging-id", rebuilt.StagingID,
		"--max-bytes", fmt.Sprintf("%d", maxBytes),
		"--timeout", timeout.String(),
	}
	if err := startActivationHelperProcess(ctx, executable, args); err != nil {
		return selfupdate.ActivationOutcome{Status: selfupdate.ActivationFailed, ActivationPlanID: rebuilt.StagingID, Reason: "activation helper launch failed"}
	}
	return selfupdate.ActivationOutcome{
		Status:           selfupdate.ActivationHelperStarted,
		ActivationPlanID: rebuilt.StagingID,
		Reason:           "activation helper started",
	}
}

func currentExecutablePath() string {
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	return exe
}
