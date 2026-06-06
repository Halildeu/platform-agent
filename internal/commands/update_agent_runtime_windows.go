//go:build windows

package commands

import (
	"os"

	winservice "platform-agent/internal/platform/windows/service"
	"platform-agent/internal/selfupdate"
)

func withDefaultUpdateAgentRuntime(opts UpdateAgentStagerOptions) UpdateAgentStagerOptions {
	if opts.Verifier == nil {
		opts.Verifier = selfupdate.WindowsAuthenticodeVerifier{}
	}
	if opts.VersionReader == nil {
		opts.VersionReader = selfupdate.WindowsPEVersionReader{}
	}
	if opts.Downloader == nil {
		opts.Downloader = selfupdate.NewHTTPDownloader()
	}
	if opts.Staging == nil {
		root := selfupdate.DefaultWindowsStagingRoot()
		opts.Staging = selfupdate.WindowsStagingStore{Root: root}
		if opts.TempDir == "" {
			opts.TempDir = root
		}
	}
	if opts.HighWater == nil {
		opts.HighWater = selfupdate.FileHighWaterStore{Path: selfupdate.DefaultWindowsHighWaterPath()}
	}
	if opts.PlanWriter == nil {
		opts.PlanWriter = selfupdate.FileActivationPlanWriter{}
	}
	if opts.CurrentBinaryPath == "" {
		if exe, err := os.Executable(); err == nil {
			opts.CurrentBinaryPath = exe
		}
	}
	if opts.ServiceName == "" {
		opts.ServiceName = winservice.DefaultName
	}
	return opts
}
