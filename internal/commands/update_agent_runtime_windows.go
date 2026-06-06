//go:build windows

package commands

import "platform-agent/internal/selfupdate"

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
	return opts
}
