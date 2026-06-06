//go:build !windows

package commands

func withDefaultUpdateAgentRuntime(opts UpdateAgentStagerOptions) UpdateAgentStagerOptions {
	return opts
}
