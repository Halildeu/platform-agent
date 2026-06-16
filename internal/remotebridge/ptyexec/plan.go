// Package ptyexec is the agent-side CONSTRAINED_PTY EXECUTOR (Faz 22.6, board #1588). It is the "execute"
// half (process/ConPTY lifecycle); the "authorize" half (permit verify + the operation gate) is the
// operation package. slice-3a is this file: the OS-agnostic, NO-execution ExecPlan builder + allowlist —
// it decides WHAT may run and produces a no-shell command line, but spawns nothing (the Windows ConPTY
// executor is slice-3b/3c). Disabled-by-default; LIVE owner-gated (ADR-0034 §13/D10).
package ptyexec

import (
	"errors"
	"fmt"

	"platform-agent/internal/remotebridge/cmdline"
	"platform-agent/internal/remotebridge/operation"
)

// ExecPlan is the resolved, no-shell execution recipe — the ONLY thing the (later) executor spawns. ExePath
// is an absolute, allowlisted trusted binary; CommandLine is CommandLineToArgvW-compatible so the target
// CRT re-parses exactly ExePath + Args (the D-2 no-shell invariant — the binary is run directly, never via
// cmd /c or any shell).
type ExecPlan struct {
	ExePath     string
	Args        []string
	CommandLine string
}

// AllowRule pins an allowlisted command: the absolute trusted binary, plus an optional arg policy. The
// broker's signed commandHash already binds the exact commandId+argv (the operation gate enforces it), so a
// nil ArgPolicy is sound; a policy adds defense-in-depth (e.g. forbid flags, cap arg count) against future
// mapping drift.
type AllowRule struct {
	ExePath   string
	ArgPolicy func(args []string) error // nil ⇒ accept any args (already bound by commandHash)
}

// Stable, bounded error sentinels (safe to surface as audit/metric reasons).
var (
	ErrEmptyCommand   = errors.New("ptyexec: empty command")
	ErrNotAllowlisted = errors.New("ptyexec: command not allowlisted")
	ErrRuleExeNotAbs  = errors.New("ptyexec: allowlist rule exe path is not absolute")
	ErrArgPolicy      = errors.New("ptyexec: argument policy violation")
)

// BuildExecPlan resolves a canonical command against the allowlist, fail-closed. It does NOT execute
// anything. The command MUST be a non-empty, allowlisted commandId mapping to an ABSOLUTE trusted binary,
// and its args must pass the rule's ArgPolicy (if any). On success it returns the no-shell ExecPlan.
//
// Contract: cmd MUST already be canonical — produced by operation.ParseCommand (commandId trimmed +
// lowercased, the same canonicalisation the operation gate hashed against the permit's commandHash).
// BuildExecPlan deliberately does NOT re-normalize, so it stays byte-consistent with the verified
// commandHash binding; the executor (slice-3c) feeds it the very command the gate authorized.
//
// This is defense-in-depth ON TOP OF the operation gate (which already required a verified broker permit
// whose signed commandHash equals hash(this command)). The allowlist additionally constrains WHICH binaries
// the agent will ever launch — a broker compromise or a commandHash-mapping bug still cannot run an
// off-allowlist binary.
func BuildExecPlan(cmd operation.CanonicalCommand, allowlist map[string]AllowRule) (ExecPlan, error) {
	if cmd.IsEmpty() {
		return ExecPlan{}, ErrEmptyCommand
	}
	rule, ok := allowlist[cmd.CommandID]
	if !ok {
		return ExecPlan{}, fmt.Errorf("%w: %q", ErrNotAllowlisted, cmd.CommandID)
	}
	if !isWindowsAbs(rule.ExePath) {
		return ExecPlan{}, fmt.Errorf("%w: %q", ErrRuleExeNotAbs, rule.ExePath)
	}
	if rule.ArgPolicy != nil {
		if err := rule.ArgPolicy(cmd.Argv); err != nil {
			return ExecPlan{}, fmt.Errorf("%w: %v", ErrArgPolicy, err)
		}
	}
	args := append([]string(nil), cmd.Argv...)
	return ExecPlan{
		ExePath:     rule.ExePath,
		Args:        args,
		CommandLine: cmdline.BuildCommandLine(rule.ExePath, args),
	}, nil
}

// DefaultAllowlist is the tiny, read-only diagnostic command set for the pilot — fail-closed by omission
// (anything not here is rejected by BuildExecPlan). Read-only / no-side-effect System32 binaries ONLY: no
// shells (cmd/powershell), no write/admin tools (reg/sc/net/del). commandIds are lowercase (CanonicalCommand
// lowercases). An operator widens this deliberately; it is never auto-expanded. Returns a FRESH map on every
// call (the caller owns it — there is no shared mutable singleton to corrupt).
//
// RECONCILED to the broker's issuance allowlist (endpoint-admin-service
// PtyCommandGuard.PILOT_DEFAULT_ALLOWLIST = hostname/whoami/ver/netstat/ping/tracert), MINUS `ver` — a cmd
// shell-builtin with no standalone .exe that this no-shell executor (CreateProcess direct) cannot run. The
// agent's last-line EXECUTION allowlist MUST stay a subset of the broker's ISSUANCE set: systeminfo /
// tasklist / ipconfig were deliberately excluded broker-side (credential-on-command-line + remote-recon
// surface) and must not be re-permitted here, or a broker bug/compromise that minted such a permit would
// execute. (`ver`'s presence broker-side is itself questionable for a no-shell agent — flagged separately.)
func DefaultAllowlist() map[string]AllowRule {
	const sys = `C:\Windows\System32\`
	return map[string]AllowRule{
		"hostname": {ExePath: sys + "hostname.exe"},
		"whoami":   {ExePath: sys + "whoami.exe"},
		"netstat":  {ExePath: sys + "netstat.exe"},
		"ping":     {ExePath: sys + "ping.exe"},
		"tracert":  {ExePath: sys + "tracert.exe"},
	}
}

// isWindowsAbs reports a drive-rooted Windows absolute path (e.g. C:\...). Checked explicitly (not
// filepath.IsAbs) because the allowlist holds Windows paths but the package is OS-agnostic + host-tested.
func isWindowsAbs(p string) bool {
	if len(p) < 3 {
		return false
	}
	c := p[0]
	isLetter := (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
	return isLetter && p[1] == ':' && (p[2] == '\\' || p[2] == '/')
}
