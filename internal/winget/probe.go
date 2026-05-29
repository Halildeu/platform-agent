package winget

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"time"

	"platform-agent/internal/security"
)

// Locator returns the absolute path to winget.exe or an error if it
// cannot be found. The Windows build supplies a real implementation
// that walks LookPath → %LOCALAPPDATA%\Microsoft\WindowsApps → the
// system-wide WindowsApps directory; tests inject a fake that returns
// a fixed path so the probe can be exercised hermetically.
type Locator func() (string, error)

// Executor runs the located binary with the supplied args under the
// caller-provided context and returns the combined stdout/stderr
// output. Tests inject a fake; production wiring uses exec.Command.
//
// The signature does NOT accept a *exec.Cmd or any other exec-package
// type so the probe.go file can stay platform-agnostic (no
// os/exec import in the pure-logic layer).
type Executor func(ctx context.Context, path string, args ...string) ([]byte, error)

// ProbeOptions controls how Probe acquires winget.exe and invokes it.
// Zero value picks safe defaults from the Windows build; on non-Windows
// the platform stub returns an unsupported Readiness without consulting
// the options.
type ProbeOptions struct {
	Locator Locator
	Execute Executor
	Timeout time.Duration
	Now     func() time.Time
}

// ErrWinGetNotFound is the canonical "winget.exe could not be located
// on this host" error. The probe surfaces it as
// AvailableInCurrentContext=false rather than as a fatal error.
var ErrWinGetNotFound = errors.New("winget.exe not found")

// DesktopAppInstallerGlob is the arch-agnostic AppX package-folder
// glob the Windows locator uses under %ProgramFiles%\WindowsApps.
// The folder format is
// Microsoft.DesktopAppInstaller_<version>_<arch>__8wekyb3d8bbwe
// (8wekyb3d8bbwe is the Microsoft Store publisher hash). The `*`
// spans the version+arch segment so the locator matches x64, arm64,
// arm and x86 identically. Prior to AG-026A's arch fix this glob
// hard-coded `_x64__`, so winget was never located under
// LocalSystem on ARM64 Windows (Windows-on-ARM / Apple-Silicon
// Parallels lab VMs), which made AG-026A report wingetReady=false
// and BE-021A preflight BLOCK every install on those endpoints.
const DesktopAppInstallerGlob = "Microsoft.DesktopAppInstaller_*__8wekyb3d8bbwe"

// versionPattern matches the dotted-numeric Version line from
// `winget --version` (which is typically prefixed with "v"). Anything
// before/after the matched group is ignored so we tolerate the various
// shapes winget returns ("v1.7.10861", "1.7.10861", "1.7.10861-preview").
var versionPattern = regexp.MustCompile(`v?(\d+\.\d+\.\d+(?:[\.\-]\w+)*)`)

// Probe runs the locator, then `winget --version` under a hard
// timeout, and constructs a Readiness with both probe signals.
//
// Two design notes worth keeping:
//
//  1. The args slice is hard-coded inside this function (NOT taken
//     from opts) so a future caller cannot accidentally pass through
//     a user-controlled argv. The only command this package will ever
//     run is `winget --version`.
//
//  2. systemContextReady is gated on three conditions, in this order:
//     binary found, no timeout, parseable version string. Any one
//     missing flips the flag to false even if the other two pass.
func Probe(opts ProbeOptions) (readiness Readiness) {
	if opts.Timeout <= 0 {
		opts.Timeout = DefaultProbeTimeout * time.Second
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	readiness = Readiness{
		Supported:     true,
		SchemaVersion: SchemaVersion,
	}
	if opts.Locator == nil || opts.Execute == nil {
		readiness.ProbeError = "probe options incomplete"
		return readiness
	}
	// Named return + defer is the only reliable way to record the
	// elapsed duration on every exit path (locator error, executor
	// error, timeout, parse failure, success). Without the named
	// return the defer body operates on a fresh copy and the field
	// stays zero — that bit us in iteration 1.
	startedAt := opts.Now()
	defer func() {
		readiness.ProbeDurationMs = int(opts.Now().Sub(startedAt) / time.Millisecond)
	}()

	path, err := opts.Locator()
	if err != nil {
		readiness.ProbeError = security.RedactSoftwareString(err.Error())
		return readiness
	}
	readiness.ExecutablePath = security.RedactSoftwareString(path)
	readiness.AvailableInCurrentContext = true

	ctx, cancel := context.WithTimeout(context.Background(), opts.Timeout)
	defer cancel()
	stdout, err := opts.Execute(ctx, path, "--version")
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		readiness.Timeout = true
		readiness.ProbeError = "winget --version timed out"
		return readiness
	}
	if err != nil {
		readiness.ProbeError = security.RedactSoftwareString(err.Error())
		return readiness
	}
	version := parseVersion(string(stdout))
	if version == "" {
		readiness.ProbeError = "winget --version returned no recognisable version"
		return readiness
	}
	readiness.Version = version
	readiness.SystemContextReady = true
	return readiness
}

// parseVersion grabs the first dotted-numeric token from `winget
// --version` output. It is deliberately permissive about leading
// "v"/trailing build qualifiers so we don't have to chase WinGet
// release-format changes.
func parseVersion(output string) string {
	for _, line := range strings.Split(output, "\n") {
		if match := versionPattern.FindStringSubmatch(strings.TrimSpace(line)); len(match) >= 2 {
			return match[1]
		}
	}
	return ""
}
