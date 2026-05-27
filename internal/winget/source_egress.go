package winget

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"platform-agent/internal/security"
)

// AG-026A — WinGet source/egress readiness preflight (Faz 22.5).
//
// HARD BOUNDARY (Codex 019e6b5d plan-time AGREE, kilit şart):
//
//   AG-026A only produces read-only WinGet source/egress readiness
//   evidence; it does not pull backend catalog, does not classify
//   unauthorized software, and does not install/uninstall/upgrade
//   anything.
//
// What this file adds on top of the AG-026 `winget --version`
// readiness probe (probe.go):
//
//   1. `winget source list` parser + executor — read-only, fixed
//      argv. The package NEVER calls `winget source add/remove/
//      update/reset`, `winget install/upgrade/uninstall`, or any
//      other mutating subcommand.
//   2. Single, fixed package-id query (`winget show --id <pkg>`)
//      against `7zip.7zip` (the pilot package per Codex
//      019e6b5d). The package id is hard-coded inside this file
//      so a future caller cannot inject an arbitrary id.
//   3. DNS / TCP / HTTPS reachability summary for the WinGet
//      community + msstore CDN endpoints. The hostname list is
//      hard-coded (no payload-controlled URLs); the seam allows
//      tests to inject fake resolver / dialer / HTTP checker
//      implementations without touching the real network.
//
// What this file deliberately does NOT do (scope discipline):
//
//   - Does not advertise install/uninstall capabilities.
//   - Does not pull or mirror any backend approved-catalog
//     payload — catalog authority stays at BE-020 admin endpoints.
//   - Does not classify unauthorized software (BE-023 / BE-025).
//   - Does not run install execution (AG-027).
//   - Does not modify WinGet sources or settings.

// FixedPackageQueryID is the single id this preflight is allowed
// to query. It is intentionally a const so the executor cannot be
// tricked into running `winget show --id <user-input>` via a
// future refactor or payload field. Pilot choice per Codex
// 019e6b5d: 7zip.7zip is small, widely available on both default
// sources, and well-behaved under LocalSystem.
const FixedPackageQueryID = "7zip.7zip"

// DefaultSourceEgressTimeout is the wall-clock budget for the
// entire preflight (source list + package query + egress probes
// combined). The COLLECT_INVENTORY command stays responsive even
// when one upstream stalls.
const DefaultSourceEgressTimeout = 15 // seconds

// SourceEgressSchemaVersion is bumped when a non-additive change
// ships. Independent from the legacy `Readiness.SchemaVersion`
// (which stays pinned to AG-026's `--version` probe shape).
const SourceEgressSchemaVersion = 1

// defaultEgressTargets is the hard-coded list of hostnames that
// WinGet's two default sources rely on. Unexported + read-only: the
// only way to surface this list to a caller is DefaultEgressTargets()
// which returns a copy. A future contributor cannot mutate the list
// in-place or wire an alternative via SourceEgressOptions (the
// options struct intentionally has no Targets field — see Codex
// 019e6b70 iter-1 P1#2 absorb).
var defaultEgressTargets = [...]EgressTarget{
	// Community repo (winget source) CDN endpoint.
	{Source: "winget", Hostname: "cdn.winget.microsoft.com", Port: 443},
	// Microsoft Store source (msstore) edge.
	{Source: "msstore", Hostname: "storeedgefd.dsx.mp.microsoft.com", Port: 443},
}

// DefaultEgressTargets returns a copy of the hard-coded egress
// target list. Callers cannot mutate the canonical slice — every
// invocation allocates a fresh backing array. The preflight runner
// uses this internally; external code uses it for diagnostics
// (e.g. operator runbooks listing the expected reachability
// surface).
func DefaultEgressTargets() []EgressTarget {
	out := make([]EgressTarget, len(defaultEgressTargets))
	copy(out, defaultEgressTargets[:])
	return out
}

// EgressTarget pairs a logical source with the network endpoint
// the WinGet client opens against. Source is informational only;
// the network probe runs Hostname:Port regardless of which
// `winget source list` entry it correlates with.
type EgressTarget struct {
	Source   string
	Hostname string
	Port     int
}

// Resolver looks up the addresses for a hostname. Tests inject a
// deterministic stub; production wires net.DefaultResolver.LookupHost.
type Resolver func(ctx context.Context, host string) ([]string, error)

// Dialer opens a TCP connection to host:port and immediately closes
// it. Tests inject a stub; production wires (&net.Dialer{}).DialContext
// followed by Close.
type Dialer func(ctx context.Context, network, address string) error

// HTTPChecker runs an HTTPS HEAD against the given URL and reports
// whether the response was reachable. The probe does NOT inspect
// the body or care about the status code — any HTTP/TLS response
// is sufficient to prove the host is reachable. Tests inject a
// stub; production wires an http.Client with short timeouts.
type HTTPChecker func(ctx context.Context, target string) (statusCode int, err error)

// SourceEgressOptions controls how RunSourceEgressPreflight acquires
// winget.exe, invokes its read-only subcommands, and probes the
// upstream endpoints. Zero value yields safe defaults on Windows;
// the seam fields allow tests to override every I/O boundary so the
// package can be exercised hermetically.
//
// HARD BOUNDARY (Codex 019e6b70 iter-1 P1#2 absorb): the options
// struct intentionally has no Targets or PackageID field. The egress
// target list is hard-coded (defaultEgressTargets) and the package
// id is hard-coded (FixedPackageQueryID); a future caller cannot
// override either via the public surface. Tests inject alternative
// targets via the unexported runEgressWith helper inside the package
// — that is the only way the preflight will dial a non-default host.
type SourceEgressOptions struct {
	Locator   Locator
	Execute   Executor
	Resolve   Resolver
	Dial      Dialer
	HTTPCheck HTTPChecker
	Timeout   time.Duration
	Now       func() time.Time
}

// SourceInfo is one row from `winget source list`.
type SourceInfo struct {
	Name       string `json:"name"`
	Argument   string `json:"argument"`
	Type       string `json:"type,omitempty"`
	TrustLevel string `json:"trustLevel,omitempty"`
	Explicit   bool   `json:"explicit,omitempty"`
}

// PackageQueryResult is the structured outcome of the single,
// fixed package-id reachability probe (`winget show --id <pkg>`).
//
//   - Found is true when winget emitted a non-empty package
//     manifest (any version is sufficient).
//   - ExitCode is the process exit code; non-zero with Timeout=false
//     and Found=false means the source could not satisfy the query.
//   - DurationMs is wall-clock; bounded by SourceEgressOptions.Timeout.
//   - ErrorReason is sanitised via security.RedactSoftwareString.
type PackageQueryResult struct {
	PackageID   string `json:"packageId"`
	Found       bool   `json:"found"`
	ExitCode    int    `json:"exitCode"`
	DurationMs  int    `json:"durationMs"`
	Timeout     bool   `json:"timeout"`
	ErrorReason string `json:"errorReason,omitempty"`
}

// NetworkCheck is a single DNS / TCP / HTTPS probe result. Target
// is the hostname (DNS), host:port (TCP), or full URL (HTTPS).
type NetworkCheck struct {
	Target      string `json:"target"`
	OK          bool   `json:"ok"`
	DurationMs  int    `json:"durationMs"`
	ErrorReason string `json:"errorReason,omitempty"`
}

// EgressSummary aggregates the DNS / TCP / HTTPS reachability
// probes against DefaultEgressTargets.
type EgressSummary struct {
	DNS        []NetworkCheck `json:"dns,omitempty"`
	TCP        []NetworkCheck `json:"tcp,omitempty"`
	HTTPS      []NetworkCheck `json:"https,omitempty"`
	ProxyURL   string         `json:"proxyUrl,omitempty"`
	ProxyConfigured bool      `json:"proxyConfigured"`
}

// SourceEgressReadiness is the wire-safe preflight result.
//
//   - Supported is false on non-Windows builds.
//   - Sources lists what `winget source list` returned (read-only).
//     Empty list with a non-empty SourceListError means the source-list
//     subcommand failed or timed out (Codex 019e6b70 iter-1 P1#3
//     absorb); empty list with no error means winget reported no
//     configured sources.
//   - SourceListError is the sanitised reason `winget source list`
//     failed (timeout, non-zero exit, parse failure). Set only on
//     failure; absent from the wire when the subcommand returned a
//     parseable table.
//   - PackageQuery is the result of the FixedPackageQueryID probe.
//   - Egress is the DNS / TCP / HTTPS reachability rollup.
//   - SchemaVersion gates wire-evolution.
//   - Timeout is true when the overall preflight budget was exceeded
//     OR any sub-probe (source list, package query, egress) hit its
//     own deadline. Individual NetworkCheck rows + PackageQuery.Timeout
//     still carry per-probe error reasons.
type SourceEgressReadiness struct {
	Supported       bool               `json:"supported"`
	SchemaVersion   int                `json:"schemaVersion"`
	ProbeDurationMs int                `json:"probeDurationMs"`
	Timeout         bool               `json:"timeout"`
	ProbeError      string             `json:"probeError,omitempty"`
	Sources         []SourceInfo       `json:"sources,omitempty"`
	SourceListError string             `json:"sourceListError,omitempty"`
	PackageQuery    PackageQueryResult `json:"packageQuery"`
	Egress          EgressSummary      `json:"egress"`
}

// RunSourceEgressPreflight executes the read-only AG-026A preflight
// pipeline: locator → `winget source list` → fixed-id `winget show`
// → DNS / TCP / HTTPS probes.
//
// The function never invokes a mutating subcommand and never accepts
// a caller-supplied argv. Every argv element is constructed inside
// this file so there is a single audit point for the boundary.
//
// Timeout discipline (Codex 019e6b70 iter-1 P1#1 absorb):
//
//   - opts.Timeout is the OVERALL budget for the entire preflight.
//   - A single root context with that deadline is created here; every
//     sub-probe derives a child context from it via the per-probe
//     slice. The deadline ALSO clamps the total wall-clock even if
//     the per-probe slice is larger.
//   - The per-probe slice is `remaining / N` where N is the number of
//     sub-probes still to run, with a 250ms floor; this gives the
//     short-budget worst case a chance to finish at least one cheap
//     probe before the root deadline elapses. (The previous fixed
//     `opts.Timeout / 3` slice violated the overall budget on
//     pathological inputs where every sub-probe stalled to the slice
//     deadline.)
//   - Source-list, package-query, AND egress timeouts ALL flip
//     readiness.Timeout=true (previously only PackageQuery.Timeout
//     surfaced — see Codex 019e6b70 P1#3).
func RunSourceEgressPreflight(opts SourceEgressOptions) (readiness SourceEgressReadiness) {
	if opts.Timeout <= 0 {
		opts.Timeout = DefaultSourceEgressTimeout * time.Second
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}

	readiness = SourceEgressReadiness{
		Supported:     true,
		SchemaVersion: SourceEgressSchemaVersion,
		PackageQuery: PackageQueryResult{
			PackageID: FixedPackageQueryID,
		},
	}

	startedAt := opts.Now()
	defer func() {
		readiness.ProbeDurationMs = int(opts.Now().Sub(startedAt) / time.Millisecond)
	}()

	if opts.Locator == nil || opts.Execute == nil {
		readiness.ProbeError = "preflight options incomplete"
		return readiness
	}

	wingetPath, err := opts.Locator()
	if err != nil {
		readiness.ProbeError = security.RedactSoftwareString(err.Error())
		return readiness
	}

	// Root context with the overall preflight deadline. Every
	// sub-probe is bounded by this AND its per-probe slice.
	rootCtx, rootCancel := context.WithTimeout(context.Background(), opts.Timeout)
	defer rootCancel()

	// 1. Source list (read-only, fixed argv).
	sources, sourceListErr, sourceListTimedOut := runSourceList(rootCtx, opts, wingetPath, perProbeSlice(rootCtx, opts.Now, 3))
	readiness.Sources = sources
	if sourceListErr != "" {
		readiness.SourceListError = sourceListErr
	}
	if sourceListTimedOut {
		readiness.Timeout = true
	}

	// 2. Fixed package-id query (read-only, fixed argv).
	readiness.PackageQuery = runPackageQuery(rootCtx, opts, wingetPath, perProbeSlice(rootCtx, opts.Now, 2))
	if readiness.PackageQuery.Timeout {
		readiness.Timeout = true
	}

	// 3. Egress reachability (DNS / TCP / HTTPS).
	readiness.Egress = runEgressWith(rootCtx, opts, defaultEgressTargets[:], perProbeSlice(rootCtx, opts.Now, 1))
	if egressTimedOut(readiness.Egress) {
		readiness.Timeout = true
	}

	// 4. Proxy snapshot. Reads the standard env vars on the agent
	//    host; the URL is sanitised before leaving the function.
	readiness.Egress.ProxyConfigured, readiness.Egress.ProxyURL = readProxyConfig()

	return readiness
}

// perProbeSlice returns the per-sub-probe deadline given the remaining
// root-context budget and the number of sub-probes still to run. A
// 250ms floor keeps the cheap egress probes responsive even when the
// overall budget is nearly spent; the root context still clamps the
// total wall-clock so a slow probe cannot exceed the overall deadline.
func perProbeSlice(rootCtx context.Context, now func() time.Time, remainingProbes int) time.Duration {
	deadline, ok := rootCtx.Deadline()
	if !ok || remainingProbes <= 0 {
		return time.Second
	}
	remaining := deadline.Sub(now())
	if remaining <= 0 {
		return 0
	}
	slice := remaining / time.Duration(remainingProbes)
	const floor = 250 * time.Millisecond
	if slice < floor {
		return floor
	}
	return slice
}

// egressTimedOut reports whether any DNS / TCP / HTTPS check
// recorded a context-deadline error. Used to roll the per-probe
// timeout signal up into readiness.Timeout for the overall flag.
func egressTimedOut(summary EgressSummary) bool {
	for _, check := range summary.DNS {
		if isTimeoutReason(check.ErrorReason) {
			return true
		}
	}
	for _, check := range summary.TCP {
		if isTimeoutReason(check.ErrorReason) {
			return true
		}
	}
	for _, check := range summary.HTTPS {
		if isTimeoutReason(check.ErrorReason) {
			return true
		}
	}
	return false
}

func isTimeoutReason(reason string) bool {
	if reason == "" {
		return false
	}
	lc := strings.ToLower(reason)
	return strings.Contains(lc, "deadline exceeded") || strings.Contains(lc, "timed out") || strings.Contains(lc, "timeout")
}

// runSourceList invokes `winget source list` and parses the
// fixed tabular output into SourceInfo rows.
//
// Codex 019e6b70 iter-1 P1#3 absorb: the function now returns the
// sanitised error reason + a timeout flag so the caller can surface
// both on the wire (SourceEgressReadiness.SourceListError +
// .Timeout). The previous "_" discard pattern hid timeout / non-zero
// / parse failures from the operator.
func runSourceList(parent context.Context, opts SourceEgressOptions, wingetPath string, timeout time.Duration) (sources []SourceInfo, errorReason string, timedOut bool) {
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	// FIXED ARGV — never composed from payload.
	stdout, err := opts.Execute(ctx, wingetPath, "source", "list")
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return nil, "winget source list timed out", true
	}
	if err != nil {
		return nil, security.RedactSoftwareString(err.Error()), false
	}
	parsed := parseSourceListOutput(string(stdout))
	if len(parsed) == 0 && strings.TrimSpace(string(stdout)) != "" {
		// Stdout had content but did not parse — flag for operator
		// without dropping the underlying signal.
		return parsed, "winget source list output not parseable", false
	}
	return parsed, "", false
}

// parseSourceListOutput accepts the raw `winget source list`
// stdout and returns one SourceInfo per source row. Tolerant of
// localized header text — it identifies the header row by the
// presence of a fixed-width separator line of dashes immediately
// below it (a winget UI convention that is stable across
// localizations).
//
// The parser is deliberately defensive: malformed / empty input
// yields an empty slice rather than an error, which lets the
// caller surface a readiness signal ("source list unreadable")
// without losing the rest of the preflight.
func parseSourceListOutput(raw string) []SourceInfo {
	lines := strings.Split(raw, "\n")
	headerIdx := -1
	for i := 0; i < len(lines)-1; i++ {
		// Header row is followed by a row of dashes; we tolerate
		// per-column dash groups separated by whitespace ("---  ---")
		// because winget pads the separator to the column widths
		// in some locales / terminal widths.
		next := strings.TrimSpace(lines[i+1])
		if next == "" {
			continue
		}
		if isDashSeparator(next) {
			headerIdx = i
			break
		}
	}
	if headerIdx < 0 {
		return nil
	}
	header := lines[headerIdx]
	// Identify column boundaries from runs of whitespace in the
	// header row. WinGet keeps the columns at fixed offsets in
	// the source list output even after localization.
	columns := splitFixedColumns(header)
	if len(columns) < 2 {
		return nil
	}
	var out []SourceInfo
	for _, line := range lines[headerIdx+2:] {
		trimmed := strings.TrimRight(line, "\r\n")
		if strings.TrimSpace(trimmed) == "" {
			continue
		}
		fields := splitByColumns(trimmed, columns)
		if len(fields) < 2 {
			continue
		}
		info := SourceInfo{
			Name:     strings.TrimSpace(fields[0]),
			Argument: security.RedactSoftwareString(strings.TrimSpace(fields[1])),
		}
		if len(fields) >= 3 {
			info.Type = strings.TrimSpace(fields[2])
		}
		if len(fields) >= 4 {
			info.TrustLevel = strings.TrimSpace(fields[3])
		}
		if len(fields) >= 5 {
			info.Explicit = strings.EqualFold(strings.TrimSpace(fields[4]), "true")
		}
		if info.Name == "" {
			continue
		}
		out = append(out, info)
	}
	return out
}

// isDashSeparator reports whether a trimmed line consists only of
// dashes and whitespace, with at least 3 dashes present. This is
// the heuristic for the row that winget prints between the table
// header and the data rows.
func isDashSeparator(line string) bool {
	dashCount := 0
	for _, r := range line {
		switch r {
		case '-':
			dashCount++
		case ' ', '\t':
			// allowed
		default:
			return false
		}
	}
	return dashCount >= 3
}

// splitFixedColumns returns the byte offset where each column
// begins, computed from runs of whitespace in the header row.
func splitFixedColumns(header string) []int {
	var starts []int
	inSpace := true
	for i, r := range header {
		if r == ' ' || r == '\t' {
			inSpace = true
			continue
		}
		if inSpace {
			starts = append(starts, i)
		}
		inSpace = false
	}
	return starts
}

// splitByColumns slices the line at the given column offsets.
// Missing trailing columns yield empty strings; an over-short
// line returns fewer elements.
func splitByColumns(line string, columns []int) []string {
	out := make([]string, 0, len(columns))
	for i, start := range columns {
		if start >= len(line) {
			break
		}
		end := len(line)
		if i+1 < len(columns) && columns[i+1] <= len(line) {
			end = columns[i+1]
		}
		out = append(out, line[start:end])
	}
	return out
}

// runPackageQuery executes `winget show --id <FixedPackageQueryID>`
// with the package id pinned to the hard-coded constant.
//
// Codex 019e6b70 iter-1 P2#4 absorb: the success criterion is now
// "winget exited cleanly AND emitted the pinned package id (case-
// insensitive) somewhere in stdout" rather than the previous
// English-only "no package found" negative heuristic. The new check
// is robust against localized winget output (Turkish "paket
// bulunamadı", German "Kein Paket gefunden", Japanese
// "パッケージが見つかりません", etc.) because the canonical id is the
// same in every locale.
func runPackageQuery(parent context.Context, opts SourceEgressOptions, wingetPath string, timeout time.Duration) PackageQueryResult {
	result := PackageQueryResult{
		PackageID: FixedPackageQueryID,
	}
	startedAt := opts.Now()
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	// FIXED ARGV. The package id is the constant — no SourceEgressOptions
	// field can override it (Codex 019e6b70 iter-1 P1#2 / P2 absorb).
	stdout, err := opts.Execute(ctx, wingetPath, "show", "--id", FixedPackageQueryID, "--exact", "--disable-interactivity")
	result.DurationMs = int(opts.Now().Sub(startedAt) / time.Millisecond)
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		result.Timeout = true
		result.ErrorReason = "winget show timed out"
		return result
	}
	if err != nil {
		var exitErr interface{ ExitCode() int }
		if errors.As(err, &exitErr) {
			result.ExitCode = exitErr.ExitCode()
		} else {
			result.ExitCode = -1
		}
		result.ErrorReason = security.RedactSoftwareString(err.Error())
		return result
	}
	// Locale-stable check: the canonical package id (FixedPackageQueryID
	// = "7zip.7zip") appears in any successful `winget show --exact`
	// output, regardless of the operator's regional settings. Exit code
	// 0 alone is not sufficient because winget can emit diagnostic
	// banners without a manifest.
	body := string(stdout)
	result.Found = strings.Contains(strings.ToLower(body), strings.ToLower(FixedPackageQueryID))
	return result
}

// runEgressWith runs DNS / TCP / HTTPS probes against the supplied
// target slice. Production callers always pass the unexported
// defaultEgressTargets — no public path exists for an alternative
// target list (Codex 019e6b70 iter-1 P1#2 absorb). Tests inside the
// same package can pass their own targets via this internal helper
// without exposing a Targets field on SourceEgressOptions.
//
// Each sub-probe uses its own context derived from the parent root
// context so the overall preflight deadline always clamps the total
// wall-clock even if the per-probe slice is larger.
func runEgressWith(parent context.Context, opts SourceEgressOptions, targets []EgressTarget, perProbe time.Duration) EgressSummary {
	summary := EgressSummary{}
	resolve := opts.Resolve
	if resolve == nil {
		resolve = defaultResolver
	}
	dial := opts.Dial
	if dial == nil {
		dial = defaultDialer
	}
	httpCheck := opts.HTTPCheck
	if httpCheck == nil {
		httpCheck = defaultHTTPChecker
	}
	for _, target := range targets {
		summary.DNS = append(summary.DNS, runDNS(parent, resolve, target.Hostname, perProbe, opts.Now))
		summary.TCP = append(summary.TCP, runTCP(parent, dial, target.Hostname, target.Port, perProbe, opts.Now))
		summary.HTTPS = append(summary.HTTPS, runHTTPS(parent, httpCheck, target.Hostname, target.Port, perProbe, opts.Now))
	}
	return summary
}

func runDNS(parent context.Context, resolve Resolver, host string, timeout time.Duration, now func() time.Time) NetworkCheck {
	check := NetworkCheck{Target: host}
	startedAt := now()
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	_, err := resolve(ctx, host)
	check.DurationMs = int(now().Sub(startedAt) / time.Millisecond)
	if err != nil {
		check.ErrorReason = security.RedactSoftwareString(err.Error())
		return check
	}
	check.OK = true
	return check
}

func runTCP(parent context.Context, dial Dialer, host string, port int, timeout time.Duration, now func() time.Time) NetworkCheck {
	address := host + ":" + portString(port)
	check := NetworkCheck{Target: address}
	startedAt := now()
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	err := dial(ctx, "tcp", address)
	check.DurationMs = int(now().Sub(startedAt) / time.Millisecond)
	if err != nil {
		check.ErrorReason = security.RedactSoftwareString(err.Error())
		return check
	}
	check.OK = true
	return check
}

func runHTTPS(parent context.Context, httpCheck HTTPChecker, host string, port int, timeout time.Duration, now func() time.Time) NetworkCheck {
	target := "https://" + host
	if port != 443 {
		target += ":" + portString(port)
	}
	check := NetworkCheck{Target: target}
	startedAt := now()
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	_, err := httpCheck(ctx, target)
	check.DurationMs = int(now().Sub(startedAt) / time.Millisecond)
	if err != nil {
		check.ErrorReason = security.RedactSoftwareString(err.Error())
		return check
	}
	check.OK = true
	return check
}

// portString converts an int port to a decimal string without
// pulling strconv into this hot path for a single allocation.
func portString(port int) string {
	if port == 443 {
		return "443"
	}
	if port == 80 {
		return "80"
	}
	// Generic conversion; the explicit fast-paths above cover the
	// only ports DefaultEgressTargets uses today.
	digits := []byte{}
	if port <= 0 {
		return "0"
	}
	for port > 0 {
		digits = append([]byte{byte('0' + port%10)}, digits...)
		port /= 10
	}
	return string(digits)
}

// readProxyConfig returns whether an HTTPS_PROXY / HTTP_PROXY env
// var is set and emits a redacted form of the URL so credentials
// embedded as `http://user:pass@host` never reach the wire.
func readProxyConfig() (bool, string) {
	for _, name := range []string{"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"} {
		if v := strings.TrimSpace(getEnv(name)); v != "" {
			return true, redactProxyURL(v)
		}
	}
	return false, ""
}

// redactProxyURL strips the userinfo section of the proxy URL so
// `http://user:pass@host` becomes `http://host`. Falls back to
// the existing RedactSoftwareString for non-URL strings.
func redactProxyURL(raw string) string {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" {
		return security.RedactSoftwareString(raw)
	}
	parsed.User = nil
	return parsed.String()
}

// getEnv is a tiny indirection so tests can replace the env lookup
// without touching the real os.Getenv. Production wires os.Getenv.
var getEnv = os.Getenv

// defaultResolver / defaultDialer / defaultHTTPChecker are the
// production wiring for the seam. Tests replace the seam directly
// via SourceEgressOptions rather than monkey-patching these.
var (
	defaultResolver Resolver = func(ctx context.Context, host string) ([]string, error) {
		return net.DefaultResolver.LookupHost(ctx, host)
	}
	defaultDialer Dialer = func(ctx context.Context, network, address string) error {
		d := net.Dialer{}
		conn, err := d.DialContext(ctx, network, address)
		if err != nil {
			return err
		}
		_ = conn.Close()
		return nil
	}
	defaultHTTPChecker HTTPChecker = func(ctx context.Context, target string) (int, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodHead, target, nil)
		if err != nil {
			return 0, err
		}
		client := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
			},
		}
		resp, err := client.Do(req)
		if err != nil {
			return 0, err
		}
		defer resp.Body.Close()
		return resp.StatusCode, nil
	}
)
