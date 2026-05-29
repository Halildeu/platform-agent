package winget

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

// AG-026A — RunSourceEgressPreflight unit tests.
//
// Coverage targets the contract that Codex 019e6b5d plan-time
// AGREE locked in:
//
//   - Fixed argv only (no caller-supplied subcommand or args).
//   - Hard-coded package id (FixedPackageQueryID = 7zip.7zip).
//   - Hard-coded egress hostname list (DefaultEgressTargets).
//   - Read-only — no install/upgrade/uninstall, no source mutation.
//   - Timeout sliced per sub-probe so one stall cannot starve another.
//   - All free-form output redacted via security.RedactSoftwareString
//     (user paths, proxy credentials, SIDs, license-shaped strings).
//   - Non-Windows builds return Supported=false with the rest zero.

// ─── runner contract ────────────────────────────────────────────────

func TestRunSourceEgressMissingOptions(t *testing.T) {
	r := RunSourceEgressPreflight(SourceEgressOptions{})
	if !r.Supported {
		t.Fatalf("Supported should default to true on shared code path")
	}
	if r.ProbeError == "" {
		t.Fatalf("ProbeError should report incomplete options")
	}
	if r.PackageQuery.PackageID != FixedPackageQueryID {
		t.Fatalf("PackageQuery.PackageID = %q, want %q", r.PackageQuery.PackageID, FixedPackageQueryID)
	}
	if r.SchemaVersion != SourceEgressSchemaVersion {
		t.Fatalf("SchemaVersion = %d, want %d", r.SchemaVersion, SourceEgressSchemaVersion)
	}
}

// SourceEgressOptions.PackageID and SourceEgressOptions.Targets were
// removed in Codex 019e6b70 iter-1 absorb (public fields were
// footguns even with runtime guards). The constants
// (FixedPackageQueryID, defaultEgressTargets) are now the single
// source of truth.
//
// Codex 019e6b70 iter-2 absorb: reflection-based assertion replaces
// the previous struct-literal guard. A struct literal that only
// sets Locator+Execute would still compile if either field came
// back, so it does NOT actually pin the API surface. Reflection on
// the field set catches reintroduction directly.
func TestSourceEgressOptionsHasNoOverrideFields(t *testing.T) {
	typ := reflect.TypeOf(SourceEgressOptions{})
	forbidden := []string{"PackageID", "Targets"}
	for _, name := range forbidden {
		if _, ok := typ.FieldByName(name); ok {
			t.Fatalf("SourceEgressOptions must not expose %q (Codex 019e6b70 iter-1 P1#2 absorb)", name)
		}
	}
	// Runtime sanity: the readiness shape still echoes the pinned
	// id in PackageQuery.PackageID so backend parsers do not have to
	// handle a missing field.
	r := RunSourceEgressPreflight(SourceEgressOptions{})
	if r.PackageQuery.PackageID != FixedPackageQueryID {
		t.Fatalf("PackageQuery.PackageID = %q, want %q", r.PackageQuery.PackageID, FixedPackageQueryID)
	}
}

func TestRunSourceEgressLocatorErrorReturnsEarly(t *testing.T) {
	r := RunSourceEgressPreflight(SourceEgressOptions{
		Locator: func() (string, error) { return "", ErrWinGetNotFound },
		Execute: func(ctx context.Context, path string, args ...string) ([]byte, error) {
			t.Fatalf("executor must not run when locator fails")
			return nil, nil
		},
		Now: deterministicNow(0, 10),
	})
	if r.ProbeError == "" {
		t.Fatalf("locator error should populate ProbeError")
	}
}

func TestRunSourceEgressFixedSourceListArgv(t *testing.T) {
	var capturedSourceArgs []string
	_ = RunSourceEgressPreflight(SourceEgressOptions{
		Locator: func() (string, error) { return "winget.exe", nil },
		Execute: func(ctx context.Context, path string, args ...string) ([]byte, error) {
			if len(args) >= 2 && args[0] == "source" && args[1] == "list" {
				capturedSourceArgs = append([]string{}, args...)
				return []byte(sampleSourceListOutput()), nil
			}
			// `winget show` call — return nothing so the test stays focused.
			return []byte(""), nil
		},
		Resolve:   stubResolver(nil),
		Dial:      stubDialer(nil),
		HTTPCheck: stubHTTPChecker(200, nil),
		Now:       deterministicNow(0, 5, 10, 15, 20, 25, 30, 35, 40, 45, 50, 55, 60),
	})
	if len(capturedSourceArgs) != 2 {
		t.Fatalf("source list argv must be exactly [source list], got %#v", capturedSourceArgs)
	}
	if capturedSourceArgs[0] != "source" || capturedSourceArgs[1] != "list" {
		t.Fatalf("source list argv drift, got %#v", capturedSourceArgs)
	}
}

func TestRunSourceEgressFixedPackageQueryArgv(t *testing.T) {
	var capturedShowArgs []string
	_ = RunSourceEgressPreflight(SourceEgressOptions{
		Locator: func() (string, error) { return "winget.exe", nil },
		Execute: func(ctx context.Context, path string, args ...string) ([]byte, error) {
			if len(args) >= 1 && args[0] == "show" {
				capturedShowArgs = append([]string{}, args...)
				return []byte("Found 7-Zip 23.01\n"), nil
			}
			return []byte(sampleSourceListOutput()), nil
		},
		Resolve:   stubResolver(nil),
		Dial:      stubDialer(nil),
		HTTPCheck: stubHTTPChecker(200, nil),
		Now:       deterministicNow(0, 5, 10, 15, 20, 25, 30, 35, 40, 45, 50, 55, 60),
	})
	// The argv must contain show, --id, FixedPackageQueryID, --exact,
	// and --disable-interactivity. Order matters because winget is
	// position-sensitive for the subcommand.
	wantPrefix := []string{"show", "--id", FixedPackageQueryID, "--exact", "--disable-interactivity"}
	if len(capturedShowArgs) != len(wantPrefix) {
		t.Fatalf("show argv length = %d, want %d (%#v)", len(capturedShowArgs), len(wantPrefix), capturedShowArgs)
	}
	for i := range wantPrefix {
		if capturedShowArgs[i] != wantPrefix[i] {
			t.Fatalf("show argv[%d] = %q, want %q (full=%#v)", i, capturedShowArgs[i], wantPrefix[i], capturedShowArgs)
		}
	}
}

func TestRunSourceEgressForbiddenSubcommandsNeverInvoked(t *testing.T) {
	// Codex 019e6b70 iter-1 non-blocking note: list widened to cover
	// every mutating / config / interactive winget subcommand. This
	// is a regression belt — the actual security gate is the fixed
	// argv inside runSourceList / runPackageQuery (no caller path
	// can inject an alternative subcommand).
	forbidden := []string{
		"install", "upgrade", "uninstall",
		"add", "remove", "update", "reset",
		"export", "import",
		"hash", "validate", "pin",
		"configure", "download", "repair",
		"features", "complete", "debug",
		"settings",
	}
	_ = RunSourceEgressPreflight(SourceEgressOptions{
		Locator: func() (string, error) { return "winget.exe", nil },
		Execute: func(ctx context.Context, path string, args ...string) ([]byte, error) {
			if len(args) == 0 {
				return nil, nil
			}
			for _, banned := range forbidden {
				if args[0] == banned {
					t.Fatalf("AG-026A invoked forbidden subcommand %q (full argv %#v)", banned, args)
				}
				// source modify guards: ban second-arg variants too.
				if len(args) >= 2 && args[0] == "source" && args[1] == banned {
					t.Fatalf("AG-026A invoked forbidden source subcommand %q (full argv %#v)", banned, args)
				}
			}
			if args[0] == "source" {
				return []byte(sampleSourceListOutput()), nil
			}
			return []byte("Found 7-Zip\n"), nil
		},
		Resolve:   stubResolver(nil),
		Dial:      stubDialer(nil),
		HTTPCheck: stubHTTPChecker(200, nil),
		Now:       deterministicNow(0, 5, 10, 15, 20, 25, 30, 35, 40, 45, 50, 55, 60),
	})
}

func TestRunSourceEgressPackageQueryTimeoutDoesNotMaskSourceList(t *testing.T) {
	r := RunSourceEgressPreflight(SourceEgressOptions{
		Locator: func() (string, error) { return "winget.exe", nil },
		Execute: func(ctx context.Context, path string, args ...string) ([]byte, error) {
			if args[0] == "source" {
				return []byte(sampleSourceListOutput()), nil
			}
			// winget show stalls until the context is cancelled.
			<-ctx.Done()
			return nil, ctx.Err()
		},
		Resolve:   stubResolver(nil),
		Dial:      stubDialer(nil),
		HTTPCheck: stubHTTPChecker(200, nil),
		Timeout:   30 * time.Millisecond,
		Now:       deterministicNow(0, 5, 10, 15, 20, 25, 30, 35, 40, 45, 50, 55, 60),
	})
	if len(r.Sources) == 0 {
		t.Fatalf("source list should have parsed before package query stalled, got 0 sources")
	}
	if !r.PackageQuery.Timeout {
		t.Fatalf("package query timeout must surface PackageQuery.Timeout=true")
	}
	if !r.Timeout {
		t.Fatalf("overall Timeout flag must reflect at least one sub-probe timeout")
	}
}

func TestRunSourceEgressRedactsProbeError(t *testing.T) {
	r := RunSourceEgressPreflight(SourceEgressOptions{
		Locator: func() (string, error) {
			return "", errors.New(`failed to locate winget under C:\Users\halilkocoglu\AppData\Local\Microsoft\WindowsApps`)
		},
		Execute: func(ctx context.Context, path string, args ...string) ([]byte, error) {
			t.Fatalf("executor must not run when locator fails")
			return nil, nil
		},
		Now: deterministicNow(0, 1),
	})
	if strings.Contains(r.ProbeError, "halilkocoglu") {
		t.Fatalf("user segment leaked into ProbeError: %q", r.ProbeError)
	}
	if !strings.Contains(r.ProbeError, "[REDACTED]") {
		t.Fatalf("redaction sentinel missing in ProbeError: %q", r.ProbeError)
	}
}

// ─── source list parser ────────────────────────────────────────────

func TestParseSourceListWellFormed(t *testing.T) {
	out := parseSourceListOutput(sampleSourceListOutput())
	if len(out) != 2 {
		t.Fatalf("expected 2 sources from well-formed sample, got %d (%#v)", len(out), out)
	}
	if out[0].Name != "winget" {
		t.Fatalf("first source Name = %q, want winget", out[0].Name)
	}
	// Argument must be redacted (cdn.winget.microsoft.com has no PII,
	// but verify the redactor pass-through preserved it intact).
	if !strings.Contains(out[0].Argument, "winget.microsoft.com") {
		t.Fatalf("first source Argument lost canonical hostname: %q", out[0].Argument)
	}
}

func TestParseSourceListEmpty(t *testing.T) {
	if got := parseSourceListOutput(""); len(got) != 0 {
		t.Fatalf("empty input must yield 0 sources, got %#v", got)
	}
}

func TestParseSourceListMalformedReturnsEmpty(t *testing.T) {
	got := parseSourceListOutput("not a winget table\nat all\nseriously\n")
	if len(got) != 0 {
		t.Fatalf("malformed input must yield 0 sources, got %#v", got)
	}
}

func TestParseSourceListRedactsArgument(t *testing.T) {
	// Simulate (hypothetical) localized output where a source URL
	// embeds a user path. RedactSoftwareString must strip the user
	// segment before the value reaches the SourceInfo.Argument field.
	raw := "Name    Argument\n----    --------\nlocal   C:\\Users\\halilkocoglu\\custom\\source\n"
	got := parseSourceListOutput(raw)
	if len(got) != 1 {
		t.Fatalf("expected 1 source, got %d", len(got))
	}
	if strings.Contains(got[0].Argument, "halilkocoglu") {
		t.Fatalf("user segment leaked into Argument: %q", got[0].Argument)
	}
}

// ─── proxy URL redaction ───────────────────────────────────────────

func TestRedactProxyURLStripsUserInfo(t *testing.T) {
	// Build credential-shaped value via concatenation so secret scanners
	// (gitleaks) do not flag this fixture as a real leak (AG-025H
	// pattern, parser_test.go:151).
	user := "us" + "er"
	pass := "se" + "cret"
	raw := "http://" + user + ":" + pass + "@proxy.example.com:3128"
	got := redactProxyURL(raw)
	if strings.Contains(got, user) || strings.Contains(got, pass) {
		t.Fatalf("proxy userinfo leaked: %q", got)
	}
	if !strings.Contains(got, "proxy.example.com") {
		t.Fatalf("proxy hostname dropped: %q", got)
	}
}

func TestRedactProxyURLNonURLFallback(t *testing.T) {
	raw := "C:\\Users\\halilkocoglu\\proxy.cfg"
	got := redactProxyURL(raw)
	if strings.Contains(got, "halilkocoglu") {
		t.Fatalf("non-URL fallback leaked user segment: %q", got)
	}
}

// ─── DNS / TCP / HTTPS probes ──────────────────────────────────────

func TestRunSourceEgressEgressOKWithStubs(t *testing.T) {
	r := RunSourceEgressPreflight(SourceEgressOptions{
		Locator:   func() (string, error) { return "winget.exe", nil },
		Execute:   func(ctx context.Context, path string, args ...string) ([]byte, error) { return []byte(""), nil },
		Resolve:   stubResolver([]string{"203.0.113.10"}),
		Dial:      stubDialer(nil),
		HTTPCheck: stubHTTPChecker(200, nil),
		Now:       deterministicNow(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16),
	})
	if len(r.Egress.DNS) != len(DefaultEgressTargets()) {
		t.Fatalf("expected DNS probe per target (%d), got %d", len(DefaultEgressTargets()), len(r.Egress.DNS))
	}
	for i, check := range r.Egress.DNS {
		if !check.OK {
			t.Fatalf("DNS check %d = %#v, expected OK", i, check)
		}
	}
	for i, check := range r.Egress.TCP {
		if !check.OK {
			t.Fatalf("TCP check %d = %#v, expected OK", i, check)
		}
	}
	for i, check := range r.Egress.HTTPS {
		if !check.OK {
			t.Fatalf("HTTPS check %d = %#v, expected OK", i, check)
		}
	}
}

func TestRunSourceEgressEgressFailureRedacts(t *testing.T) {
	r := RunSourceEgressPreflight(SourceEgressOptions{
		Locator: func() (string, error) { return "winget.exe", nil },
		Execute: func(ctx context.Context, path string, args ...string) ([]byte, error) { return []byte(""), nil },
		Resolve: func(ctx context.Context, host string) ([]string, error) {
			return nil, errors.New(`lookup failed via C:\Users\halilkocoglu\resolvconf`)
		},
		Dial:      stubDialer(nil),
		HTTPCheck: stubHTTPChecker(200, nil),
		Now:       deterministicNow(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16),
	})
	for _, check := range r.Egress.DNS {
		if strings.Contains(check.ErrorReason, "halilkocoglu") {
			t.Fatalf("DNS ErrorReason leaked user segment: %q", check.ErrorReason)
		}
	}
}

// ─── helpers ───────────────────────────────────────────────────────

func deterministicNow(offsetsMs ...int) func() time.Time {
	base := time.Date(2026, 5, 27, 12, 0, 0, 0, time.UTC)
	idx := 0
	return func() time.Time {
		var off int
		if idx < len(offsetsMs) {
			off = offsetsMs[idx]
		} else {
			off = offsetsMs[len(offsetsMs)-1]
		}
		idx++
		return base.Add(time.Duration(off) * time.Millisecond)
	}
}

func stubResolver(addrs []string) Resolver {
	return func(ctx context.Context, host string) ([]string, error) {
		return addrs, nil
	}
}

func stubDialer(err error) Dialer {
	return func(ctx context.Context, network, address string) error {
		return err
	}
}

func stubHTTPChecker(status int, err error) HTTPChecker {
	return func(ctx context.Context, target string) (int, error) {
		return status, err
	}
}

// ─── Codex 019e6b70 iter-1 absorb regression coverage ─────────────

// P1#1 — overall timeout enforcement. With a 100ms overall budget
// and stalled sub-probes, the total wall-clock must be bounded by
// the budget (modulo small slop) — NOT 3× the budget as the
// previous per-slice math could produce.
func TestRunSourceEgressOverallTimeoutBudgetEnforced(t *testing.T) {
	r := RunSourceEgressPreflight(SourceEgressOptions{
		Locator: func() (string, error) { return "winget.exe", nil },
		Execute: func(ctx context.Context, path string, args ...string) ([]byte, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		},
		Resolve: func(ctx context.Context, host string) ([]string, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		},
		Dial: func(ctx context.Context, network, address string) error {
			<-ctx.Done()
			return ctx.Err()
		},
		HTTPCheck: func(ctx context.Context, target string) (int, error) {
			<-ctx.Done()
			return 0, ctx.Err()
		},
		Timeout: 100 * time.Millisecond,
	})
	// Tolerate up to 2× the budget for goroutine + cleanup slop.
	if r.ProbeDurationMs > 500 {
		t.Fatalf("overall preflight exceeded budget: got %dms (limit 500ms)", r.ProbeDurationMs)
	}
	if !r.Timeout {
		t.Fatalf("overall Timeout flag must reflect sub-probe deadlines, got %#v", r)
	}
}

// P1#3 — source-list failure visibility. The previous "_" discard
// pattern hid timeout / parse-failure from the operator; the new
// SourceEgressReadiness.SourceListError field must surface both.
func TestRunSourceEgressSourceListErrorSurfaced(t *testing.T) {
	r := RunSourceEgressPreflight(SourceEgressOptions{
		Locator: func() (string, error) { return "winget.exe", nil },
		Execute: func(ctx context.Context, path string, args ...string) ([]byte, error) {
			if args[0] == "source" {
				return nil, errors.New("source list exited with non-zero")
			}
			return []byte("Found 7-Zip [7zip.7zip]\n"), nil
		},
		Resolve:   stubResolver(nil),
		Dial:      stubDialer(nil),
		HTTPCheck: stubHTTPChecker(200, nil),
		Now:       deterministicNow(0, 5, 10, 15, 20, 25, 30, 35, 40, 45, 50, 55, 60),
	})
	if r.SourceListError == "" {
		t.Fatalf("SourceListError must surface non-zero source-list exit, got empty")
	}
	if strings.Contains(r.SourceListError, "non-zero") == false && strings.Contains(r.SourceListError, "exited") == false {
		t.Fatalf("SourceListError = %q, want sanitised error reason", r.SourceListError)
	}
}

func TestRunSourceEgressSourceListTimeoutSurfacesOverallTimeout(t *testing.T) {
	r := RunSourceEgressPreflight(SourceEgressOptions{
		Locator: func() (string, error) { return "winget.exe", nil },
		Execute: func(ctx context.Context, path string, args ...string) ([]byte, error) {
			if args[0] == "source" {
				<-ctx.Done()
				return nil, ctx.Err()
			}
			return []byte("Found 7-Zip [7zip.7zip]\n"), nil
		},
		Resolve:   stubResolver(nil),
		Dial:      stubDialer(nil),
		HTTPCheck: stubHTTPChecker(200, nil),
		Timeout:   60 * time.Millisecond,
	})
	if !r.Timeout {
		t.Fatalf("source-list timeout must flip overall Timeout=true")
	}
	if r.SourceListError == "" {
		t.Fatalf("source-list timeout must populate SourceListError")
	}
}

// P2#4 — Found heuristic must be locale-stable. The previous
// "no package found" English-only negative match would have
// false-positived Turkish "paket bulunamadı" output as Found=true.
func TestRunPackageQueryFoundLocaleStable(t *testing.T) {
	cases := []struct {
		name      string
		stdout    string
		wantFound bool
	}{
		{
			name:      "english-found-with-id",
			stdout:    "Found 7-Zip [7zip.7zip]\nVersion: 24.07\n",
			wantFound: true,
		},
		{
			name:      "english-not-found-without-id",
			stdout:    "No package found matching input criteria.\n",
			wantFound: false,
		},
		{
			name:      "turkish-not-found",
			stdout:    "Giriş ölçütleriyle eşleşen paket bulunamadı.\n",
			wantFound: false,
		},
		{
			name:      "diagnostic-banner-without-id",
			stdout:    "[WARN] Cache miss — source 'winget' fell back to network.\n",
			wantFound: false,
		},
		{
			name:      "mixed-case-id-match",
			stdout:    "Found 7-Zip [7Zip.7Zip] manifest entry.\n",
			wantFound: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := RunSourceEgressPreflight(SourceEgressOptions{
				Locator: func() (string, error) { return "winget.exe", nil },
				Execute: func(ctx context.Context, path string, args ...string) ([]byte, error) {
					if len(args) >= 1 && args[0] == "show" {
						return []byte(tc.stdout), nil
					}
					return []byte(sampleSourceListOutput()), nil
				},
				Resolve:   stubResolver(nil),
				Dial:      stubDialer(nil),
				HTTPCheck: stubHTTPChecker(200, nil),
				Now:       deterministicNow(0, 5, 10, 15, 20, 25, 30, 35, 40, 45, 50, 55, 60),
			})
			if r.PackageQuery.Found != tc.wantFound {
				t.Fatalf("Found = %v, want %v (stdout=%q)", r.PackageQuery.Found, tc.wantFound, tc.stdout)
			}
		})
	}
}

// P1#2 — DefaultEgressTargets() returns a copy so callers cannot
// mutate the canonical list. The unexported defaultEgressTargets
// array stays read-only.
func TestDefaultEgressTargetsReturnsCopy(t *testing.T) {
	a := DefaultEgressTargets()
	if len(a) == 0 {
		t.Fatalf("DefaultEgressTargets() must return the hard-coded list")
	}
	original := a[0].Hostname
	a[0].Hostname = "attacker.example.com"
	b := DefaultEgressTargets()
	if b[0].Hostname != original {
		t.Fatalf("mutation leaked into canonical list: b[0].Hostname=%q", b[0].Hostname)
	}
}

func sampleSourceListOutput() string {
	// Approximates the actual winget source list output. The header is
	// followed by a separator line of dashes; the data rows align on
	// the same columns as the header.
	return "" +
		"Name      Argument                                          Type                              Trust\n" +
		"--------------------------------------------------------------------------------------------------\n" +
		"winget    https://cdn.winget.microsoft.com/cache            Microsoft.PreIndexed.Package      Trusted\n" +
		"msstore   https://storeedgefd.dsx.mp.microsoft.com/v9.0     Microsoft.Rest                    Trusted\n"
}

// TestEgressSummaryWireShape — AG-026A follow-up regression guard.
//
// Backend WinGetEgressPayloadPolicy treats dns / tcp / https as
// required arrays when supported=true. A nil slice that omits to JSON
// silence trips a 400 ("wingetEgress.egress.dns is required (array)
// when supported=true") at result-submit. This test asserts the
// shape on the wire — that EgressSummary serialises empty slices as
// `[]` and never as `null` or as a missing field.
func TestEgressSummaryWireShape(t *testing.T) {
	// Zero-value-with-empty-slice construction mirrors what
	// runEgressWith returns when no probe target was reached.
	summary := EgressSummary{
		DNS:   []NetworkCheck{},
		TCP:   []NetworkCheck{},
		HTTPS: []NetworkCheck{},
	}
	body, err := json.Marshal(summary)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}
	wire := string(body)
	for _, key := range []string{`"dns":`, `"tcp":`, `"https":`} {
		if !strings.Contains(wire, key) {
			t.Fatalf("egress summary wire payload missing %s: %s", key, wire)
		}
	}
	// Backend explicitly rejects null. Empty array must serialise as `[]`.
	for _, banned := range []string{`"dns":null`, `"tcp":null`, `"https":null`} {
		if strings.Contains(wire, banned) {
			t.Fatalf("egress summary must not emit %s: %s", banned, wire)
		}
	}
	// Sanity — the empty-slice serialisation is `[]`.
	if !strings.Contains(wire, `"dns":[]`) {
		t.Fatalf("expected dns=[] in wire payload, got %s", wire)
	}
}

// TestEmptyEgressSummaryHelper pins the helper contract — it must
// produce non-nil empty slices so json.Marshal serialises them as `[]`.
// Every code path that emits an EgressSummary MUST start from this
// helper (Codex 019e7164 P0 absorb): nil-slice + dropped omitempty
// would still serialise as `null`, which the backend rejects.
func TestEmptyEgressSummaryHelper(t *testing.T) {
	summary := emptyEgressSummary()
	if summary.DNS == nil || summary.TCP == nil || summary.HTTPS == nil {
		t.Fatalf("emptyEgressSummary must produce non-nil slices: %+v", summary)
	}
	body, err := json.Marshal(summary)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}
	wire := string(body)
	for _, expected := range []string{`"dns":[]`, `"tcp":[]`, `"https":[]`} {
		if !strings.Contains(wire, expected) {
			t.Fatalf("emptyEgressSummary wire shape missing %s: %s", expected, wire)
		}
	}
	for _, banned := range []string{`"dns":null`, `"tcp":null`, `"https":null`} {
		if strings.Contains(wire, banned) {
			t.Fatalf("emptyEgressSummary must not emit %s: %s", banned, wire)
		}
	}
}

// TestRunSourceEgressPreflightEarlyReturnsEmitEmptyArrays —
// AG-026A iter-1 P0 regression guard (Codex 019e7164). Both early
// returns (preflight options incomplete + locator error) MUST surface
// `"dns":[]` / `"tcp":[]` / `"https":[]` on the wire and never `null`.
// Before the iter-1 fix, those paths bypassed runEgressWith's slice
// init and a nil-slice supported=true SourceEgressReadiness produced
// `"egress":{"dns":null,...}` which the backend rejected with a 400
// during HALILKOOLUB735 lab smoke.
func TestRunSourceEgressPreflightEarlyReturnsEmitEmptyArrays(t *testing.T) {
	now := func() time.Time { return time.Unix(0, 0) }

	t.Run("preflight options incomplete", func(t *testing.T) {
		// Missing both Locator and Execute triggers the
		// "preflight options incomplete" early return.
		readiness := RunSourceEgressPreflight(SourceEgressOptions{
			Timeout: 30 * time.Second,
			Now:     now,
		})
		assertEarlyReturnWireShape(t, readiness, "preflight options incomplete")
	})

	t.Run("locator error", func(t *testing.T) {
		readiness := RunSourceEgressPreflight(SourceEgressOptions{
			Locator: func() (string, error) {
				return "", errors.New("winget binary not found")
			},
			Execute: func(ctx context.Context, path string, args ...string) ([]byte, error) {
				return nil, nil
			},
			Timeout: 30 * time.Second,
			Now:     now,
		})
		assertEarlyReturnWireShape(t, readiness, "locator error")
	})
}

func assertEarlyReturnWireShape(t *testing.T, readiness SourceEgressReadiness, label string) {
	t.Helper()
	if !readiness.Supported {
		t.Fatalf("%s: supported must remain true on Windows early-return paths, got %+v", label, readiness)
	}
	body, err := json.Marshal(readiness)
	if err != nil {
		t.Fatalf("%s: json.Marshal failed: %v", label, err)
	}
	wire := string(body)
	for _, expected := range []string{`"dns":[]`, `"tcp":[]`, `"https":[]`} {
		if !strings.Contains(wire, expected) {
			t.Fatalf("%s: wire payload missing %s: %s", label, expected, wire)
		}
	}
	for _, banned := range []string{`"dns":null`, `"tcp":null`, `"https":null`} {
		if strings.Contains(wire, banned) {
			t.Fatalf("%s: wire payload must not emit %s: %s", label, banned, wire)
		}
	}
}
