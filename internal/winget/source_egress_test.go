package winget

import (
	"context"
	"errors"
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

func TestRunSourceEgressRejectsArbitraryPackageID(t *testing.T) {
	r := RunSourceEgressPreflight(SourceEgressOptions{
		Locator:   func() (string, error) { return "winget.exe", nil },
		Execute:   func(ctx context.Context, path string, args ...string) ([]byte, error) { return nil, nil },
		PackageID: "evil.injection",
	})
	if r.ProbeError == "" || !strings.Contains(r.ProbeError, FixedPackageQueryID) {
		t.Fatalf("preflight must refuse non-pilot package id, got ProbeError=%q", r.ProbeError)
	}
	if r.Sources != nil {
		t.Fatalf("rejected preflight must skip source list, got %d entries", len(r.Sources))
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
	forbidden := []string{"install", "upgrade", "uninstall", "add", "remove", "update", "reset", "export", "import"}
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
	if len(r.Egress.DNS) != len(DefaultEgressTargets) {
		t.Fatalf("expected DNS probe per target (%d), got %d", len(DefaultEgressTargets), len(r.Egress.DNS))
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
