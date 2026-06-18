package ptyexec

import (
	"errors"
	"strings"
	"testing"

	"platform-agent/internal/remotebridge/operation"
)

func testAllowlist() map[string]AllowRule {
	return map[string]AllowRule{
		"hostname": {ExePath: `C:\Windows\System32\hostname.exe`},
		"ipconfig": {ExePath: `C:\Windows\System32\ipconfig.exe`, ArgPolicy: func(args []string) error {
			for _, a := range args {
				if a != "/all" {
					return errors.New("ipconfig: only /all permitted")
				}
			}
			return nil
		}},
		"relrule": {ExePath: `not\absolute.exe`}, // misconfigured rule (non-absolute) — must be rejected
	}
}

func TestBuildExecPlanHappy(t *testing.T) {
	allow := testAllowlist()

	p, err := BuildExecPlan(operation.ParseCommand("hostname"), allow)
	if err != nil {
		t.Fatalf("hostname: %v", err)
	}
	if p.ExePath != `C:\Windows\System32\hostname.exe` || p.CommandLine != `C:\Windows\System32\hostname.exe` || len(p.Args) != 0 {
		t.Fatalf("hostname plan wrong: exe=%q cmdline=%q args=%v", p.ExePath, p.CommandLine, p.Args)
	}

	// args bound by the broker (commandHash); the rule's arg policy also passes for /all
	p2, err := BuildExecPlan(operation.ParseCommand("ipconfig /all"), allow)
	if err != nil {
		t.Fatalf("ipconfig /all: %v", err)
	}
	if p2.CommandLine != `C:\Windows\System32\ipconfig.exe /all` || len(p2.Args) != 1 || p2.Args[0] != "/all" {
		t.Fatalf("ipconfig plan wrong: cmdline=%q args=%v", p2.CommandLine, p2.Args)
	}
}

func TestBuildExecPlanFailClosed(t *testing.T) {
	allow := testAllowlist()
	cases := []struct {
		name string
		line string
		want error
	}{
		{"empty/whitespace", "   ", ErrEmptyCommand},
		{"not allowlisted", "powershell -enc ZQBjAGgAbwA=", ErrNotAllowlisted},
		{"arg policy violation", "ipconfig /release", ErrArgPolicy},
		{"non-absolute rule exe", "relrule", ErrRuleExeNotAbs},
	}
	for _, c := range cases {
		_, err := BuildExecPlan(operation.ParseCommand(c.line), allow)
		if !errors.Is(err, c.want) {
			t.Errorf("%s: err=%v, want errors.Is %v", c.name, err, c.want)
		}
	}
}

func TestIsWindowsAbs(t *testing.T) {
	for _, p := range []string{`C:\x.exe`, `c:/x`, `D:\a\b`} {
		if !isWindowsAbs(p) {
			t.Errorf("%q should be absolute", p)
		}
	}
	for _, p := range []string{``, `x`, `\x`, `/x`, `C:`, `Cx\y`, `1:\x`, `relative\p.exe`} {
		if isWindowsAbs(p) {
			t.Errorf("%q should NOT be absolute", p)
		}
	}
}

// the default allowlist is read-only diagnostics only: every rule is an absolute System32 .exe, and no shell
// / write / admin tool is present — the pilot security posture.
func TestDefaultAllowlistPosture(t *testing.T) {
	allow := DefaultAllowlist()
	if len(allow) == 0 {
		t.Fatal("default allowlist is empty")
	}
	for id, rule := range allow {
		if !isWindowsAbs(rule.ExePath) {
			t.Errorf("%q: exe %q not absolute", id, rule.ExePath)
		}
		if !strings.HasSuffix(strings.ToLower(rule.ExePath), ".exe") {
			t.Errorf("%q: exe %q not an .exe", id, rule.ExePath)
		}
		if !strings.HasPrefix(rule.ExePath, `C:\Windows\System32\`) {
			t.Errorf("%q: exe %q not under System32", id, rule.ExePath)
		}
		if id != strings.ToLower(id) {
			t.Errorf("commandId %q must be lowercase (CanonicalCommand lowercases)", id)
		}
	}
	for _, forbidden := range []string{"cmd", "powershell", "pwsh", "reg", "sc", "net", "del", "rundll32", "wmic"} {
		if _, ok := allow[forbidden]; ok {
			t.Errorf("default allowlist must NOT contain shell/write/admin tool %q", forbidden)
		}
	}
	// Broker-excluded recon / credential-on-command-line commands must NOT be re-permitted by the agent's
	// last-line execution allowlist — it must stay a subset of the broker PILOT issuance set.
	for _, excluded := range []string{"systeminfo", "tasklist", "ipconfig", "gpresult", "getmac", "driverquery"} {
		if _, ok := allow[excluded]; ok {
			t.Errorf("default allowlist must NOT re-permit broker-excluded recon command %q", excluded)
		}
	}
	// Drift guard: the agent default MUST equal the broker PILOT_DEFAULT_ALLOWLIST runnable set (minus the
	// shell-only `ver`). Catches both re-adding a dangerous command and dropping an allowed one.
	want := map[string]bool{"hostname": true, "whoami": true, "netstat": true, "ping": true, "tracert": true}
	if len(allow) != len(want) {
		t.Errorf("default allowlist size %d != reconciled broker-runnable set size %d", len(allow), len(want))
	}
	for id := range want {
		if _, ok := allow[id]; !ok {
			t.Errorf("default allowlist missing reconciled command %q", id)
		}
	}
	for id := range allow {
		if !want[id] {
			t.Errorf("default allowlist has unexpected command %q (outside the reconciled broker-runnable set)", id)
		}
	}
	// a default-allowlisted command builds a plan
	if _, err := BuildExecPlan(operation.ParseCommand("hostname"), allow); err != nil {
		t.Errorf("default-allowlisted hostname should build: %v", err)
	}
}
