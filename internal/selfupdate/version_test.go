package selfupdate

import "testing"

func TestParseVersion_ValidAndInvalid(t *testing.T) {
	valid := []string{
		"0.0.0", "1.2.3", "v1.2.3", "V1.2.3", "10.20.30",
		"1.2.3-alpha", "1.2.3-alpha.1", "1.2.3-0.3.7", "1.2.3-x.7.z.92",
		"1.2.3+build.1", "1.2.3-beta+exp.sha.5114f85", "0.1.0-dev",
		"1.0.0-alpha.beta", "1.0.0-rc.1+build.123",
	}
	for _, s := range valid {
		if _, err := ParseVersion(s); err != nil {
			t.Errorf("ParseVersion(%q) unexpected error: %v", s, err)
		}
	}
	invalid := []string{
		"", "dev", "1", "1.2", "1.2.3.4", "01.2.3", "1.02.3", "1.2.03",
		"1.2.3-", "1.2.3+", "1.2.3-01", "1.2.3-alpha..1", "1.2.3-al pha",
		"x.y.z", "1.2.-3", "-1.2.3", "1.2.3-béta", "ag040fix-80ff28e",
	}
	for _, s := range invalid {
		if _, err := ParseVersion(s); err == nil {
			t.Errorf("ParseVersion(%q) expected error, got nil", s)
		}
	}
}

// TestCompare_SpecCanonicalChain pins the SemVer 2.0.0 §11 example precedence
// chain. A regression here could silently let a downgrade through the
// security gate, so it is asserted strictly increasing.
func TestCompare_SpecCanonicalChain(t *testing.T) {
	chain := []string{
		"1.0.0-alpha",
		"1.0.0-alpha.1",
		"1.0.0-alpha.beta",
		"1.0.0-beta",
		"1.0.0-beta.2",
		"1.0.0-beta.11",
		"1.0.0-rc.1",
		"1.0.0",
	}
	vs := make([]Version, len(chain))
	for i, s := range chain {
		v, err := ParseVersion(s)
		if err != nil {
			t.Fatalf("ParseVersion(%q): %v", s, err)
		}
		vs[i] = v
	}
	for i := 0; i+1 < len(vs); i++ {
		if Compare(vs[i], vs[i+1]) != -1 {
			t.Errorf("expected %q < %q", chain[i], chain[i+1])
		}
		if Compare(vs[i+1], vs[i]) != 1 {
			t.Errorf("expected %q > %q", chain[i+1], chain[i])
		}
		if Compare(vs[i], vs[i]) != 0 {
			t.Errorf("expected %q == %q", chain[i], chain[i])
		}
	}
}

func TestCompare_BuildMetadataIgnored(t *testing.T) {
	a, _ := ParseVersion("1.2.3+build.1")
	b, _ := ParseVersion("1.2.3+build.999")
	if Compare(a, b) != 0 {
		t.Errorf("build metadata must not affect precedence")
	}
	c, _ := ParseVersion("v1.2.3")
	if Compare(a, c) != 0 {
		t.Errorf("v-prefix + build metadata must compare equal to plain")
	}
}

func TestEvaluateVersionPolicy(t *testing.T) {
	cases := []struct {
		name                     string
		current, target, maxSeen string
		wantAllowed, wantNoop    bool
		wantCode                 ErrorCode
	}{
		{"clean upgrade", "1.2.3", "1.2.4", "", true, false, ""},
		{"v-prefix upgrade", "v1.2.3", "1.3.0", "", true, false, ""},
		{"major upgrade", "1.9.9", "2.0.0", "", true, false, ""},
		{"prerelease to release upgrade", "1.0.0-rc.1", "1.0.0", "", true, false, ""},
		{"upgrade from dev prerelease", "0.1.0-dev", "0.1.0", "", true, false, ""},
		{"equal is noop", "1.2.3", "1.2.3", "", false, true, ""},
		{"equal ignoring build is noop", "1.2.3", "1.2.3+b2", "", false, true, ""},
		{"downgrade refused", "1.2.3", "1.2.2", "", false, false, ErrVersionDowngrade},
		{"prerelease downgrade refused", "1.0.0", "1.0.0-rc.1", "", false, false, ErrVersionDowngrade},
		{"replay refused (<= maxSeen)", "1.0.0", "1.5.0", "1.5.0", false, false, ErrVersionReplay},
		{"replay refused (below maxSeen)", "1.0.0", "1.4.0", "1.5.0", false, false, ErrVersionReplay},
		{"above maxSeen allowed", "1.0.0", "1.6.0", "1.5.0", true, false, ""},
		{"unparseable current", "dev", "1.2.3", "", false, false, ErrVersionUnparseable},
		{"unparseable target", "1.2.3", "garbage", "", false, false, ErrVersionUnparseable},
		{"unparseable maxSeen", "1.2.3", "1.2.4", "nope", false, false, ErrVersionUnparseable},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := EvaluateVersionPolicy(c.current, c.target, c.maxSeen)
			if d.Allowed != c.wantAllowed || d.Noop != c.wantNoop || d.Code != c.wantCode {
				t.Errorf("got {Allowed:%v Noop:%v Code:%q} want {Allowed:%v Noop:%v Code:%q}",
					d.Allowed, d.Noop, d.Code, c.wantAllowed, c.wantNoop, c.wantCode)
			}
		})
	}
}

// TestCompare_NumericPrereleaseArbitraryPrecision pins Codex 019e9912 #1: a
// numeric prerelease identifier that overflows uint64 must STILL sort as a
// number (numeric < alphanumeric; longer-digits = larger), not fall through to
// an alphanumeric string compare.
func TestCompare_NumericPrereleaseArbitraryPrecision(t *testing.T) {
	const huge = "18446744073709551616"   // math.MaxUint64 + 1
	const bigger = "18446744073709551617" // + 2
	mustLess := func(a, b string) {
		t.Helper()
		va, err := ParseVersion(a)
		if err != nil {
			t.Fatalf("parse %q: %v", a, err)
		}
		vb, err := ParseVersion(b)
		if err != nil {
			t.Fatalf("parse %q: %v", b, err)
		}
		if Compare(va, vb) != -1 || Compare(vb, va) != 1 {
			t.Errorf("expected %q < %q", a, b)
		}
	}
	mustLess("1.0.0-"+huge, "1.0.0-0alpha")  // huge numeric < alphanumeric
	mustLess("1.0.0-2", "1.0.0-"+huge)       // small numeric < huge numeric
	mustLess("1.0.0-"+huge, "1.0.0-"+bigger) // huge < huge+1 (equal length, lexical)
}

// TestEvaluateVersionPolicy_OverflowNoBypass: the uint64-overflow comparator
// bug must not let a downgrade or replay through the version gate.
func TestEvaluateVersionPolicy_OverflowNoBypass(t *testing.T) {
	const huge = "18446744073709551616"
	// target numeric-prerelease < current alphanumeric-prerelease ⇒ downgrade
	if d := EvaluateVersionPolicy("1.0.0-0alpha", "1.0.0-"+huge, ""); d.Code != ErrVersionDowngrade {
		t.Errorf("overflow downgrade not refused: %+v", d)
	}
	// target numeric-prerelease ≤ alphanumeric maxSeen ⇒ replay
	if d := EvaluateVersionPolicy("1.0.0-0", "1.0.0-"+huge, "1.0.0-0alpha"); d.Code != ErrVersionReplay {
		t.Errorf("overflow replay not refused: %+v", d)
	}
}
