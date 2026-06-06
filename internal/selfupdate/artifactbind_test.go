package selfupdate

import "testing"

func TestEvaluateArtifactVersionBinding(t *testing.T) {
	cases := []struct {
		name   string
		pe     string
		target string
		want   ErrorCode // "" => bound OK
	}{
		{"exact semver match", "2.0.0", "2.0.0", ""},
		{"windows 4-field zero revision", "2.0.0.0", "2.0.0", ""},
		{"windows 3-field", "2.0.0", "2.0.0", ""},
		{"zero-extend 2-field", "1.2", "1.2.0", ""},
		{"zero-extend 1-field", "3", "3.0.0", ""},
		{"zero-padded fields", "01.02.03", "1.2.3", ""},
		{"leading v on stamp", "v2.0.0", "2.0.0", ""},
		{"prerelease match", "2.0.0-rc.1", "2.0.0-rc.1", ""},
		{"build metadata ignored", "2.0.0+build5", "2.0.0", ""},

		{"nonzero 4th field refused", "2.0.0.7", "2.0.0", ErrCatalogMismatch},
		{"different patch", "1.5.0", "2.0.0", ErrCatalogMismatch},
		{"different minor", "2.1.0", "2.0.0", ErrCatalogMismatch},
		{"empty stamp", "", "2.0.0", ErrCatalogMismatch},
		{"garbage stamp", "not-a-version", "2.0.0", ErrCatalogMismatch},
		{"too many fields", "1.2.3.4.5", "1.2.3", ErrCatalogMismatch},
		{"prerelease mismatch", "2.0.0-rc.1", "2.0.0-rc.2", ErrCatalogMismatch},
		{"release vs prerelease", "2.0.0", "2.0.0-rc.1", ErrCatalogMismatch},
		{"unparseable target", "2.0.0", "two-point-oh", ErrCatalogMismatch},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			code, reason := EvaluateArtifactVersionBinding(c.pe, c.target)
			if code != c.want {
				t.Fatalf("pe=%q target=%q => code %q (%q), want %q", c.pe, c.target, code, reason, c.want)
			}
		})
	}
}

// TestArtifactBinding_DefeatsSignedDowngrade is the must-fix #2 narrative: an
// allowlisted-signed OLD binary (stamp 1.0.0) cannot be passed off under a
// forged higher targetVersion (9.9.9) — the bind catches the divergence.
func TestArtifactBinding_DefeatsSignedDowngrade(t *testing.T) {
	if code, _ := EvaluateArtifactVersionBinding("1.0.0", "9.9.9"); code != ErrCatalogMismatch {
		t.Fatalf("a 1.0.0 binary claimed as 9.9.9 must be refused, got %q", code)
	}
}
