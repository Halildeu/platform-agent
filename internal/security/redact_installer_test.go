package security

import (
	"strings"
	"testing"
)

// AG-027L unit tests for RedactInstallerString. Mirror the
// table-driven style of redact_pii_test.go so each pattern carries
// one positive case (does redact) and at least one negative case
// (does NOT redact look-alikes).

func TestRedactInstallerString_URLUserInfo(t *testing.T) {
	cases := []struct {
		name     string
		input    string
		want     string
		mustHide []string
	}{
		{
			name:     "userinfo with password",
			input:    "Downloading https://operator:s3cret@vendor.example.com/installer.msi",
			want:     "Downloading https://[REDACTED]@vendor.example.com/installer.msi",
			mustHide: []string{"operator", "s3cret"},
		},
		{
			name:     "bare userinfo (no password)",
			input:    "GET https://apitoken@cdn.example.com/v1/pkg",
			want:     "GET https://[REDACTED]@cdn.example.com/v1/pkg",
			mustHide: []string{"apitoken"},
		},
		{
			name:  "no userinfo — URL untouched",
			input: "GET https://cdn.example.com/installer.msi",
			want:  "GET https://cdn.example.com/installer.msi",
		},
		{
			name:  "userinfo would span path — pattern must not match",
			input: "see https://cdn.example.com/path/with@symbol",
			want:  "see https://cdn.example.com/path/with@symbol",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := RedactInstallerString(tc.input)
			if got != tc.want {
				t.Fatalf("got %q\nwant %q", got, tc.want)
			}
			for _, h := range tc.mustHide {
				if strings.Contains(got, h) {
					t.Fatalf("expected redaction to hide %q, got %q", h, got)
				}
			}
		})
	}
}

func TestRedactInstallerString_MSIProperty(t *testing.T) {
	cases := []struct {
		name     string
		input    string
		want     string
		mustHide []string
	}{
		{
			name:     "LICENSEKEY assignment",
			input:    `msiexec /i app.msi LICENSEKEY=ABC-DEF-123-XYZ /qn`,
			want:     `msiexec /i app.msi LICENSEKEY=[REDACTED] /qn`,
			mustHide: []string{"ABC-DEF-123-XYZ"},
		},
		{
			name:     "SERIAL assignment with quoted value",
			input:    `setup.exe SERIAL="SN-12345-XYZ" /S`,
			want:     `setup.exe SERIAL=[REDACTED] /S`,
			mustHide: []string{"SN-12345-XYZ"},
		},
		{
			name:     "lowercase apikey assignment",
			input:    `installer.exe apikey=sk_live_abc123 /quiet`,
			want:     `installer.exe apikey=[REDACTED] /quiet`,
			mustHide: []string{"sk_live_abc123"},
		},
		{
			name:     "ACTIVATION embedded in vendor template",
			input:    `Starting install with ACTIVATION=01234567890abc...`,
			want:     `Starting install with ACTIVATION=[REDACTED]`,
			mustHide: []string{"01234567890abc"},
		},
		{
			name:  "LICENSES_VALIDATED=1 is NOT a credential — must NOT match",
			input: `Info: LICENSES_VALIDATED=1`,
			want:  `Info: LICENSES_VALIDATED=1`,
		},
		{
			name:  "regular property like INSTALLDIR is untouched",
			input: `setup.exe INSTALLDIR="C:\Program Files\App" /S`,
			want:  `setup.exe INSTALLDIR="C:\Program Files\App" /S`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := RedactInstallerString(tc.input)
			if got != tc.want {
				t.Fatalf("got %q\nwant %q", got, tc.want)
			}
			for _, h := range tc.mustHide {
				if strings.Contains(got, h) {
					t.Fatalf("expected redaction to hide %q, got %q", h, got)
				}
			}
		})
	}
}

func TestRedactInstallerString_QueryStringToken(t *testing.T) {
	cases := []struct {
		name     string
		input    string
		want     string
		mustHide []string
	}{
		{
			name:     "token=… as first param",
			input:    `GET /api?token=secret-value HTTP/1.1`,
			want:     `GET /api?token=[REDACTED] HTTP/1.1`,
			mustHide: []string{"secret-value"},
		},
		{
			name:     "access_token=… second param",
			input:    `https://api.example.com/v1?org=acme&access_token=ABCXYZ123`,
			want:     `https://api.example.com/v1?org=acme&access_token=[REDACTED]`,
			mustHide: []string{"ABCXYZ123"},
		},
		{
			name:     "api-key with dash variant",
			input:    `https://cdn.example.com/d?api-key=Krn7ax`,
			want:     `https://cdn.example.com/d?api-key=[REDACTED]`,
			mustHide: []string{"Krn7ax"},
		},
		{
			name:     "refresh_token at end of string",
			input:    `redirect=oauth/cb?refresh_token=rfk-token-payload`,
			want:     `redirect=oauth/cb?refresh_token=[REDACTED]`,
			mustHide: []string{"rfk-token-payload"},
		},
		{
			name:  "?version=1.2.3 is NOT a token — must NOT match",
			input: `GET /api?version=1.2.3`,
			want:  `GET /api?version=1.2.3`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := RedactInstallerString(tc.input)
			if got != tc.want {
				t.Fatalf("got %q\nwant %q", got, tc.want)
			}
			for _, h := range tc.mustHide {
				if strings.Contains(got, h) {
					t.Fatalf("expected redaction to hide %q, got %q", h, got)
				}
			}
		})
	}
}

func TestRedactInstallerString_LayersWithSoftwareString(t *testing.T) {
	// AG-027L composes RedactSoftwareString first, then installer
	// patterns. The combined call must scrub both the AG-025/AG-026
	// baseline shapes AND the AG-027L-specific shapes.

	input := `User=alice@example.com installed pkg from ` +
		`https://operator:apitoken@cdn.example.com/?token=secret123 ` +
		`with LICENSEKEY=KEY-AAA-BBB into C:\Users\alice\AppData\Local\Temp`

	out := RedactInstallerString(input)

	// AG-025/AG-026 baseline patterns:
	if strings.Contains(out, "alice@example.com") {
		t.Errorf("email/UPN should be redacted: %q", out)
	}
	if strings.Contains(out, `C:\Users\alice`) {
		t.Errorf("user profile path should be redacted: %q", out)
	}

	// AG-027L additions:
	if strings.Contains(out, "operator:apitoken") {
		t.Errorf("URL userinfo should be redacted: %q", out)
	}
	if strings.Contains(out, "secret123") {
		t.Errorf("query string token should be redacted: %q", out)
	}
	if strings.Contains(out, "KEY-AAA-BBB") {
		t.Errorf("LICENSEKEY value should be redacted: %q", out)
	}

	// Survivor structural anchors (non-sensitive context kept for
	// debuggability):
	for _, keep := range []string{
		"User=",          // assignment key kept
		"installed pkg",  // narrative kept
		"https://",       // URL scheme kept
		"cdn.example.com",// hostname kept (non-credential)
		"LICENSEKEY=",    // assignment key kept
		"AppData\\Local\\Temp", // path tail kept (non-PII)
	} {
		if !strings.Contains(out, keep) {
			t.Errorf("non-sensitive marker %q should survive redaction, got %q", keep, out)
		}
	}
}

func TestRedactInstallerString_Empty(t *testing.T) {
	if got := RedactInstallerString(""); got != "" {
		t.Fatalf("empty input must return empty, got %q", got)
	}
}

func TestRedactInstallerString_NoMatch(t *testing.T) {
	// A typical clean install line should be untouched.
	input := `Successfully installed 7zip.7zip 24.07 in 18.2s`
	if got := RedactInstallerString(input); got != input {
		t.Fatalf("clean input must pass through unchanged\ninput: %q\ngot:   %q", input, got)
	}
}
