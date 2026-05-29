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
			input:    "Downloading https://operator:MASKME@vendor.example.com/installer.msi",
			want:     "Downloading https://[REDACTED]@vendor.example.com/installer.msi",
			mustHide: []string{"operator", "MASKME"},
		},
		{
			name:     "bare userinfo (no password)",
			input:    "GET https://MASKME@cdn.example.com/v1/pkg",
			want:     "GET https://[REDACTED]@cdn.example.com/v1/pkg",
			mustHide: []string{"MASKME"},
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
		{
			// Codex 019e73de iter-1 must_fix #1: `?` delimiter must
			// end authority parsing so query values containing `@`
			// (e.g. `?email=user@example.com`) do not get scrubbed
			// as if they were userinfo.
			name:  "query value contains @ — pattern must not match",
			input: "GET https://cdn.example.com?email=user@example.com",
			want:  "GET https://cdn.example.com?email=[REDACTED]",
		},
		{
			// Same guard for `#` fragment delimiter.
			name:  "fragment contains @ — pattern must not match",
			input: "see https://docs.example.com/api#section@detail",
			want:  "see https://docs.example.com/api#section@detail",
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
			input:    `msiexec /i app.msi LICENSEKEY=MASKME /qn`,
			want:     `msiexec /i app.msi LICENSEKEY=[REDACTED] /qn`,
			mustHide: []string{"MASKME"},
		},
		{
			name:     "SERIAL assignment with quoted value",
			input:    `setup.exe SERIAL="MASKME" /S`,
			want:     `setup.exe SERIAL=[REDACTED] /S`,
			mustHide: []string{"MASKME"},
		},
		{
			name:     "lowercase apikey assignment",
			input:    `installer.exe apikey=MASKME /quiet`,
			want:     `installer.exe apikey=[REDACTED] /quiet`,
			mustHide: []string{"MASKME"},
		},
		{
			name:     "ACTIVATION embedded in vendor template",
			input:    `Starting install with ACTIVATION=MASKME...`,
			want:     `Starting install with ACTIVATION=[REDACTED]`,
			mustHide: []string{"MASKME"},
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
		// Codex 019e73de iter-1 must_fix #2: snake_case + kebab-case
		// + camelCase OAuth/vendor property shapes.
		{
			name:     "CLIENT_SECRET snake_case",
			input:    `setup.exe CLIENT_SECRET=MASKME /qn`,
			want:     `setup.exe CLIENT_SECRET=[REDACTED] /qn`,
			mustHide: []string{"MASKME"},
		},
		{
			name:     "client-secret kebab-case",
			input:    `provider config: client-secret=MASKME`,
			want:     `provider config: client-secret=[REDACTED]`,
			mustHide: []string{"MASKME"},
		},
		{
			name:     "clientSecret camelCase (bare allowlist)",
			input:    `init: clientSecret="MASKME"`,
			want:     `init: clientSecret=[REDACTED]`,
			mustHide: []string{"MASKME"},
		},
		{
			name:     "ACCESS_TOKEN snake_case",
			input:    `vendor.cli --ACCESS_TOKEN=MASKME`,
			want:     `vendor.cli --ACCESS_TOKEN=[REDACTED]`,
			mustHide: []string{"MASKME"},
		},
		{
			name:     "REFRESH_TOKEN snake_case",
			input:    `cfg: REFRESH_TOKEN=MASKME`,
			want:     `cfg: REFRESH_TOKEN=[REDACTED]`,
			mustHide: []string{"MASKME"},
		},
		{
			name:     "OAUTH_TOKEN snake_case",
			input:    `OAUTH_TOKEN=MASKME`,
			want:     `OAUTH_TOKEN=[REDACTED]`,
			mustHide: []string{"MASKME"},
		},
		{
			name:     "ID_TOKEN snake_case",
			input:    `Issuing ID_TOKEN=MASKME`,
			want:     `Issuing ID_TOKEN=[REDACTED]`,
			mustHide: []string{"MASKME"},
		},
		{
			name:     "API_KEY snake_case",
			input:    `cfg API_KEY=MASKME`,
			want:     `cfg API_KEY=[REDACTED]`,
			mustHide: []string{"MASKME"},
		},
		{
			name:     "SECRET_KEY snake_case",
			input:    `setup SECRET_KEY=MASKME`,
			want:     `setup SECRET_KEY=[REDACTED]`,
			mustHide: []string{"MASKME"},
		},
		{
			name:     "AUTH_TOKEN snake_case",
			input:    `req AUTH_TOKEN=MASKME`,
			want:     `req AUTH_TOKEN=[REDACTED]`,
			mustHide: []string{"MASKME"},
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
			input:    `GET /api?token=MASKME HTTP/1.1`,
			want:     `GET /api?token=[REDACTED] HTTP/1.1`,
			mustHide: []string{"MASKME"},
		},
		{
			name:     "access_token=… second param",
			input:    `https://api.example.com/v1?org=acme&access_token=MASKME`,
			want:     `https://api.example.com/v1?org=acme&access_token=[REDACTED]`,
			mustHide: []string{"MASKME"},
		},
		{
			name:     "api-key with dash variant",
			input:    `https://cdn.example.com/d?api-key=MASKME`,
			want:     `https://cdn.example.com/d?api-key=[REDACTED]`,
			mustHide: []string{"MASKME"},
		},
		{
			name:     "refresh_token at end of string",
			input:    `redirect=oauth/cb?refresh_token=MASKME`,
			want:     `redirect=oauth/cb?refresh_token=[REDACTED]`,
			mustHide: []string{"MASKME"},
		},
		{
			name:  "?version=1.2.3 is NOT a token — must NOT match",
			input: `GET /api?version=1.2.3`,
			want:  `GET /api?version=1.2.3`,
		},
		// Codex 019e73de iter-1 must_fix #3: OAuth/vendor query param
		// shapes (snake_case + kebab-case + bare).
		{
			name:     "client_secret query param",
			input:    `https://idp.example.com/oauth/token?client_secret=MASKME`,
			want:     `https://idp.example.com/oauth/token?client_secret=[REDACTED]`,
			mustHide: []string{"MASKME"},
		},
		{
			name:     "client-secret kebab-case query param",
			input:    `cb=oauth?client-secret=MASKME`,
			want:     `cb=oauth?client-secret=[REDACTED]`,
			mustHide: []string{"MASKME"},
		},
		{
			name:     "id_token snake_case query param",
			input:    `redirect?id_token=MASKME`,
			want:     `redirect?id_token=[REDACTED]`,
			mustHide: []string{"MASKME"},
		},
		{
			name:     "oauth_token snake_case query param",
			input:    `cb?oauth_token=MASKME`,
			want:     `cb?oauth_token=[REDACTED]`,
			mustHide: []string{"MASKME"},
		},
		{
			name:     "auth_token snake_case query param",
			input:    `link/cb?auth_token=MASKME`,
			want:     `link/cb?auth_token=[REDACTED]`,
			mustHide: []string{"MASKME"},
		},
		{
			name:     "secret_key snake_case query param",
			input:    `vendor?secret_key=MASKME`,
			want:     `vendor?secret_key=[REDACTED]`,
			mustHide: []string{"MASKME"},
		},
		{
			name:     "follow-on &client_secret position",
			input:    `https://idp.example.com/oauth?org=acme&client_secret=MASKME`,
			want:     `https://idp.example.com/oauth?org=acme&client_secret=[REDACTED]`,
			mustHide: []string{"MASKME"},
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
	// AG-027L composes installer patterns first, then the
	// RedactSoftwareString baseline. The combined call must scrub
	// both the AG-025/AG-026 baseline shapes AND the AG-027L-specific
	// shapes. (Codex 019e73de iter-1 should_fix: comment order
	// corrected to match implementation.)

	input := `User=alice@example.com installed pkg from ` +
		`https://operator:MASKME@cdn.example.com/?token=secret123 ` +
		`with LICENSEKEY=MASKME into C:\Users\alice\AppData\Local\Temp`

	out := RedactInstallerString(input)

	// AG-025/AG-026 baseline patterns:
	if strings.Contains(out, "alice@example.com") {
		t.Errorf("email/UPN should be redacted: %q", out)
	}
	if strings.Contains(out, `C:\Users\alice`) {
		t.Errorf("user profile path should be redacted: %q", out)
	}

	// AG-027L additions:
	if strings.Contains(out, "operator:MASKME") {
		t.Errorf("URL userinfo should be redacted: %q", out)
	}
	if strings.Contains(out, "secret123") {
		t.Errorf("query string token should be redacted: %q", out)
	}
	if strings.Contains(out, "MASKME") {
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
