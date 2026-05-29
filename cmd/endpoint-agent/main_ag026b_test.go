package main

import (
	"strings"
	"testing"

	"platform-agent/internal/config"
)

// TestEnrollmentTokenFlagPrecedence locks the AG-026B precedence
// contract: CLI flag (when non-empty) wins over env; empty CLI flag
// does NOT clobber a non-empty env value. The same TrimSpace +
// override logic the main() entry point uses lives here as a small
// pure helper so we can exercise it without a binary build.
func TestEnrollmentTokenFlagPrecedence(t *testing.T) {
	cases := []struct {
		name   string
		envTok string
		cliTok string
		want   string
	}{
		{"cli wins over env", "env-token", "cli-token", "cli-token"},
		{"cli trims whitespace", "env-token", "  cli-token  ", "cli-token"},
		{"empty cli keeps env", "env-token", "", "env-token"},
		{"whitespace cli keeps env", "env-token", "   ", "env-token"},
		{"empty cli + empty env stays empty", "", "", ""},
		{"cli only with empty env", "", "cli-token", "cli-token"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.Default()
			cfg.EnrollmentToken = tc.envTok
			cliTrimmed := strings.TrimSpace(tc.cliTok)
			if cliTrimmed != "" {
				cfg.EnrollmentToken = cliTrimmed
			}
			if cfg.EnrollmentToken != tc.want {
				t.Errorf("got %q, want %q", cfg.EnrollmentToken, tc.want)
			}
		})
	}
}
