package security

import (
	"strings"
	"testing"
)

func TestRedactTextRedactsSensitiveAssignments(t *testing.T) {
	input := `agentSecret=abc123 token: secret-token password="TempPassword" safe=value`

	redacted := RedactText(input)

	for _, leaked := range []string{"abc123", "secret-token", "TempPassword"} {
		if strings.Contains(redacted, leaked) {
			t.Fatalf("redacted text leaked %q: %s", leaked, redacted)
		}
	}
	if !strings.Contains(redacted, "safe=value") {
		t.Fatalf("safe value was changed: %s", redacted)
	}
}

func TestRedactTextRedactsBearerToken(t *testing.T) {
	input := "Authorization=Bearer eyJhbGciOiJIUzI1NiJ9.payload.signature"

	redacted := RedactText(input)

	if strings.Contains(redacted, "eyJhbGciOiJIUzI1NiJ9") {
		t.Fatalf("bearer token leaked: %s", redacted)
	}
	if !strings.Contains(redacted, RedactedValue) {
		t.Fatalf("bearer token was not redacted: %s", redacted)
	}
}
