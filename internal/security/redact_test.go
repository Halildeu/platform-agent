package security

import "testing"

func TestRedactMapRedactsSensitiveKeys(t *testing.T) {
	input := map[string]interface{}{
		"username":          "test.user",
		"newPasswordSecret": "TempPassword",
		"nested": map[string]interface{}{
			"agentToken": "token-value",
			"safe":       "visible",
		},
	}

	redacted := RedactMap(input)

	if redacted["username"] != "test.user" {
		t.Fatalf("safe field was changed: %#v", redacted["username"])
	}
	if redacted["newPasswordSecret"] != RedactedValue {
		t.Fatalf("password secret was not redacted: %#v", redacted["newPasswordSecret"])
	}
	nested, ok := redacted["nested"].(map[string]interface{})
	if !ok {
		t.Fatalf("nested map missing: %#v", redacted["nested"])
	}
	if nested["agentToken"] != RedactedValue {
		t.Fatalf("nested token was not redacted: %#v", nested["agentToken"])
	}
	if nested["safe"] != "visible" {
		t.Fatalf("nested safe field changed: %#v", nested["safe"])
	}
}
