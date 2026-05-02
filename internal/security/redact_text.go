package security

import (
	"regexp"
)

var (
	keyValueSecretPattern = regexp.MustCompile(`(?i)\b(authorization|cookie|credential|key|password|secret|signature|token|newPasswordSecret|agentSecret|enrollmentToken)(\s*[:=]\s*)(Bearer\s+[A-Za-z0-9._~+/=-]+|"[^"]*"|'[^']*'|[^,\s}\]]+)`)
	bearerSecretPattern   = regexp.MustCompile(`(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+`)
)

func RedactText(input string) string {
	output := keyValueSecretPattern.ReplaceAllString(input, `$1$2`+RedactedValue)
	output = bearerSecretPattern.ReplaceAllString(output, `Bearer `+RedactedValue)
	return output
}
