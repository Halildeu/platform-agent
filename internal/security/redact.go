package security

import "strings"

const RedactedValue = "<redacted>"

var sensitiveKeyFragments = []string{
	"authorization",
	"cookie",
	"credential",
	"key",
	"password",
	"secret",
	"signature",
	"token",
}

func IsSensitiveKey(key string) bool {
	normalized := strings.ToLower(strings.TrimSpace(key))
	for _, fragment := range sensitiveKeyFragments {
		if strings.Contains(normalized, fragment) {
			return true
		}
	}
	return false
}

func RedactMap(input map[string]interface{}) map[string]interface{} {
	if input == nil {
		return nil
	}
	output := make(map[string]interface{}, len(input))
	for key, value := range input {
		if IsSensitiveKey(key) {
			output[key] = RedactedValue
			continue
		}
		output[key] = redactValue(value)
	}
	return output
}

func redactValue(value interface{}) interface{} {
	switch typed := value.(type) {
	case map[string]interface{}:
		return RedactMap(typed)
	case []interface{}:
		items := make([]interface{}, len(typed))
		for index, item := range typed {
			items[index] = redactValue(item)
		}
		return items
	default:
		return value
	}
}
