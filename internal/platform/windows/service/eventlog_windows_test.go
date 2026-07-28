//go:build windows

package service

import (
	"fmt"
	"os"
	"testing"
	"time"

	"golang.org/x/sys/windows/registry"
)

func TestEnsureEventLogSourceUnderIsIdempotent(t *testing.T) {
	parentPath := fmt.Sprintf(
		`Software\PlatformAgentEventLogTest-%d-%d`,
		os.Getpid(),
		time.Now().UnixNano(),
	)
	parentKey, _, err := registry.CreateKey(
		registry.CURRENT_USER,
		parentPath,
		registry.CREATE_SUB_KEY,
	)
	if err != nil {
		t.Fatalf("create test registry parent: %v", err)
	}
	defer func() {
		parentKey.Close()
		_ = registry.DeleteKey(registry.CURRENT_USER, parentPath+`\EndpointAgent`)
		_ = registry.DeleteKey(registry.CURRENT_USER, parentPath)
	}()

	for attempt := 1; attempt <= 2; attempt++ {
		if err := ensureEventLogSourceUnder(parentKey, "EndpointAgent"); err != nil {
			t.Fatalf("ensure event source attempt %d: %v", attempt, err)
		}
	}

	sourceKey, err := registry.OpenKey(
		parentKey,
		"EndpointAgent",
		registry.QUERY_VALUE,
	)
	if err != nil {
		t.Fatalf("open ensured event source: %v", err)
	}
	defer sourceKey.Close()

	customSource, _, err := sourceKey.GetIntegerValue("CustomSource")
	if err != nil {
		t.Fatalf("read CustomSource: %v", err)
	}
	if customSource != 1 {
		t.Fatalf("CustomSource = %d, want 1", customSource)
	}

	messageFile, _, err := sourceKey.GetStringValue("EventMessageFile")
	if err != nil {
		t.Fatalf("read EventMessageFile: %v", err)
	}
	if messageFile != eventCreateMessageFile {
		t.Fatalf("EventMessageFile = %q, want %q", messageFile, eventCreateMessageFile)
	}

	typesSupported, _, err := sourceKey.GetIntegerValue("TypesSupported")
	if err != nil {
		t.Fatalf("read TypesSupported: %v", err)
	}
	if typesSupported != uint64(eventSourceSupportedTypes) {
		t.Fatalf(
			"TypesSupported = %d, want %d",
			typesSupported,
			eventSourceSupportedTypes,
		)
	}
}
