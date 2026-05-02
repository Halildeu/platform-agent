package logging

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoggerWritesRedactedFile(t *testing.T) {
	logDir := t.TempDir()
	bundle, err := New(Options{AgentName: "test-agent", LogDir: logDir})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	bundle.Logger.Printf("agentSecret=abc123 token=tokVALUE123 password=\"TempPassword\" safe=value")
	if err := bundle.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(logDir, logFileName))
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	content := string(data)
	for _, leaked := range []string{"abc123", "tokVALUE123", "TempPassword"} {
		if strings.Contains(content, leaked) {
			t.Fatalf("log leaked %q: %s", leaked, content)
		}
	}
	if !strings.Contains(content, "safe=value") {
		t.Fatalf("safe field missing: %s", content)
	}
}
