package logging

import (
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"sync"

	"platform-agent/internal/security"
)

const logFileName = "endpoint-agent.log"

type Options struct {
	AgentName     string
	LogDir        string
	IncludeStdout bool
}

type Bundle struct {
	Logger  *log.Logger
	LogPath string
	close   func() error
}

func New(options Options) (*Bundle, error) {
	if options.AgentName == "" {
		options.AgentName = "endpoint-agent"
	}
	if options.LogDir == "" {
		options.LogDir = DefaultLogDir()
	}
	if err := os.MkdirAll(options.LogDir, 0o750); err != nil {
		return nil, fmt.Errorf("create log directory %q: %w", options.LogDir, err)
	}

	logPath := filepath.Join(options.LogDir, logFileName)
	file, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o640)
	if err != nil {
		return nil, fmt.Errorf("open log file %q: %w", logPath, err)
	}

	var writer io.Writer = file
	if options.IncludeStdout {
		writer = io.MultiWriter(file, os.Stdout)
	}
	writer = &redactingWriter{writer: writer}

	return &Bundle{
		Logger:  log.New(writer, options.AgentName+" ", log.LstdFlags|log.LUTC),
		LogPath: logPath,
		close:   file.Close,
	}, nil
}

func (b *Bundle) Close() error {
	if b == nil || b.close == nil {
		return nil
	}
	return b.close()
}

func DefaultLogDir() string {
	if runtime.GOOS == "windows" {
		programData := os.Getenv("ProgramData")
		if programData == "" {
			programData = `C:\ProgramData`
		}
		return filepath.Join(programData, "EndpointAgent", "logs")
	}
	if runtime.GOOS == "darwin" {
		if home, err := os.UserHomeDir(); err == nil && home != "" {
			return filepath.Join(home, "Library", "Logs", "EndpointAgent")
		}
	}
	if cacheDir, err := os.UserCacheDir(); err == nil && cacheDir != "" {
		return filepath.Join(cacheDir, "endpoint-agent", "logs")
	}
	return filepath.Join(os.TempDir(), "endpoint-agent", "logs")
}

type redactingWriter struct {
	mu     sync.Mutex
	writer io.Writer
}

func (w *redactingWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	redacted := security.RedactText(string(p))
	_, err := io.WriteString(w.writer, redacted)
	if err != nil {
		return 0, err
	}
	return len(p), nil
}
