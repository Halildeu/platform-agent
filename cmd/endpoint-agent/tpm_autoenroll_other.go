//go:build !windows

package main

import (
	"context"
	"fmt"
	"os"

	"platform-agent/internal/config"
)

// runTpmAutoEnroll is unavailable off Windows — the hardware path needs Windows
// TBS. The same signature on every platform lets main() reference it unconditionally.
func runTpmAutoEnroll(_ context.Context, _ config.Config, _ string) int {
	fmt.Fprintln(os.Stderr, "tpm auto-enroll requires Windows (TBS); not available on this platform")
	return 1
}
