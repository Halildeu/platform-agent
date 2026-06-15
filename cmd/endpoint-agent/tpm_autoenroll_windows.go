//go:build windows

package main

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"platform-agent/internal/config"
	"platform-agent/internal/tpmenroll"
)

// runTpmAutoEnroll wires the real Windows deps: a TBS-backed TPMDevice, a
// bootstrap HTTPS client (server-TLS + token-in-body — the device has no client
// cert YET, it is enrolling to get one), and a file-based artifact persist.
//
// NOTE: steady-state consumption (importing the issued cert into the Windows
// certstore + associating the TPM-resident device key via CNG) is a follow-up
// (3c-3, AD CS-coupled). This slice persists the issued cert as the enrollment
// artifact; the device key is re-derivable (deterministic TPM primary).
func runTpmAutoEnroll(ctx context.Context, cfg config.Config, apiURL string) int {
	return runTpmAutoEnrollWith(ctx, cfg, apiURL, tpmEnrollDeps{
		newDevice:  tpmenroll.NewWindowsTPMDevice,
		httpClient: &http.Client{Timeout: 30 * time.Second},
		persist: func(certPEM string) error {
			base := os.Getenv("ProgramData")
			if base == "" {
				base = "."
			}
			out := filepath.Join(base, "EndpointAgent", "tpm-client-cert.pem")
			if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
				return err
			}
			return os.WriteFile(out, []byte(certPEM), 0o600)
		},
	})
}
