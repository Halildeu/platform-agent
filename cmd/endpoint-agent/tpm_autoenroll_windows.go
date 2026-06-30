//go:build windows

package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"platform-agent/internal/autoenroll"
	"platform-agent/internal/config"
	"platform-agent/internal/mtls"
	"platform-agent/internal/platform/windows/certstore"
	"platform-agent/internal/tpmenroll"
)

// runTpmAutoEnroll wires the real Windows deps for the Faz 22.3B / 22.6 #548 TPM
// device-key enrollment.
//
// Transport is mTLS using the device's EXISTING machine-cert from LocalMachine\My
// (the same cert the regular auto-enroll selects). The live enrollment edge
// (mtls.*.acik.com) requires a client cert at the TLS layer, so the previous
// plain "server-TLS + token-in-body, no client cert" bootstrap fails the
// handshake with `remote error: tls: certificate required` (observed live on the
// #548 target, both interactive and SYSTEM context). The strong TPM path runs
// ON TOP of an already machine-cert-enrolled device (runbook §2 order), so the
// bootstrap cert is always present; a missing or broad-filter cert is
// **fail-closed** — there is deliberately NO plain fallback (Codex 019f024b: a
// silent downgrade would mask an edge/cert misconfiguration and could pick a
// wrong corp/VPN client-auth cert, polluting the #548 evidence). A genuine
// first-enroll-with-no-cert bootstrap is a separate, explicit, non-default mode.
//
// The machine-cert is loaded BEFORE the TPM device is opened (the TPM device
// opens EK+AK+device-key transient primaries; loading the cert first avoids
// overlapping those with the cert-selection path — TPM handle budget). The
// CNG signer handle and idle connections are released on return. The TPM-issued
// cert produced by /attest is persisted separately as the enrollment artifact;
// importing it into the certstore + CNG association for the bridge transport is
// the §3.1 follow-up.
func runTpmAutoEnroll(ctx context.Context, cfg config.Config, apiURL string) int {
	// Resolve the API URL up front (flag → ENDPOINT_AGENT_AUTO_ENROLL_API_URL
	// fallback) — the wrapper needs the host for the mTLS SNI, so it must apply
	// the SAME resolution the orchestrator does, else the env-only path breaks
	// (Codex 019f024b P1).
	resolvedAPIURL := resolveTpmEnrollAPIURL(apiURL, cfg)
	if resolvedAPIURL == "" {
		fmt.Fprintln(os.Stderr, "tpm auto-enroll: --api-url (or ENDPOINT_AGENT_AUTO_ENROLL_API_URL) is required")
		return 2
	}
	// Token preflight here too, so a missing token fails fast WITHOUT opening the
	// cert store (the orchestrator re-checks it — defense in depth).
	if strings.TrimSpace(cfg.EnrollmentToken) == "" {
		fmt.Fprintln(os.Stderr, "tpm auto-enroll: an enrollment token is required (ENDPOINT_AGENT_ENROLLMENT_TOKEN)")
		return 2
	}

	// Bootstrap transport cert == the existing machine-cert (NOT the TPM-issued
	// cert this run produces). Reuse the regular auto-enroll cert filter so the
	// same narrowing (subject suffix / SAN URI prefix) applies.
	filter := autoenroll.DefaultCertFilter()
	filter.SubjectSuffix = cfg.AutoEnrollCertSubjectSuffix
	filter.SANURIPrefix = cfg.AutoEnrollCertSANURIPrefix
	if err := validateAutoEnrollCertFilter(filter); err != nil {
		fmt.Fprintf(os.Stderr, "tpm auto-enroll: bootstrap mTLS cert filter: %v\n", err)
		return 1
	}

	host, err := hostnameOnly(resolvedAPIURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "tpm auto-enroll: parse --api-url host: %v\n", err)
		return 1
	}

	material, err := certstore.New().LoadEligibleCert(ctx, filter)
	if err != nil {
		fmt.Fprintf(os.Stderr, "tpm auto-enroll: bootstrap mTLS cert load (LocalMachine\\My): %v\n", err)
		return 1
	}
	// The Windows signer holds an NCrypt/CNG handle — release it on return.
	defer func() {
		if c, ok := material.TLSCertificate.PrivateKey.(interface{ Close() }); ok {
			c.Close()
		}
	}()

	httpClient, err := mtls.NewClient(mtls.Options{
		Cert:       material.TLSCertificate,
		ServerName: host,
		Timeout:    30 * time.Second,
		MinVersion: tls.VersionTLS12,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "tpm auto-enroll: build mTLS client: %v\n", err)
		return 1
	}
	defer httpClient.CloseIdleConnections()

	return runTpmAutoEnrollWith(ctx, cfg, resolvedAPIURL, tpmEnrollDeps{
		newDevice:  tpmenroll.NewWindowsTPMDevice,
		httpClient: httpClient,
		persist: func(certPEM string) error {
			// Shared with the remote-bridge #548 device-key session reader
			// (internal/app/newTPMDeviceKeySessionIdentity) via the same helper so the
			// write and read locations can never drift.
			out := tpmenroll.DeviceClientCertPath()
			if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
				return err
			}
			return os.WriteFile(out, []byte(certPEM), 0o600)
		},
	})
}
