package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"

	"platform-agent/internal/config"
	"platform-agent/internal/tpmenroll"
)

// tpmEnrollDeps are the injectable seams of the TPM auto-enroll flow. The real
// impls live in tpm_autoenroll_windows.go; the unit test injects fakes so the
// orchestration is testable without a TPM or a live backend.
type tpmEnrollDeps struct {
	newDevice  func() (tpmenroll.TPMDevice, error)
	httpClient *http.Client
	persist    func(certPEM string) error
}

// resolveTpmEnrollAPIURL resolves the TPM auto-enroll API base URL: the --api-url
// flag (trimmed, trailing slash removed) wins; an empty flag falls back to
// cfg.AutoEnrollAPIURL (the ENDPOINT_AGENT_AUTO_ENROLL_API_URL env path). Returns
// "" when neither is set (callers exit 2). Shared by the Windows real-deps
// wrapper (which needs the resolved host for the mTLS SNI) and this orchestrator
// so the env-path contract cannot diverge between them (Codex 019f024b P1).
func resolveTpmEnrollAPIURL(apiURL string, cfg config.Config) string {
	resolved := strings.TrimRight(strings.TrimSpace(apiURL), "/")
	if resolved == "" {
		resolved = strings.TrimRight(strings.TrimSpace(cfg.AutoEnrollAPIURL), "/")
	}
	return resolved
}

// runTpmAutoEnrollWith drives the Faz 22.3B 4-leg TPM enrollment (POST /nonce →
// ActivateCredential → Quote/Certify/CSR → POST /attest) and persists the issued
// client certificate. Returns a process exit code. All external effects are
// injected, so the flow is exercised end-to-end in tests against a fake device +
// an httptest backend. This entrypoint is a CLOSED feature path (off unless
// --auto-enroll-tpm is passed); the live e2e is operator-gated (needs the
// deployed backend + Vault PKI engine).
func runTpmAutoEnrollWith(ctx context.Context, cfg config.Config, apiURL string, deps tpmEnrollDeps) int {
	apiURL = resolveTpmEnrollAPIURL(apiURL, cfg)
	if apiURL == "" {
		fmt.Fprintln(os.Stderr, "tpm auto-enroll: --api-url (or ENDPOINT_AGENT_AUTO_ENROLL_API_URL) is required")
		return 2
	}
	if strings.TrimSpace(cfg.EnrollmentToken) == "" {
		fmt.Fprintln(os.Stderr, "tpm auto-enroll: an enrollment token is required (ENDPOINT_AGENT_ENROLLMENT_TOKEN)")
		return 2
	}

	dev, err := deps.newDevice()
	if err != nil {
		fmt.Fprintf(os.Stderr, "tpm auto-enroll: open TPM device: %v\n", err)
		return 1
	}
	defer func() { _ = dev.Close() }()

	client, err := tpmenroll.NewClient(apiURL, deps.httpClient)
	if err != nil {
		fmt.Fprintf(os.Stderr, "tpm auto-enroll: build client: %v\n", err)
		return 1
	}

	host, _ := os.Hostname()
	certPEM, err := client.Enroll(ctx, dev, tpmenroll.EnrollOptions{
		EnrollmentToken: cfg.EnrollmentToken,
		DeviceRef:       host,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "tpm auto-enroll: enroll: %v\n", err)
		return 1
	}

	if err := deps.persist(certPEM); err != nil {
		fmt.Fprintf(os.Stderr, "tpm auto-enroll: persist certificate: %v\n", err)
		return 1
	}
	fmt.Fprintf(os.Stdout, "tpm auto-enroll: success — issued client certificate persisted (deviceRef=%s)\n", host)
	return 0
}
