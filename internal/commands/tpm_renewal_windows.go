//go:build windows

package commands

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"platform-agent/internal/tpmenroll"
)

func platformSupportsTPMRenewal() bool {
	return true
}

func platformRenewTPMCertificate(
	ctx context.Context,
	opts TPMRenewalOptions,
	req TPMRenewalRequest,
) (TPMRenewalResult, error) {
	executable, err := os.Executable()
	if err != nil {
		return TPMRenewalResult{}, fmt.Errorf("TPM_RENEWAL_EXECUTABLE_UNAVAILABLE")
	}

	cmd := exec.CommandContext(ctx, executable, "--auto-enroll-tpm", "--api-url", opts.APIURL)
	cmd.Env = sanitizedChildEnvironment(os.Environ(),
		"ENDPOINT_AGENT_ENROLLMENT_TOKEN",
		"ENDPOINT_AGENT_AUTO_ENROLL_CERT_SUBJECT_SUFFIX",
		"ENDPOINT_AGENT_AUTO_ENROLL_CERT_SAN_URI_PREFIX")
	cmd.Env = append(cmd.Env,
		"ENDPOINT_AGENT_ENROLLMENT_TOKEN="+req.EnrollmentToken,
		"ENDPOINT_AGENT_AUTO_ENROLL_CERT_SUBJECT_SUFFIX="+opts.CertSubjectSuffix,
		"ENDPOINT_AGENT_AUTO_ENROLL_CERT_SAN_URI_PREFIX="+opts.CertSANURIPrefix)
	// TPM CLI output is deliberately discarded. The command result below is a
	// bounded projection and never carries the enrollment token or child logs.
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return TPMRenewalResult{}, fmt.Errorf("TPM_RENEWAL_TIMEOUT")
		}
		if exitErr, ok := err.(*exec.ExitError); ok {
			return TPMRenewalResult{}, fmt.Errorf("TPM_RENEWAL_PROCESS_FAILED_%d", exitErr.ExitCode())
		}
		return TPMRenewalResult{}, fmt.Errorf("TPM_RENEWAL_PROCESS_FAILED")
	}

	certPEM, err := os.ReadFile(tpmenroll.DeviceClientCertPath())
	if err != nil {
		return TPMRenewalResult{}, fmt.Errorf("TPM_RENEWAL_CERTIFICATE_MISSING")
	}
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return TPMRenewalResult{}, fmt.Errorf("TPM_RENEWAL_CERTIFICATE_INVALID")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return TPMRenewalResult{}, fmt.Errorf("TPM_RENEWAL_CERTIFICATE_INVALID")
	}
	now := time.Now().UTC()
	if !cert.NotAfter.After(now) || cert.NotBefore.After(now.Add(5*time.Minute)) {
		return TPMRenewalResult{}, fmt.Errorf("TPM_RENEWAL_CERTIFICATE_NOT_CURRENT")
	}
	digest := sha256.Sum256(cert.Raw)
	return TPMRenewalResult{
		EnrollmentID:        req.EnrollmentID,
		CertificateSHA256:   hex.EncodeToString(digest[:]),
		CertificateNotAfter: cert.NotAfter.UTC(),
		RenewedAt:           now,
	}, nil
}

func sanitizedChildEnvironment(current []string, blocked ...string) []string {
	prefixes := make([]string, 0, len(blocked))
	for _, key := range blocked {
		prefixes = append(prefixes, strings.ToUpper(key)+"=")
	}
	clean := make([]string, 0, len(current))
	for _, entry := range current {
		upper := strings.ToUpper(entry)
		blockedEntry := false
		for _, prefix := range prefixes {
			if strings.HasPrefix(upper, prefix) {
				blockedEntry = true
				break
			}
		}
		if !blockedEntry {
			clean = append(clean, entry)
		}
	}
	return clean
}
