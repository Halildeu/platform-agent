package commands

import (
	"context"
	"strings"
	"testing"
	"time"

	"platform-agent/internal/protocol"
)

func TestRenewTPMCertificateCommandReturnsBoundedResultWithoutSecret(t *testing.T) {
	original := renewTPMCertificateFn
	t.Cleanup(func() { renewTPMCertificateFn = original })
	renewTPMCertificateFn = func(
		_ context.Context,
		_ TPMRenewalOptions,
		req TPMRenewalRequest,
	) (TPMRenewalResult, error) {
		return TPMRenewalResult{
			EnrollmentID:        req.EnrollmentID,
			CertificateSHA256:   "aabbcc",
			CertificateNotAfter: time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC),
			RenewedAt:           time.Date(2026, 7, 26, 15, 0, 0, 0, time.UTC),
		}, nil
	}

	executor := NewLocalExecutor(
		[]protocol.CommandType{protocol.CommandRenewTPMCertificate}, "0.3.18")
	executor.TPMRenewal = &TPMRenewalOptions{
		APIURL:           "https://mtls.test.example/api/v1/endpoint-agent",
		CertSANURIPrefix: "adcomputer:",
	}
	command := protocol.AgentCommand{
		CommandID:     "command-1",
		ClaimID:       "claim-1",
		AttemptNumber: 1,
		Type:          protocol.CommandRenewTPMCertificate,
		RequestedBy:   "platform-admin",
		Reason:        "certificate rotation",
		Payload: map[string]interface{}{
			"reason":          "certificate rotation",
			"enrollmentId":    "33333333-3333-3333-3333-333333333333",
			"secretRef":       "endpoint-command-secret:enrollmentToken",
			"secretName":      "enrollmentToken",
			"secretDelivery":  "agent_claim_once",
			"expiresAt":       time.Now().Add(15 * time.Minute).UTC().Format(time.RFC3339Nano),
			"enrollmentToken": strings.Repeat("a", 32),
		},
		ClaimExpiresAt: time.Now().Add(time.Minute),
	}

	result := executor.Execute(context.Background(), command)

	if result.Status != protocol.CommandStatusSucceeded {
		t.Fatalf("status = %s, summary=%s code=%s", result.Status, result.Summary, result.ErrorCode)
	}
	if result.Summary != "RENEW_TPM_CERTIFICATE succeeded" {
		t.Fatalf("summary = %q", result.Summary)
	}
	if result.Details == nil || result.Details["tpmRenewal"] == nil {
		t.Fatalf("bounded TPM renewal result missing: %#v", result.Details)
	}
	if containsValue(result.Details, command.Payload["enrollmentToken"].(string)) {
		t.Fatal("command result leaked enrollment token")
	}
}

func TestRenewTPMCertificateRejectsMissingOneUseSecret(t *testing.T) {
	executor := NewLocalExecutor(
		[]protocol.CommandType{protocol.CommandRenewTPMCertificate}, "0.3.18")
	executor.TPMRenewal = &TPMRenewalOptions{
		APIURL:           "https://mtls.test.example/api/v1/endpoint-agent",
		CertSANURIPrefix: "adcomputer:",
	}
	command := protocol.AgentCommand{
		CommandID:      "command-2",
		ClaimID:        "claim-2",
		AttemptNumber:  1,
		Type:           protocol.CommandRenewTPMCertificate,
		RequestedBy:    "platform-admin",
		Reason:         "certificate rotation",
		ClaimExpiresAt: time.Now().Add(time.Minute),
		Payload: map[string]interface{}{
			"reason":         "certificate rotation",
			"enrollmentId":   "33333333-3333-3333-3333-333333333333",
			"secretRef":      "endpoint-command-secret:enrollmentToken",
			"secretName":     "enrollmentToken",
			"secretDelivery": "agent_claim_once",
			"expiresAt":      time.Now().Add(15 * time.Minute).UTC().Format(time.RFC3339Nano),
		},
	}

	result := executor.Execute(context.Background(), command)

	if result.Status != protocol.CommandStatusFailed {
		t.Fatalf("status = %s", result.Status)
	}
	if result.ErrorCode != "TPM_RENEWAL_INVALID_PAYLOAD" {
		t.Fatalf("errorCode = %q", result.ErrorCode)
	}
}

func TestRenewTPMCertificateRejectsExpiredEnrollment(t *testing.T) {
	executor := NewLocalExecutor(
		[]protocol.CommandType{protocol.CommandRenewTPMCertificate}, "0.3.18")
	executor.TPMRenewal = &TPMRenewalOptions{
		APIURL:           "https://mtls.test.example/api/v1/endpoint-agent",
		CertSANURIPrefix: "adcomputer:",
	}
	command := protocol.AgentCommand{
		CommandID:      "command-3",
		ClaimID:        "claim-3",
		AttemptNumber:  1,
		Type:           protocol.CommandRenewTPMCertificate,
		RequestedBy:    "platform-admin",
		Reason:         "certificate rotation",
		ClaimExpiresAt: time.Now().Add(time.Minute),
		Payload: map[string]interface{}{
			"reason":          "certificate rotation",
			"enrollmentId":    "33333333-3333-4333-8333-333333333333",
			"secretRef":       "endpoint-command-secret:enrollmentToken",
			"secretName":      "enrollmentToken",
			"secretDelivery":  "agent_claim_once",
			"expiresAt":       time.Now().Add(-time.Minute).UTC().Format(time.RFC3339Nano),
			"enrollmentToken": strings.Repeat("a", 32),
		},
	}

	result := executor.Execute(context.Background(), command)

	if result.Status != protocol.CommandStatusFailed {
		t.Fatalf("status = %s", result.Status)
	}
	if result.ErrorCode != "TPM_RENEWAL_INVALID_PAYLOAD" {
		t.Fatalf("errorCode = %q", result.ErrorCode)
	}
}

func TestTPMRenewalChildArgsUseExplicitCertificateLessBootstrap(t *testing.T) {
	opts := TPMRenewalOptions{
		APIURL: "https://test.example/api/v1/endpoint-agent",
	}
	args := tpmRenewalChildArgs(opts)
	want := []string{
		"--auto-enroll-tpm",
		"--tpm-bootstrap-server-tls",
		"--api-url",
		opts.APIURL,
	}
	if strings.Join(args, "\x00") != strings.Join(want, "\x00") {
		t.Fatalf("args = %#v, want %#v", args, want)
	}
}

func TestClassifyTPMRenewalChildFailureIsBoundedAndSecretFree(t *testing.T) {
	token := strings.Repeat("secret-token-", 1024)
	var diagnostic boundedDiagnosticWriter
	_, err := diagnostic.Write([]byte(
		"tpm auto-enroll: enroll: POST /enrollments/tpm/nonce returned 403: " + token,
	))
	if err != nil {
		t.Fatalf("write diagnostic: %v", err)
	}
	if len(diagnostic.String()) > tpmRenewalDiagnosticLimit {
		t.Fatalf("diagnostic length = %d", len(diagnostic.String()))
	}
	code := classifyTPMRenewalChildFailure(diagnostic.String(), 1)
	if code != "TPM_RENEWAL_NONCE_DENIED" {
		t.Fatalf("code = %q", code)
	}
	if strings.Contains(code, token) {
		t.Fatal("stable error code leaked child diagnostic")
	}
}

func TestClassifyTPMRenewalChildFailureStages(t *testing.T) {
	tests := []struct {
		name   string
		stderr string
		want   string
	}{
		{
			name:   "client certificate required",
			stderr: "remote error: tls: certificate required",
			want:   "TPM_RENEWAL_TLS_CLIENT_CERT_REQUIRED",
		},
		{
			name:   "tpm open",
			stderr: "tpm auto-enroll: open TPM device: tpmenroll: open TBS",
			want:   "TPM_RENEWAL_TPM_OPEN_FAILED",
		},
		{
			name:   "unknown",
			stderr: "unexpected child failure",
			want:   "TPM_RENEWAL_PROCESS_FAILED_7",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := classifyTPMRenewalChildFailure(tt.stderr, 7); got != tt.want {
				t.Fatalf("classifyTPMRenewalChildFailure() = %q, want %q", got, tt.want)
			}
		})
	}
}

func containsValue(value interface{}, wanted string) bool {
	switch node := value.(type) {
	case map[string]interface{}:
		for _, child := range node {
			if containsValue(child, wanted) {
				return true
			}
		}
	case string:
		return node == wanted
	}
	return false
}
