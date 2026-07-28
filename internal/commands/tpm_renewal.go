package commands

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"
)

const tpmEnrollmentTokenField = "enrollmentToken"
const tpmRenewalDiagnosticLimit = 8 * 1024

var enrollmentTokenPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{32,512}$`)
var enrollmentIDPattern = regexp.MustCompile(
	`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`,
)

type TPMRenewalOptions struct {
	APIURL            string
	CertSubjectSuffix string
	CertSANURIPrefix  string
}

type TPMRenewalRequest struct {
	EnrollmentID    string
	EnrollmentToken string
	Reason          string
	ExpiresAt       time.Time
}

type TPMRenewalResult struct {
	EnrollmentID        string    `json:"enrollmentId"`
	CertificateSHA256   string    `json:"certificateSha256,omitempty"`
	CertificateNotAfter time.Time `json:"certificateNotAfter,omitempty"`
	RenewedAt           time.Time `json:"renewedAt,omitempty"`
}

type boundedDiagnosticWriter struct {
	buf []byte
}

func (w *boundedDiagnosticWriter) Write(p []byte) (int, error) {
	accepted := len(p)
	remaining := tpmRenewalDiagnosticLimit - len(w.buf)
	if remaining > 0 {
		if len(p) > remaining {
			p = p[:remaining]
		}
		w.buf = append(w.buf, p...)
	}
	return accepted, nil
}

func (w *boundedDiagnosticWriter) String() string {
	return string(w.buf)
}

func classifyTPMRenewalChildFailure(stderr string, exitCode int) string {
	diagnostic := strings.ToLower(stderr)
	switch {
	case strings.Contains(diagnostic, "tls: certificate required"):
		return "TPM_RENEWAL_TLS_CLIENT_CERT_REQUIRED"
	case strings.Contains(diagnostic, "x509: certificate signed by unknown authority"):
		return "TPM_RENEWAL_TLS_TRUST_FAILED"
	case strings.Contains(diagnostic, "build server-tls bootstrap client"):
		return "TPM_RENEWAL_TLS_CLIENT_FAILED"
	case strings.Contains(diagnostic, "open tpm device"),
		strings.Contains(diagnostic, "tpmenroll: open tbs"):
		return "TPM_RENEWAL_TPM_OPEN_FAILED"
	case strings.Contains(diagnostic, "tpmenroll: create ek"):
		return "TPM_RENEWAL_EK_CREATE_FAILED"
	case strings.Contains(diagnostic, "tpmenroll: create ak"):
		return "TPM_RENEWAL_AK_CREATE_FAILED"
	case strings.Contains(diagnostic, "tpmenroll: create device key"):
		return "TPM_RENEWAL_DEVICE_KEY_CREATE_FAILED"
	case strings.Contains(diagnostic, "/enrollments/tpm/nonce returned 403"):
		return "TPM_RENEWAL_NONCE_DENIED"
	case strings.Contains(diagnostic, "/enrollments/tpm/nonce returned 429"):
		return "TPM_RENEWAL_RATE_LIMITED"
	case strings.Contains(diagnostic, "persist certificate"):
		return "TPM_RENEWAL_CERT_PERSIST_FAILED"
	case strings.Contains(diagnostic, "timeout"),
		strings.Contains(diagnostic, "connection refused"),
		strings.Contains(diagnostic, "no such host"):
		return "TPM_RENEWAL_NETWORK_FAILED"
	default:
		if exitCode >= 0 {
			return fmt.Sprintf("TPM_RENEWAL_PROCESS_FAILED_%d", exitCode)
		}
		return "TPM_RENEWAL_PROCESS_FAILED"
	}
}

var renewTPMCertificateFn = platformRenewTPMCertificate

func tpmRenewalChildArgs(opts TPMRenewalOptions) []string {
	return []string{
		"--auto-enroll-tpm",
		"--tpm-bootstrap-server-tls",
		"--api-url",
		opts.APIURL,
	}
}

func normalizeTPMRenewalOptions(opts TPMRenewalOptions) (TPMRenewalOptions, error) {
	opts.APIURL = strings.TrimRight(strings.TrimSpace(opts.APIURL), "/")
	opts.CertSubjectSuffix = strings.TrimSpace(opts.CertSubjectSuffix)
	opts.CertSANURIPrefix = strings.TrimSpace(opts.CertSANURIPrefix)
	if opts.APIURL == "" {
		return TPMRenewalOptions{}, fmt.Errorf("TPM renewal API URL is not configured")
	}
	parsed, err := url.Parse(opts.APIURL)
	if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" ||
		parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return TPMRenewalOptions{}, fmt.Errorf("TPM renewal API URL must be a canonical HTTPS URL")
	}
	if opts.CertSubjectSuffix == "" && opts.CertSANURIPrefix == "" {
		return TPMRenewalOptions{}, fmt.Errorf("TPM renewal certificate filter is not configured")
	}
	return opts, nil
}

func unmarshalTPMRenewalPayload(payload map[string]interface{}) (TPMRenewalRequest, error) {
	allowed := map[string]struct{}{
		"reason": {}, "enrollmentId": {}, "secretRef": {}, "secretName": {},
		"secretDelivery": {}, "expiresAt": {}, tpmEnrollmentTokenField: {},
	}
	for key := range payload {
		if _, ok := allowed[key]; !ok {
			return TPMRenewalRequest{}, fmt.Errorf("TPM_RENEWAL_INVALID_PAYLOAD: unsupported field %q", key)
		}
	}
	req := TPMRenewalRequest{
		EnrollmentID:    strings.TrimSpace(stringPayload(payload, "enrollmentId")),
		EnrollmentToken: strings.TrimSpace(stringPayload(payload, tpmEnrollmentTokenField)),
		Reason:          strings.TrimSpace(stringPayload(payload, "reason")),
	}
	if !enrollmentIDPattern.MatchString(req.EnrollmentID) || req.Reason == "" {
		return TPMRenewalRequest{}, fmt.Errorf("TPM_RENEWAL_INVALID_PAYLOAD: enrollmentId and reason are required")
	}
	if !enrollmentTokenPattern.MatchString(req.EnrollmentToken) {
		return TPMRenewalRequest{}, fmt.Errorf("TPM_RENEWAL_INVALID_SECRET: enrollment token is missing or malformed")
	}
	if strings.TrimSpace(stringPayload(payload, "secretRef")) !=
		"endpoint-command-secret:enrollmentToken" ||
		strings.TrimSpace(stringPayload(payload, "secretName")) != tpmEnrollmentTokenField ||
		strings.TrimSpace(stringPayload(payload, "secretDelivery")) != "agent_claim_once" {
		return TPMRenewalRequest{}, fmt.Errorf("TPM_RENEWAL_INVALID_PAYLOAD: command-secret binding is invalid")
	}
	expiresAt, err := time.Parse(
		time.RFC3339Nano,
		strings.TrimSpace(stringPayload(payload, "expiresAt")),
	)
	if err != nil || !expiresAt.After(time.Now().UTC()) ||
		expiresAt.After(time.Now().UTC().Add(time.Hour)) {
		return TPMRenewalRequest{}, fmt.Errorf("TPM_RENEWAL_INVALID_PAYLOAD: enrollment is expired or invalid")
	}
	req.ExpiresAt = expiresAt.UTC()
	return req, nil
}

func stringPayload(payload map[string]interface{}, key string) string {
	value, ok := payload[key]
	if !ok || value == nil {
		return ""
	}
	return fmt.Sprint(value)
}
