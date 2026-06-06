//go:build windows

package selfupdate

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// authenticode_windows.go — AG-029 PR1b Windows Authenticode runtime
// collaborator. The verifier extracts bounded signature evidence; the trust
// tier policy decides whether that evidence is acceptable. This split matters
// for LAB_ONLY_EVIDENCE: a parseable self-signed lab signature is evidence with
// ChainValid=false, while unsigned/tampered artifacts still fail closed.

// WindowsAuthenticodeVerifier verifies a staged Windows binary and extracts the
// signer facts consumed by the self-update policy. It is staging-only: it never
// activates or replaces a running service binary.
type WindowsAuthenticodeVerifier struct{}

// Verify implements AuthenticodeVerifier.
func (WindowsAuthenticodeVerifier) Verify(ctx context.Context, path string) (AuthenticodeEvidence, error) {
	if err := ctx.Err(); err != nil {
		return AuthenticodeEvidence{}, err
	}
	if strings.TrimSpace(path) == "" {
		return AuthenticodeEvidence{}, errors.New("authenticode: path is empty")
	}
	sig, err := queryAuthenticodeSignature(ctx, path)
	if err != nil {
		return AuthenticodeEvidence{}, err
	}
	chainValid, err := classifyAuthenticodeStatus(sig.Status, sig.StatusMessage)
	if err != nil {
		return AuthenticodeEvidence{}, err
	}
	if strings.TrimSpace(sig.CertRaw) == "" {
		return AuthenticodeEvidence{}, errors.New("authenticode: signer certificate missing")
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(sig.CertRaw))
	if err != nil {
		return AuthenticodeEvidence{}, fmt.Errorf("authenticode: signer certificate decode: %w", err)
	}
	cert, err := x509.ParseCertificate(raw)
	if err != nil {
		return AuthenticodeEvidence{}, fmt.Errorf("authenticode: parse primary signer certificate: %w", err)
	}

	now := time.Now()
	sum := sha256.Sum256(cert.Raw)
	return AuthenticodeEvidence{
		ChainValid:        chainValid,
		HasCodeSigningEKU: hasCodeSigningEKU(cert),
		SignerThumbprint:  strings.ToUpper(hex.EncodeToString(sum[:])),
		// Timestamp/countersignature extraction lands in a later hardening
		// slice. Until then, untimestamped semantics apply: the cert must be
		// valid at the current wall-clock time.
		Timestamped:      false,
		SigningTimeValid: false,
		CurrentTimeValid: !now.Before(cert.NotBefore) && !now.After(cert.NotAfter),
	}, nil
}

type authenticodeSignatureFacts struct {
	Status        string `json:"status"`
	StatusMessage string `json:"statusMessage"`
	CertRaw       string `json:"certRaw"`
}

func queryAuthenticodeSignature(ctx context.Context, path string) (authenticodeSignatureFacts, error) {
	psCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	const script = `$ErrorActionPreference = 'Stop'
$path = $env:ENDPOINT_AGENT_AUTHENTICODE_TARGET_PATH
if ([string]::IsNullOrWhiteSpace($path)) { throw 'authenticode: target path missing' }
$sig = Get-AuthenticodeSignature -LiteralPath $path
if ($null -eq $sig) { throw 'authenticode: signature missing' }
$cert = $sig.SignerCertificate
$certRaw = $null
if ($null -ne $cert) { $certRaw = [Convert]::ToBase64String($cert.RawData) }
[pscustomobject]@{
  status = [string]$sig.Status
  statusMessage = [string]$sig.StatusMessage
  certRaw = $certRaw
} | ConvertTo-Json -Compress`

	cmd := exec.CommandContext(psCtx, "powershell.exe",
		"-NoProfile",
		"-NonInteractive",
		"-ExecutionPolicy", "Bypass",
		"-Command", script,
	)
	cmd.Env = append(cmd.Environ(), "ENDPOINT_AGENT_AUTHENTICODE_TARGET_PATH="+path)
	out, err := cmd.CombinedOutput()
	if psCtx.Err() != nil {
		return authenticodeSignatureFacts{}, fmt.Errorf("authenticode: signature query timeout: %w", psCtx.Err())
	}
	if err != nil {
		return authenticodeSignatureFacts{}, fmt.Errorf("authenticode: signature query: %w: %s", err, strings.TrimSpace(string(out)))
	}
	var facts authenticodeSignatureFacts
	if err := json.Unmarshal([]byte(strings.TrimSpace(string(out))), &facts); err != nil {
		return authenticodeSignatureFacts{}, fmt.Errorf("authenticode: signature query decode: %w", err)
	}
	return facts, nil
}

func classifyAuthenticodeStatus(status, message string) (bool, error) {
	normalized := strings.ToLower(strings.TrimSpace(status))
	switch normalized {
	case "valid":
		return true, nil
	case "notsigned", "hashmismatch":
		return false, fmt.Errorf("authenticode: signature status %s", status)
	case "nottrusted", "unknownerror":
		if authenticodeMessageIsChainOnly(message) {
			return false, nil
		}
		return false, fmt.Errorf("authenticode: signature status %s: %s", status, strings.TrimSpace(message))
	default:
		return false, fmt.Errorf("authenticode: unsupported signature status %s: %s", status, strings.TrimSpace(message))
	}
}

func authenticodeMessageIsChainOnly(message string) bool {
	m := strings.ToLower(message)
	chainTerms := []string{
		"not trusted",
		"untrusted",
		"root certificate",
		"certificate chain",
		"terminated in a root",
		"revocation",
		"offline",
	}
	for _, term := range chainTerms {
		if strings.Contains(m, term) {
			return true
		}
	}
	return false
}

func hasCodeSigningEKU(cert *x509.Certificate) bool {
	if cert == nil {
		return false
	}
	for _, eku := range cert.ExtKeyUsage {
		if eku == x509.ExtKeyUsageCodeSigning {
			return true
		}
	}
	return false
}
