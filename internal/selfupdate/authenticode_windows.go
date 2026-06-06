//go:build windows

package selfupdate

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// authenticode_windows.go — AG-029 PR1b Windows Authenticode runtime
// collaborator. WinVerifyTrust remains the authority for signature and
// revocation decisions. Signer-certificate extraction uses Windows'
// Get-AuthenticodeSignature cmdlet with a fixed script and argv path, avoiding
// the unsafe WinTrust state-data pointer cast that go vet rejects.

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
	cert, err := winVerifyPrimarySigner(ctx, path)
	if err != nil {
		return AuthenticodeEvidence{}, err
	}

	now := time.Now()
	sum := sha256.Sum256(cert.Raw)
	return AuthenticodeEvidence{
		ChainValid:        true,
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

func winVerifyPrimarySigner(ctx context.Context, path string) (*x509.Certificate, error) {
	if err := winVerifyTrust(path); err != nil {
		return nil, err
	}
	return authenticodeSignerCertificate(ctx, path)
}

func winVerifyTrust(path string) error {
	utf16Path, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return fmt.Errorf("authenticode: utf16 path: %w", err)
	}
	fileInfo := &windows.WinTrustFileInfo{
		Size:     uint32(unsafe.Sizeof(windows.WinTrustFileInfo{})),
		FilePath: utf16Path,
	}
	data := &windows.WinTrustData{
		Size:                            uint32(unsafe.Sizeof(windows.WinTrustData{})),
		UIChoice:                        windows.WTD_UI_NONE,
		RevocationChecks:                windows.WTD_REVOKE_WHOLECHAIN,
		UnionChoice:                     windows.WTD_CHOICE_FILE,
		StateAction:                     windows.WTD_STATEACTION_VERIFY,
		FileOrCatalogOrBlobOrSgnrOrCert: unsafe.Pointer(fileInfo),
		ProvFlags: windows.WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT |
			windows.WTD_DISABLE_MD2_MD4,
	}
	verifyErr := windows.WinVerifyTrustEx(windows.InvalidHWND, &windows.WINTRUST_ACTION_GENERIC_VERIFY_V2, data)
	data.StateAction = windows.WTD_STATEACTION_CLOSE
	closeErr := windows.WinVerifyTrustEx(windows.InvalidHWND, &windows.WINTRUST_ACTION_GENERIC_VERIFY_V2, data)
	if verifyErr != nil {
		return fmt.Errorf("authenticode: WinVerifyTrust: %w", verifyErr)
	}
	if closeErr != nil {
		return fmt.Errorf("authenticode: WinVerifyTrust close: %w", closeErr)
	}
	return nil
}

func authenticodeSignerCertificate(ctx context.Context, path string) (*x509.Certificate, error) {
	psCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	const script = `$ErrorActionPreference = 'Stop'
$sig = Get-AuthenticodeSignature -LiteralPath $args[0]
if ($null -eq $sig) { throw 'authenticode: signature missing' }
if ($sig.Status -ne 'Valid') { throw ('authenticode: signature status ' + [string]$sig.Status) }
$cert = $sig.SignerCertificate
if ($null -eq $cert) { throw 'authenticode: signer certificate missing' }
[Convert]::ToBase64String($cert.RawData)`

	cmd := exec.CommandContext(psCtx, "powershell.exe",
		"-NoProfile",
		"-NonInteractive",
		"-ExecutionPolicy", "Bypass",
		"-Command", script,
		path,
	)
	out, err := cmd.CombinedOutput()
	if psCtx.Err() != nil {
		return nil, fmt.Errorf("authenticode: signer certificate query timeout: %w", psCtx.Err())
	}
	if err != nil {
		return nil, fmt.Errorf("authenticode: signer certificate query: %w: %s", err, strings.TrimSpace(string(out)))
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(out)))
	if err != nil {
		return nil, fmt.Errorf("authenticode: signer certificate decode: %w", err)
	}
	cert, err := x509.ParseCertificate(raw)
	if err != nil {
		return nil, fmt.Errorf("authenticode: parse primary signer certificate: %w", err)
	}
	return cert, nil
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
