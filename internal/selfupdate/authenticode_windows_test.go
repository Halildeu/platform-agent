//go:build windows

package selfupdate

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestWindowsAuthenticodeVerifierUnsignedFailsClosed(t *testing.T) {
	exe := copyCurrentTestExecutable(t, "unsigned.exe")

	_, err := (WindowsAuthenticodeVerifier{}).Verify(context.Background(), exe)
	if err == nil {
		t.Fatal("unsigned executable must fail Authenticode verification")
	}
}

func TestWindowsAuthenticodeVerifierReturnsLabEvidenceForSelfSignedSignature(t *testing.T) {
	exe := copyCurrentTestExecutable(t, "signed.exe")
	signWithLocalSelfSignedCertOrSkip(t, exe)

	ev, err := (WindowsAuthenticodeVerifier{}).Verify(context.Background(), exe)
	if err != nil {
		t.Fatalf("Verify self-signed lab signature: %v", err)
	}
	if ev.SignerThumbprint == "" {
		t.Fatalf("SignerThumbprint empty: %+v", ev)
	}
	if !ev.HasCodeSigningEKU {
		t.Fatalf("self-signed code-signing cert should carry EKU: %+v", ev)
	}
	if !ev.CurrentTimeValid {
		t.Fatalf("self-signed cert should be current-time valid: %+v", ev)
	}
}

func TestClassifyAuthenticodeStatus(t *testing.T) {
	if chainValid, err := classifyAuthenticodeStatus("Valid", ""); err != nil || !chainValid {
		t.Fatalf("Valid => chainValid=%v err=%v", chainValid, err)
	}
	if chainValid, err := classifyAuthenticodeStatus("UnknownError", "A certificate chain processed, but terminated in a root certificate which is not trusted by the trust provider"); err != nil || chainValid {
		t.Fatalf("UnknownError untrusted root => chainValid=%v err=%v", chainValid, err)
	}
	if _, err := classifyAuthenticodeStatus("HashMismatch", ""); err == nil {
		t.Fatal("HashMismatch must fail closed")
	}
	if _, err := classifyAuthenticodeStatus("UnknownError", "unexpected provider error"); err == nil {
		t.Fatal("unclassified UnknownError must fail closed")
	}
}

func copyCurrentTestExecutable(t *testing.T, name string) string {
	t.Helper()
	src, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(t.TempDir(), name)
	raw, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, raw, 0o700); err != nil {
		t.Fatal(err)
	}
	return dst
}

func signWithLocalSelfSignedCertOrSkip(t *testing.T, path string) {
	t.Helper()
	const script = `$ErrorActionPreference = 'Stop'
$path = $env:AUTH_TEST_PATH
if ([string]::IsNullOrWhiteSpace($path)) { throw 'AUTH_TEST_PATH missing' }
$cert = New-SelfSignedCertificate -Subject 'CN=platform-agent local authenticode verifier test' -CertStoreLocation Cert:\CurrentUser\My -Type CodeSigningCert -KeyUsage DigitalSignature -KeyAlgorithm RSA -KeyLength 2048 -NotAfter (Get-Date).AddDays(3)
$sig = Set-AuthenticodeSignature -LiteralPath $path -Certificate $cert -HashAlgorithm SHA256
if ($null -eq $sig.SignerCertificate) { throw 'signer certificate missing after Set-AuthenticodeSignature' }
[string]$sig.Status`
	cmd := exec.Command("powershell.exe",
		"-NoProfile",
		"-NonInteractive",
		"-ExecutionPolicy", "Bypass",
		"-Command", script,
	)
	cmd.Env = append(os.Environ(), "AUTH_TEST_PATH="+path)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Skipf("local self-signed Authenticode signing unavailable: %v: %s", err, strings.TrimSpace(string(out)))
	}
}
