//go:build windows

package selfupdate

import (
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNativeAuthenticodeVerifierUnsignedFileFailsClosed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "endpoint-agent.exe")
	if err := os.WriteFile(path, []byte("not a signed PE file"), 0o600); err != nil {
		t.Fatal(err)
	}

	ev, code, reason := NewNativeAuthenticodeVerifier().VerifyAuthenticode(path)
	if code != ErrSignatureInvalid {
		t.Fatalf("code=%q reason=%q ev=%+v, want signature invalid", code, reason, ev)
	}
}

func TestCertificateToAuthenticodeEvidenceUsesTimestampSigningTime(t *testing.T) {
	cert := &x509.Certificate{
		Raw:         []byte("certificate-bytes"),
		NotBefore:   time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:    time.Date(2024, 12, 31, 23, 59, 59, 0, time.UTC),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
	}
	ev := certificateToAuthenticodeEvidence(cert, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), winTrustEvidence{
		Timestamped: true,
		SigningTime: time.Date(2024, 6, 1, 12, 0, 0, 0, time.UTC),
	})
	if !ev.Timestamped || !ev.SigningTimeValid {
		t.Fatalf("timestamp evidence not applied: %+v", ev)
	}
	if ev.CurrentTimeValid {
		t.Fatalf("current time should be outside cert validity: %+v", ev)
	}
}

func TestCertificateToAuthenticodeEvidenceRejectsOutOfRangeTimestamp(t *testing.T) {
	cert := &x509.Certificate{
		Raw:         []byte("certificate-bytes"),
		NotBefore:   time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:    time.Date(2024, 12, 31, 23, 59, 59, 0, time.UTC),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
	}
	ev := certificateToAuthenticodeEvidence(cert, time.Date(2024, 6, 1, 12, 0, 0, 0, time.UTC), winTrustEvidence{
		Timestamped: true,
		SigningTime: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
	})
	if !ev.Timestamped || ev.SigningTimeValid {
		t.Fatalf("out-of-range signing time should fail timestamp validity: %+v", ev)
	}
}
