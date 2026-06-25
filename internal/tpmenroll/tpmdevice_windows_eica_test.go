//go:build windows

package tpmenroll

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
)

func mkDER(t *testing.T, cn string) []byte {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: cn}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatalf("mkDER: %v", err)
	}
	return der
}

func TestSplitDERCertsSeparatesConcatenatedChain(t *testing.T) {
	a, b := mkDER(t, "EICA-A"), mkDER(t, "EICA-B")
	out := splitDERCerts(append(append([]byte(nil), a...), b...))
	if len(out) != 2 {
		t.Fatalf("got %d certs, want 2", len(out))
	}
	for i, der := range out {
		if _, err := x509.ParseCertificate(der); err != nil {
			t.Fatalf("cert %d does not parse: %v", i, err)
		}
	}
	if splitDERCerts(nil) != nil {
		t.Fatal("empty blob must yield nil")
	}
	if got := splitDERCerts([]byte{0x30, 0x05, 0xde, 0xad}); len(got) != 0 {
		// truncated SEQUENCE: asn1.Unmarshal errors → no spurious cert
		t.Fatalf("truncated blob yielded %d certs, want 0", len(got))
	}
}
