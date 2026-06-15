package tpmenroll

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"time"
)

// MockTPMDevice is a software TPMDevice for CI + local development: it generates
// RSA EK / AK / device keys in memory and produces the SAME TCG wire encodings
// (public areas, Name, MakeCredential activation, quote/certify, signatures) that
// a real TPM does, using this package's golden/NIST-verified primitives. It is
// NOT a security boundary — there is no hardware root of trust; the go-tpm
// Windows-TBS implementation (a later slice) is the real device. The mock exists
// so the enrollment orchestrator (3b) and its tests run end-to-end without a TPM.
type MockTPMDevice struct {
	ek        *rsa.PrivateKey
	ak        *rsa.PrivateKey
	deviceKey *rsa.PrivateKey
	ekCertDER []byte
	akPub     []byte
	akName    []byte
}

// NewMockTPMDevice generates the three RSA-2048 keys + a self-signed EK cert and
// pre-computes the AK public area + Name. nameAlg is SHA-256 (this feature).
func NewMockTPMDevice() (*MockTPMDevice, error) {
	ek, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("tpmenroll: mock EK: %w", err)
	}
	ak, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("tpmenroll: mock AK: %w", err)
	}
	deviceKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("tpmenroll: mock device key: %w", err)
	}

	akPub, err := BuildRSASigningPublicArea(ak.N, AlgSHA256, AKObjectAttributes, AlgRSASSA, AlgSHA256)
	if err != nil {
		return nil, err
	}
	pa, err := ParsePublicArea(akPub, true)
	if err != nil {
		return nil, err
	}
	akName, err := pa.ComputeName()
	if err != nil {
		return nil, err
	}

	// Self-signed EK cert placeholder (the backend V2 chain is config-pinned + off
	// by default; the mock is not a manufacturer-rooted EK). Software signing with
	// the EK key is fine here even though a real EK is a decrypt-only key.
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "mock-tpm-ek"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	ekCertDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &ek.PublicKey, ek)
	if err != nil {
		return nil, fmt.Errorf("tpmenroll: mock EK cert: %w", err)
	}

	return &MockTPMDevice{ek: ek, ak: ak, deviceKey: deviceKey, ekCertDER: ekCertDER, akPub: akPub, akName: akName}, nil
}

func (m *MockTPMDevice) EndorsementKey() (pub, certDER []byte, chainDER [][]byte, err error) {
	p, err := BuildRSAStorageEKPublicArea(m.ek.N)
	if err != nil {
		return nil, nil, nil, err
	}
	return p, cloneBytes(m.ekCertDER), nil, nil
}

func (m *MockTPMDevice) AttestationKey() (pub, name []byte, err error) {
	return cloneBytes(m.akPub), cloneBytes(m.akName), nil
}

func (m *MockTPMDevice) DeviceKey() ([]byte, error) {
	return BuildRSASigningPublicArea(m.deviceKey.N, AlgSHA256, DeviceKeyObjectAttributes, AlgNull, 0)
}

func (m *MockTPMDevice) ActivateCredential(credentialBlob, encSecret []byte) ([]byte, error) {
	return ActivateCredential(m.ek, AlgSHA256, m.akName, credentialBlob, encSecret)
}

func (m *MockTPMDevice) Quote(nonce []byte, sels []PCRSelection) (quoteAttest, quoteSig []byte, err error) {
	// A software mock has no real PCRs; the aggregate digest is a fixed zero block.
	// The backend's V6 PCR policy is opt-in and validates the digest only when a
	// required selection is configured (off by default for the pilot).
	attest := MarshalQuoteAttest(m.akName, nonce, sels, make([]byte, 32))
	sig, err := SignAttestRSASSA(m.ak, AlgSHA256, attest)
	if err != nil {
		return nil, nil, err
	}
	return attest, sig, nil
}

func (m *MockTPMDevice) CertifyDeviceKey(qualifyingData []byte) (certifyAttest, certifySig []byte, err error) {
	dkPub, err := m.DeviceKey()
	if err != nil {
		return nil, nil, err
	}
	dkPA, err := ParsePublicArea(dkPub, true)
	if err != nil {
		return nil, nil, err
	}
	dkName, err := dkPA.ComputeName()
	if err != nil {
		return nil, nil, err
	}
	attest := MarshalCertifyAttest(m.akName, qualifyingData, dkName)
	sig, err := SignAttestRSASSA(m.ak, AlgSHA256, attest)
	if err != nil {
		return nil, nil, err
	}
	return attest, sig, nil
}

func (m *MockTPMDevice) DeviceKeySigner() crypto.Signer { return m.deviceKey }

func cloneBytes(b []byte) []byte {
	out := make([]byte, len(b))
	copy(out, b)
	return out
}
