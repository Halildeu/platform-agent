//go:build windows

package tpmenroll

import (
	"crypto"
	"encoding/asn1"
	"fmt"
	"io"
	"math/big"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/windowstpm"
)

// WindowsTPMDevice is the real TPMDevice backed by a hardware/firmware TPM 2.0
// via Windows TBS (go-tpm). It creates an EK (endorsement primary), an AK
// (restricted-signing owner primary), and a device key (RSA-3072 non-restricted
// owner primary), and produces the SAME TCG wire encodings the MockTPMDevice +
// the backend verifier use. The private keys never leave the TPM.
//
// Lifecycle: NewWindowsTPMDevice opens TBS + creates the three keys as transient
// primaries (held by handle for the enrollment); Close flushes them + closes TBS.
type WindowsTPMDevice struct {
	tpm transport.TPMCloser

	ekHandle tpm2.TPMHandle
	ekName   tpm2.TPM2BName
	ekPublic tpm2.TPM2BPublic

	akHandle tpm2.TPMHandle
	akName   tpm2.TPM2BName
	akPublic tpm2.TPM2BPublic

	deviceHandle tpm2.TPMHandle
	deviceName   tpm2.TPM2BName
	devicePublic tpm2.TPM2BPublic
}

// NewWindowsTPMDevice opens the TPM via TBS and creates the EK, AK, and device key.
func NewWindowsTPMDevice() (TPMDevice, error) {
	thetpm, err := windowstpm.Open()
	if err != nil {
		return nil, fmt.Errorf("tpmenroll: open TBS: %w", err)
	}
	d := &WindowsTPMDevice{tpm: thetpm}
	ok := false
	defer func() {
		if !ok {
			d.Close()
		}
	}()

	// EK — endorsement-hierarchy primary, TCG RSA EK template.
	ek, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHEndorsement,
		InPublic:      tpm2.New2B(tpm2.RSAEKTemplate),
	}.Execute(thetpm)
	if err != nil {
		return nil, fmt.Errorf("tpmenroll: create EK: %w", err)
	}
	d.ekHandle, d.ekName, d.ekPublic = ek.ObjectHandle, ek.Name, ek.OutPublic

	// AK — owner-hierarchy primary, restricted RSA-2048 signing key (the
	// attestation key the backend V11 expects + MakeCredential binds to).
	ak, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      tpm2.New2B(rsaAKTemplate()),
	}.Execute(thetpm)
	if err != nil {
		return nil, fmt.Errorf("tpmenroll: create AK: %w", err)
	}
	d.akHandle, d.akName, d.akPublic = ak.ObjectHandle, ak.Name, ak.OutPublic

	// Device key — owner-hierarchy primary, non-restricted EC P-256 signing key
	// (the cert subject key). The V12 DEVICE floor is "RSA-3072+ OR EC-P256+";
	// EC P-256 is chosen because RSA-3072 primary creation is OPTIONAL in TPM 2.0
	// and unsupported on many TPMs (incl. the test vTPM → TPM_RC_VALUE), whereas
	// EC P-256 is universally supported.
	dev, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      tpm2.New2B(eccP256SigningTemplate()),
	}.Execute(thetpm)
	if err != nil {
		return nil, fmt.Errorf("tpmenroll: create device key: %w", err)
	}
	d.deviceHandle, d.deviceName, d.devicePublic = dev.ObjectHandle, dev.Name, dev.OutPublic

	ok = true
	return d, nil
}

// Close flushes the transient keys and closes the TBS handle.
func (d *WindowsTPMDevice) Close() error {
	if d.tpm == nil {
		return nil
	}
	for _, h := range []tpm2.TPMHandle{d.deviceHandle, d.akHandle, d.ekHandle} {
		if h != 0 {
			_, _ = tpm2.FlushContext{FlushHandle: h}.Execute(d.tpm)
		}
	}
	return d.tpm.Close()
}

// ekCertNVIndexRSA is the TCG PC Client RSA-2048 endorsement-key certificate NV index (TPM 2.0 Part 2,
// "Registry of reserved handles"). Firmware TPMs provision the manufacturer EK cert here; per the PC Client
// profile the index is AuthRead with an EMPTY auth value, so it is readable via the index's own (nil) password.
const ekCertNVIndexRSA = 0x01C00002

func (d *WindowsTPMDevice) EndorsementKey() (pub, certDER []byte, chainDER [][]byte, err error) {
	b := tpm2.Marshal(d.ekPublic)
	// #548 strong path: read the manufacturer EK certificate from TPM NV. Best-effort by design — the backend
	// EK-chain check (V2) is config-pinned and the device-key strong path is gated, so a TPM with no readable EK
	// cert degrades to the bounded-lab path (the broker denies ek-cert-required, fail-closed) instead of
	// breaking enrollment. HARDWARE-UNVERIFIED: the go-tpm NV sequence and the index's auth model are exercised
	// only on a real Windows TPM at the step-7 live run; vendor NV provisioning (AuthRead-empty vs OwnerRead,
	// MAX_NV_BUFFER size) can vary and is confirmed there.
	cert, rerr := d.readEKCertificate()
	if rerr != nil {
		return b, nil, nil, nil
	}
	return b, cert, nil, nil
}

// readEKCertificate reads the DER manufacturer EK certificate from the RSA EK-cert NV index. It first reads the
// index public area for the data size + Name, then reads the area in bounded chunks via the index's own (empty)
// auth, concatenating until DataSize bytes are read. Any TPM error (index absent, auth-model mismatch) surfaces
// to the caller, which treats a read failure as "no cert" (fail-closed at the broker verifier).
func (d *WindowsTPMDevice) readEKCertificate() ([]byte, error) {
	if d.tpm == nil {
		return nil, fmt.Errorf("tpm not open")
	}
	idx := tpm2.TPMHandle(ekCertNVIndexRSA)
	readPub, err := tpm2.NVReadPublic{NVIndex: idx}.Execute(d.tpm)
	if err != nil {
		return nil, fmt.Errorf("NV read-public EK cert index 0x%x: %w", ekCertNVIndexRSA, err)
	}
	nvPub, err := readPub.NVPublic.Contents()
	if err != nil {
		return nil, fmt.Errorf("decode EK cert NV public area: %w", err)
	}
	total := int(nvPub.DataSize)
	if total == 0 {
		return nil, fmt.Errorf("EK cert NV index 0x%x reports zero data size", ekCertNVIndexRSA)
	}
	// chunk conservatively below the TPM's MAX_NV_BUFFER_SIZE (>=512 octets on all PC Client TPMs).
	const chunk = 512
	out := make([]byte, 0, total)
	for off := 0; off < total; {
		n := total - off
		if n > chunk {
			n = chunk
		}
		rsp, err := tpm2.NVRead{
			AuthHandle: tpm2.AuthHandle{Handle: idx, Name: readPub.NVName, Auth: tpm2.PasswordAuth(nil)},
			NVIndex:    tpm2.NamedHandle{Handle: idx, Name: readPub.NVName},
			Size:       uint16(n),
			Offset:     uint16(off),
		}.Execute(d.tpm)
		if err != nil {
			return nil, fmt.Errorf("NV read EK cert at offset %d: %w", off, err)
		}
		if len(rsp.Data.Buffer) == 0 {
			return nil, fmt.Errorf("NV read EK cert returned 0 bytes at offset %d", off)
		}
		out = append(out, rsp.Data.Buffer...)
		off += len(rsp.Data.Buffer)
	}
	return out, nil
}

func (d *WindowsTPMDevice) AttestationKey() (pub, name []byte, err error) {
	return tpm2.Marshal(d.akPublic), append([]byte(nil), d.akName.Buffer...), nil
}

func (d *WindowsTPMDevice) DeviceKey() ([]byte, error) {
	return tpm2.Marshal(d.devicePublic), nil
}

func (d *WindowsTPMDevice) ActivateCredential(credentialBlob, encSecret []byte) ([]byte, error) {
	// The wire credBlob is the raw idObject (TPM2B(hmac)‖encIdentity) and encSecret
	// is the raw OAEP output — exactly what go-tpm's TPM2BIDObject/EncryptedSecret
	// hold (it marshals the TPM2B size prefix to the TPM). NOT Unmarshal (which
	// would expect an already-size-prefixed blob).
	rsp, err := tpm2.ActivateCredential{
		ActivateHandle: tpm2.NamedHandle{Handle: d.akHandle, Name: d.akName},
		KeyHandle: tpm2.AuthHandle{
			Handle: d.ekHandle,
			Name:   d.ekName,
			Auth:   tpm2.Policy(tpm2.TPMAlgSHA256, 16, d.ekPolicy),
		},
		CredentialBlob: tpm2.TPM2BIDObject{Buffer: credentialBlob},
		Secret:         tpm2.TPM2BEncryptedSecret{Buffer: encSecret},
	}.Execute(d.tpm)
	if err != nil {
		return nil, fmt.Errorf("tpmenroll: activate credential: %w", err)
	}
	return append([]byte(nil), rsp.CertInfo.Buffer...), nil
}

func (d *WindowsTPMDevice) Quote(nonce []byte, sels []PCRSelection) (quoteAttest, quoteSig []byte, err error) {
	rsp, err := tpm2.Quote{
		SignHandle:     tpm2.AuthHandle{Handle: d.akHandle, Name: d.akName, Auth: tpm2.PasswordAuth(nil)},
		QualifyingData: tpm2.TPM2BData{Buffer: nonce},
		InScheme: tpm2.TPMTSigScheme{
			Scheme:  tpm2.TPMAlgRSASSA,
			Details: tpm2.NewTPMUSigScheme(tpm2.TPMAlgRSASSA, &tpm2.TPMSSchemeHash{HashAlg: tpm2.TPMAlgSHA256}),
		},
		PCRSelect: pcrSelectionList(sels),
	}.Execute(d.tpm)
	if err != nil {
		return nil, nil, fmt.Errorf("tpmenroll: quote: %w", err)
	}
	return append([]byte(nil), rsp.Quoted.Bytes()...), tpm2.Marshal(rsp.Signature), nil
}

func (d *WindowsTPMDevice) CertifyDeviceKey(qualifyingData []byte) (certifyAttest, certifySig []byte, err error) {
	rsp, err := tpm2.Certify{
		ObjectHandle:   tpm2.AuthHandle{Handle: d.deviceHandle, Name: d.deviceName, Auth: tpm2.PasswordAuth(nil)},
		SignHandle:     tpm2.AuthHandle{Handle: d.akHandle, Name: d.akName, Auth: tpm2.PasswordAuth(nil)},
		QualifyingData: tpm2.TPM2BData{Buffer: qualifyingData},
		InScheme: tpm2.TPMTSigScheme{
			Scheme:  tpm2.TPMAlgRSASSA,
			Details: tpm2.NewTPMUSigScheme(tpm2.TPMAlgRSASSA, &tpm2.TPMSSchemeHash{HashAlg: tpm2.TPMAlgSHA256}),
		},
	}.Execute(d.tpm)
	if err != nil {
		return nil, nil, fmt.Errorf("tpmenroll: certify: %w", err)
	}
	return append([]byte(nil), rsp.CertifyInfo.Bytes()...), tpm2.Marshal(rsp.Signature), nil
}

func (d *WindowsTPMDevice) DeviceKeySigner() crypto.Signer {
	return &tpmDeviceSigner{d: d}
}

// ekPolicy satisfies the EK's authPolicy (PolicySecret over the endorsement
// hierarchy) for ActivateCredential's KeyHandle auth.
func (d *WindowsTPMDevice) ekPolicy(t transport.TPM, handle tpm2.TPMISHPolicy, _ tpm2.TPM2BNonce) error {
	_, err := tpm2.PolicySecret{
		AuthHandle:    tpm2.TPMRHEndorsement,
		PolicySession: handle,
	}.Execute(t)
	return err
}

func pcrSelectionList(sels []PCRSelection) tpm2.TPMLPCRSelection {
	out := tpm2.TPMLPCRSelection{}
	for _, s := range sels {
		out.PCRSelections = append(out.PCRSelections, tpm2.TPMSPCRSelection{
			Hash:      tpm2.TPMAlgID(s.HashAlg),
			PCRSelect: append([]byte(nil), s.Bitmap...),
		})
	}
	return out
}

func rsaSigningTemplate(keyBits int, restricted bool) tpm2.TPMTPublic {
	return tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgRSA,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:            true,
			FixedParent:         true,
			SensitiveDataOrigin: true,
			UserWithAuth:        true,
			Restricted:          restricted,
			SignEncrypt:         true,
		},
		Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgRSA, &tpm2.TPMSRSAParms{
			Scheme: tpm2.TPMTRSAScheme{
				Scheme:  tpm2.TPMAlgRSASSA,
				Details: tpm2.NewTPMUAsymScheme(tpm2.TPMAlgRSASSA, &tpm2.TPMSSigSchemeRSASSA{HashAlg: tpm2.TPMAlgSHA256}),
			},
			KeyBits: tpm2.TPMKeyBits(keyBits),
		}),
		Unique: tpm2.NewTPMUPublicID(tpm2.TPMAlgRSA, &tpm2.TPM2BPublicKeyRSA{Buffer: make([]byte, keyBits/8)}),
	}
}

func rsaAKTemplate() tpm2.TPMTPublic { return rsaSigningTemplate(2048, true) }

// eccP256SigningTemplate is a non-restricted EC P-256 (ECDSA-SHA256) signing key
// — the device identity key. Symmetric=NULL (a signing key carries no symmetric
// block); KDF=NULL.
func eccP256SigningTemplate() tpm2.TPMTPublic {
	return tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgECC,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:            true,
			FixedParent:         true,
			SensitiveDataOrigin: true,
			UserWithAuth:        true,
			SignEncrypt:         true,
		},
		Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgECC, &tpm2.TPMSECCParms{
			Symmetric: tpm2.TPMTSymDefObject{Algorithm: tpm2.TPMAlgNull},
			Scheme: tpm2.TPMTECCScheme{
				Scheme:  tpm2.TPMAlgECDSA,
				Details: tpm2.NewTPMUAsymScheme(tpm2.TPMAlgECDSA, &tpm2.TPMSSigSchemeECDSA{HashAlg: tpm2.TPMAlgSHA256}),
			},
			CurveID: tpm2.TPMECCNistP256,
			KDF:     tpm2.TPMTKDFScheme{Scheme: tpm2.TPMAlgNull},
		}),
		Unique: tpm2.NewTPMUPublicID(tpm2.TPMAlgECC, &tpm2.TPMSECCPoint{
			X: tpm2.TPM2BECCParameter{Buffer: make([]byte, 32)},
			Y: tpm2.TPM2BECCParameter{Buffer: make([]byte, 32)},
		}),
	}
}

// tpmDeviceSigner adapts the TPM-resident device key to crypto.Signer (for the
// CSR proof-of-possession + the #548 device-key session binding). The device key is
// EC P-256, so it signs the supplied digest via TPM2_Sign (ECDSA, SHA-256) and
// returns an ASN.1-DER ECDSA signature.
type tpmDeviceSigner struct{ d *WindowsTPMDevice }

func (s *tpmDeviceSigner) Public() crypto.PublicKey {
	pa, err := ParsePublicArea(tpm2.Marshal(s.d.devicePublic), true)
	if err != nil {
		return nil
	}
	pub, _ := pa.PublicKey()
	return pub
}

func (s *tpmDeviceSigner) Sign(_ io.Reader, digest []byte, _ crypto.SignerOpts) ([]byte, error) {
	rsp, err := tpm2.Sign{
		KeyHandle: tpm2.AuthHandle{Handle: s.d.deviceHandle, Name: s.d.deviceName, Auth: tpm2.PasswordAuth(nil)},
		Digest:    tpm2.TPM2BDigest{Buffer: digest},
		InScheme: tpm2.TPMTSigScheme{
			Scheme:  tpm2.TPMAlgECDSA,
			Details: tpm2.NewTPMUSigScheme(tpm2.TPMAlgECDSA, &tpm2.TPMSSchemeHash{HashAlg: tpm2.TPMAlgSHA256}),
		},
		Validation: tpm2.TPMTTKHashCheck{Tag: tpm2.TPMSTHashCheck, Hierarchy: tpm2.TPMRHNull},
	}.Execute(s.d.tpm)
	if err != nil {
		return nil, fmt.Errorf("tpmenroll: device key sign: %w", err)
	}
	ecc, err := rsp.Signature.Signature.ECDSA()
	if err != nil {
		return nil, fmt.Errorf("tpmenroll: extract ECDSA sig: %w", err)
	}
	// crypto.Signer for an EC key returns the ASN.1 DER ECDSA-Sig-Value the x509
	// CSR builder + verifiers expect (the TPM emits raw fixed-width R‖S).
	return asn1.Marshal(struct{ R, S *big.Int }{
		R: new(big.Int).SetBytes(ecc.SignatureR.Buffer),
		S: new(big.Int).SetBytes(ecc.SignatureS.Buffer),
	})
}

var _ TPMDevice = (*WindowsTPMDevice)(nil)
