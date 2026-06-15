package tpmenroll

import "crypto"

// TPMDevice is the agent-side TPM 2.0 abstraction the enrollment orchestrator
// (3b) drives. It is satisfied by MockTPMDevice (software, this package, for CI +
// local-dev) and, in a later slice, by a go-tpm Windows-TBS implementation
// (build-tagged) — the two are interchangeable behind this interface so the
// orchestrator never touches platform-specific TPM code (Codex/MiniMax 3-AI cut).
//
// All public-area / Name / attest / signature byte strings are the TCG wire
// encodings produced by this package's marshalers (TPM2B_PUBLIC, TPM Name,
// TPMS_ATTEST, TPMT_SIGNATURE) so they drop straight into the /nonce + /attest
// envelopes the backend verifier parses.
type TPMDevice interface {
	// EndorsementKey returns the EK public area (TPM2B_PUBLIC), its certificate
	// (DER), and the manufacturer chain (DER, may be empty). The backend V2 chains
	// the EK cert to a pinned manufacturer root.
	EndorsementKey() (pub, certDER []byte, chainDER [][]byte, err error)

	// AttestationKey returns the AK public area (TPM2B_PUBLIC) and its TPM Name —
	// the restricted signing key whose Name keys MakeCredential and signs the
	// quote/certify (backend V11/V3).
	AttestationKey() (pub, name []byte, err error)

	// DeviceKey returns the public area (TPM2B_PUBLIC) of the TPM-resident key the
	// issued client cert will bind to (the certify subject + CSR key).
	DeviceKey() (pub []byte, err error)

	// ActivateCredential recovers the server's MakeCredential secret, proving the
	// EK and AK live in the same TPM (backend V10/V3). Fail-closed on any mismatch.
	ActivateCredential(credentialBlob, encSecret []byte) (secret []byte, err error)

	// Quote returns a TPM2_Quote TPMS_ATTEST over nonce (extraData) for the given
	// PCR selections, plus the AK's TPMT_SIGNATURE over it (backend V5).
	Quote(nonce []byte, sels []PCRSelection) (quoteAttest, quoteSig []byte, err error)

	// CertifyDeviceKey returns a TPM2_Certify TPMS_ATTEST in which the AK attests
	// the device key's Name, with qualifyingData bound, plus the AK's
	// TPMT_SIGNATURE (backend V4).
	CertifyDeviceKey(qualifyingData []byte) (certifyAttest, certifySig []byte, err error)

	// DeviceKeySigner is a crypto.Signer over the device key, for the CSR's
	// proof-of-possession (backend V9). The private key never leaves the device.
	DeviceKeySigner() crypto.Signer
}
