package tpmenroll

// Wire DTOs for the Faz 22.3B 4-leg TPM enrollment, byte-for-byte matching the
// backend records in endpoint-admin-service .../tpmattest (TpmNonceRequest,
// TpmAttestChallenge, TpmAttestEnvelope, TpmAttestResponse). The JSON keys MUST
// equal the Java record component names (Jackson default) — wire_test.go pins
// that contract. All []byte-on-the-Java-side fields are base64 strings on the
// wire; here they are typed `string` (base64-std) and the orchestrator (3b)
// encodes/decodes at the TPMDevice boundary.

// SchemaV2 is TpmAttestEnvelope.SCHEMA_V2 — the only attest schema the backend accepts.
const SchemaV2 = "faz22.3b.tpm-attest.v2"

// Endpoint suffixes (joined onto the agent API base, e.g.
// https://host/api/v1/agent). The backend maps these under
// /api/v1/agent/enrollments/tpm/{nonce,attest}.
const (
	PathTPMNonce  = "/enrollments/tpm/nonce"
	PathTPMAttest = "/enrollments/tpm/attest"
)

// NonceRequest is leg 1 (POST /nonce) — the EK/AK material the backend needs to
// run V2 (EK-chain), V11 (AK restricted-signing + Name==akName) and V12 (algo),
// then issue a nonce + a software MakeCredential challenge bound to akName.
type NonceRequest struct {
	EnrollmentToken string   `json:"enrollmentToken"`
	EKCert          string   `json:"ekCert"`
	EKCertChain     []string `json:"ekCertChain,omitempty"`
	EKPub           string   `json:"ekPub"`
	AKPub           string   `json:"akPub"`
	AKName          string   `json:"akName"`
}

// AttestChallenge is the leg-1 response: the issued nonce + the MakeCredential
// challenge (credBlob ‖ encSecret) the device must ActivateCredential to prove
// the AK is resident on the same TPM as the EK (V10).
type AttestChallenge struct {
	NonceID   string `json:"nonceId"`
	Nonce     string `json:"nonce"`
	CredBlob  string `json:"credBlob"`
	EncSecret string `json:"encSecret"`
}

// AttestEnvelope is leg 2 (POST /attest) — the full attestation: the recovered
// activation secret (V10), a TPM2_Quote over the nonce (V5) + PCRs (V6), a
// TPM2_Certify of the device key by the AK (V4), and the device-key CSR (V9)
// that Vault signs on success.
type AttestEnvelope struct {
	Schema          string                       `json:"schema"`
	EnrollmentToken string                       `json:"enrollmentToken"`
	DeviceRef       string                       `json:"deviceRef"`
	NonceID         string                       `json:"nonceId"`
	EKCert          string                       `json:"ekCert"`
	EKCertChain     []string                     `json:"ekCertChain,omitempty"`
	AKPub           string                       `json:"akPub"`
	AKName          string                       `json:"akName"`
	ActivatedSecret string                       `json:"activatedSecret"`
	CertifyInfo     string                       `json:"certifyInfo"`
	CertifySig      string                       `json:"certifySig"`
	Quote           string                       `json:"quote"`
	QuoteSig        string                       `json:"quoteSig"`
	PCRs            map[string]map[string]string `json:"pcrs,omitempty"`
	DeviceKeyPub    string                       `json:"deviceKeyPub"`
	CSRDer          string                       `json:"csrDer"`
}

// AttestResponse is the leg-2 success body: the Vault-PKI issued clientAuth
// certificate (PEM) for the attested TPM-resident device key.
type AttestResponse struct {
	Certificate string `json:"certificate"`
}
