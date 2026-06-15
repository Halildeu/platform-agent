package tpmenroll

import (
	"encoding/json"
	"testing"
)

// keys returns the top-level JSON object keys of v marshaled.
func keys(t *testing.T, v any) map[string]bool {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	out := make(map[string]bool, len(m))
	for k := range m {
		out[k] = true
	}
	return out
}

func assertKeys(t *testing.T, got map[string]bool, want ...string) {
	t.Helper()
	for _, k := range want {
		if !got[k] {
			t.Errorf("missing JSON key %q (got %v)", k, got)
		}
	}
}

// The Go DTO JSON keys MUST equal the backend Java record component names
// (Jackson default). A drift here silently breaks enrollment at runtime.
func TestNonceRequest_JSONContract(t *testing.T) {
	got := keys(t, NonceRequest{
		EnrollmentToken: "t", EKCert: "e", EKPub: "ep", AKPub: "ap", AKName: "an",
		EKCertChain: []string{"c"},
	})
	assertKeys(t, got, "enrollmentToken", "ekCert", "ekCertChain", "ekPub", "akPub", "akName")
}

func TestAttestChallenge_JSONContract(t *testing.T) {
	// Decodes a backend-shaped /nonce response.
	const body = `{"nonceId":"n1","nonce":"AAAA","credBlob":"BBBB","encSecret":"CCCC"}`
	var c AttestChallenge
	if err := json.Unmarshal([]byte(body), &c); err != nil {
		t.Fatalf("unmarshal challenge: %v", err)
	}
	if c.NonceID != "n1" || c.Nonce != "AAAA" || c.CredBlob != "BBBB" || c.EncSecret != "CCCC" {
		t.Fatalf("challenge fields not bound: %+v", c)
	}
}

func TestAttestEnvelope_JSONContract(t *testing.T) {
	got := keys(t, AttestEnvelope{
		Schema: SchemaV2, EnrollmentToken: "t", DeviceRef: "d", NonceID: "n",
		EKCert: "e", AKPub: "ap", AKName: "an", ActivatedSecret: "as",
		CertifyInfo: "ci", CertifySig: "cs", Quote: "q", QuoteSig: "qs",
		DeviceKeyPub: "dk", CSRDer: "csr",
		PCRs: map[string]map[string]string{"sha256": {"0": "AA"}},
	})
	assertKeys(t, got,
		"schema", "enrollmentToken", "deviceRef", "nonceId", "ekCert",
		"akPub", "akName", "activatedSecret", "certifyInfo", "certifySig",
		"quote", "quoteSig", "pcrs", "deviceKeyPub", "csrDer")
}

func TestAttestResponse_JSONContract(t *testing.T) {
	const body = `{"certificate":"-----BEGIN CERTIFICATE-----\nMII...\n-----END CERTIFICATE-----"}`
	var r AttestResponse
	if err := json.Unmarshal([]byte(body), &r); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if r.Certificate == "" {
		t.Fatal("certificate not bound")
	}
}

func TestSchemaV2Constant(t *testing.T) {
	if SchemaV2 != "faz22.3b.tpm-attest.v2" {
		t.Fatalf("SchemaV2 = %q", SchemaV2)
	}
}

// omitempty on optional fields must NOT drop required ones; ekCertChain/pcrs are
// the only optional fields (the backend tolerates their absence).
func TestNonceRequest_OmitsOnlyOptional(t *testing.T) {
	got := keys(t, NonceRequest{EnrollmentToken: "t", EKCert: "e", EKPub: "ep", AKPub: "ap", AKName: "an"})
	if got["ekCertChain"] {
		t.Error("empty ekCertChain should be omitted")
	}
	assertKeys(t, got, "enrollmentToken", "ekCert", "ekPub", "akPub", "akName")
}
