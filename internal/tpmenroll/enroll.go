package tpmenroll

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// Client is the agent-side 4-leg TPM enrollment wire client. It wraps an mTLS
// http.Client (the bootstrap transport) and joins the endpoint suffixes onto the
// canonical agent API base (e.g. https://host/api/v1/agent). It does no retry —
// that is the caller's / a later retry-wrapper's concern.
type Client struct {
	baseURL *url.URL
	http    *http.Client
}

// NewClient constructs the wire client. baseURL must include scheme+host and must
// NOT carry a query/fragment (suffixes are joined via url.JoinPath).
func NewClient(baseURL string, httpClient *http.Client) (*Client, error) {
	if httpClient == nil {
		return nil, fmt.Errorf("tpmenroll: http client is required")
	}
	parsed, err := url.Parse(strings.TrimRight(baseURL, "/"))
	if err != nil {
		return nil, fmt.Errorf("tpmenroll: parse base url: %w", err)
	}
	if parsed.Scheme == "" || parsed.Host == "" {
		return nil, fmt.Errorf("tpmenroll: base url must include scheme and host")
	}
	if parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, fmt.Errorf("tpmenroll: base url must not carry query or fragment")
	}
	return &Client{baseURL: parsed, http: httpClient}, nil
}

// EnrollOptions parameterizes one enrollment attempt.
type EnrollOptions struct {
	EnrollmentToken string         // the bootstrap token (server re-derives tenant/device)
	DeviceRef       string         // an opaque device reference (<=256), e.g. hostname
	PCRSelections   []PCRSelection // optional; the backend V6 PCR policy is opt-in
	SubjectCN       string         // CSR subject CN (defaults to DeviceRef)
}

// Enroll runs the 4-leg TPM attestation enrollment against the backend, driving
// the TPMDevice, and returns the issued client-cert PEM on success:
//
//	leg 1  POST /nonce  : EK/AK material → nonce + MakeCredential challenge
//	(device) ActivateCredential → recovered secret (one-TPM proof)
//	(device) Quote(nonce) + CertifyDeviceKey + CSR(deviceKey)
//	leg 2  POST /attest : the full attestation → Vault-PKI issued certificate
//
// The private keys never leave the device; only public areas, the recovered
// secret, attestations, and the CSR are sent.
func (c *Client) Enroll(ctx context.Context, tpm TPMDevice, opts EnrollOptions) (string, error) {
	if opts.EnrollmentToken == "" {
		return "", fmt.Errorf("tpmenroll: enrollment token required")
	}
	ekPub, ekCert, ekChain, err := tpm.EndorsementKey()
	if err != nil {
		return "", fmt.Errorf("tpmenroll: endorsement key: %w", err)
	}
	akPub, akName, err := tpm.AttestationKey()
	if err != nil {
		return "", fmt.Errorf("tpmenroll: attestation key: %w", err)
	}

	challenge, err := c.postNonce(ctx, NonceRequest{
		EnrollmentToken: opts.EnrollmentToken,
		EKCert:          b64(ekCert),
		EKCertChain:     b64Each(ekChain),
		EKPub:           b64(ekPub),
		AKPub:           b64(akPub),
		AKName:          b64(akName),
	})
	if err != nil {
		return "", err
	}

	credBlob, err := base64.StdEncoding.DecodeString(challenge.CredBlob)
	if err != nil {
		return "", fmt.Errorf("tpmenroll: decode credBlob: %w", err)
	}
	encSecret, err := base64.StdEncoding.DecodeString(challenge.EncSecret)
	if err != nil {
		return "", fmt.Errorf("tpmenroll: decode encSecret: %w", err)
	}
	secret, err := tpm.ActivateCredential(credBlob, encSecret)
	if err != nil {
		return "", fmt.Errorf("tpmenroll: activate credential: %w", err)
	}

	nonce, err := base64.StdEncoding.DecodeString(challenge.Nonce)
	if err != nil {
		return "", fmt.Errorf("tpmenroll: decode nonce: %w", err)
	}
	quote, quoteSig, err := tpm.Quote(nonce, opts.PCRSelections)
	if err != nil {
		return "", fmt.Errorf("tpmenroll: quote: %w", err)
	}
	// qualifyingData binds the certify to this session's nonce (the backend V4
	// checks certifiedName, not extraData, but binding the nonce is defense-in-depth).
	certify, certifySig, err := tpm.CertifyDeviceKey(nonce)
	if err != nil {
		return "", fmt.Errorf("tpmenroll: certify device key: %w", err)
	}
	deviceKeyPub, err := tpm.DeviceKey()
	if err != nil {
		return "", fmt.Errorf("tpmenroll: device key: %w", err)
	}
	cn := opts.SubjectCN
	if cn == "" {
		cn = opts.DeviceRef
	}
	csrDer, err := buildDeviceCSR(tpm.DeviceKeySigner(), cn)
	if err != nil {
		return "", fmt.Errorf("tpmenroll: build CSR: %w", err)
	}

	resp, err := c.postAttest(ctx, AttestEnvelope{
		Schema:          SchemaV2,
		EnrollmentToken: opts.EnrollmentToken,
		DeviceRef:       opts.DeviceRef,
		NonceID:         challenge.NonceID,
		EKCert:          b64(ekCert),
		EKCertChain:     b64Each(ekChain),
		AKPub:           b64(akPub),
		AKName:          b64(akName),
		ActivatedSecret: b64(secret),
		CertifyInfo:     b64(certify),
		CertifySig:      b64(certifySig),
		Quote:           b64(quote),
		QuoteSig:        b64(quoteSig),
		DeviceKeyPub:    b64(deviceKeyPub),
		CSRDer:          b64(csrDer),
	})
	if err != nil {
		return "", err
	}
	if resp.Certificate == "" {
		return "", fmt.Errorf("tpmenroll: backend returned an empty certificate")
	}
	return resp.Certificate, nil
}

func (c *Client) postNonce(ctx context.Context, req NonceRequest) (*AttestChallenge, error) {
	var out AttestChallenge
	if err := c.postJSON(ctx, PathTPMNonce, req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) postAttest(ctx context.Context, env AttestEnvelope) (*AttestResponse, error) {
	var out AttestResponse
	if err := c.postJSON(ctx, PathTPMAttest, env, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) postJSON(ctx context.Context, suffix string, body, out any) error {
	u, err := url.JoinPath(c.baseURL.String(), suffix)
	if err != nil {
		return fmt.Errorf("tpmenroll: join url: %w", err)
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("tpmenroll: marshal request: %w", err)
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("tpmenroll: new request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")
	resp, err := c.http.Do(httpReq)
	if err != nil {
		return fmt.Errorf("tpmenroll: POST %s: %w", suffix, err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		// The backend returns a uniform 403 with a {"status":"denied"} body on any
		// verifier failure; surface the status (the deny reason is audit-only server-side).
		return fmt.Errorf("tpmenroll: POST %s returned %d: %s", suffix, resp.StatusCode, strings.TrimSpace(string(respBody)))
	}
	if err := json.Unmarshal(respBody, out); err != nil {
		return fmt.Errorf("tpmenroll: decode %s response: %w", suffix, err)
	}
	return nil
}

// oidExtKeyUsage (2.5.29.37) and oidClientAuth (1.3.6.1.5.5.7.3.2) — the backend
// V9 CSR policy requires the requested EKU to be exactly {clientAuth}.
var (
	oidExtKeyUsage = asn1.ObjectIdentifier{2, 5, 29, 37}
	oidClientAuth  = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 2}
)

// buildDeviceCSR builds a PKCS#10 CSR for the TPM-resident device key, requesting
// EKU clientAuth, signed (proof-of-possession) by the device key. Go selects
// SHA-256+withRSA for an RSA-3072 key, satisfying the backend V9 PoP-hash floor.
func buildDeviceCSR(signer crypto.Signer, cn string) ([]byte, error) {
	if signer == nil {
		return nil, fmt.Errorf("tpmenroll: device key signer required")
	}
	ekuValue, err := asn1.Marshal([]asn1.ObjectIdentifier{oidClientAuth})
	if err != nil {
		return nil, err
	}
	tmpl := &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: cn},
		ExtraExtensions: []pkix.Extension{
			{Id: oidExtKeyUsage, Value: ekuValue},
		},
	}
	return x509.CreateCertificateRequest(rand.Reader, tmpl, signer)
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func b64Each(bs [][]byte) []string {
	if len(bs) == 0 {
		return nil
	}
	out := make([]string, len(bs))
	for i, b := range bs {
		out[i] = b64(b)
	}
	return out
}
