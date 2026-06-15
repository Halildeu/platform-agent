// Package autoenroll implements the --auto-enroll mode for the endpoint
// agent: mTLS-continuous self-enrollment against the backend
// endpoint-admin-service auto-enroll endpoint, as defined in ADR-0029
// (Faz 22.3 mass deployment, Plan A).
//
// The auto-enroll mode is wire-incompatible with the existing HMAC-signed
// mode (internal/app + internal/protocol). It runs as a separate Runner and
// must never fall back to the HMAC path — fail-closed is the only valid
// behaviour on auth/cert/token failure (Codex F2/F11 absorb).
//
// Wire contract is default-Jackson camelCase: the backend DTOs on this path
// (AutoEnrollmentRequest, ConsumeEnrollmentRequest) are flat Java records with
// no @JsonNaming and the service sets no global SNAKE_CASE strategy, so JSON
// keys MUST be camelCase and match the Java field names exactly (#149). The
// earlier "F12 snake_case" assumption was never accepted by the backend — it
// produced a live 400 VALIDATION_ERROR because no @NotBlank field bound.
package autoenroll

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"
	"time"
)

// ErrNoCertMatch is returned when the cert store has no certificate that
// satisfies the configured CertFilter.
var ErrNoCertMatch = errors.New("no eligible machine certificate found")

// ErrUnsupportedOS is returned by Windows primitives on non-Windows builds.
var ErrUnsupportedOS = errors.New("auto-enroll requires Windows machine certificate store and DPAPI")

// ErrAuthFailure indicates the backend rejected the cert or service token
// (HTTP 401/403). The agent must fail-closed; automatic re-enrollment from
// this state is forbidden — Codex F11 absorb (revocation bypass risk).
var ErrAuthFailure = errors.New("backend rejected cert or service token (fail-closed)")

// ErrTokenlessLifecycleUnsupported is returned when a legacy token-dependent
// step (refresh / bearer heartbeat / bearer command poll / bearer result
// submit) is reached without a bearer token. In the ADR-0029 M2 canonical
// model enrollment is tokenless and uses dedicated cert-auth heartbeat and
// command paths; reaching a legacy bearer step with an empty token means a
// caller bypassed the tokenless guard, so fail closed rather than send an
// empty Bearer.
var ErrTokenlessLifecycleUnsupported = errors.New("tokenless mTLS enrollment: token-dependent lifecycle not supported (#151)")

// CertFilter narrows the cert-store query to a single eligible machine
// certificate. Template identity, issuer, and revocation are deliberately NOT
// part of the agent filter — those checks are the backend's responsibility
// (Codex F1 absorb). The agent only proves possession of a cert with the
// right shape; the backend decides whether that cert represents an enrolled
// device.
type CertFilter struct {
	// EKU is the dotted-OID for the Extended Key Usage the cert must carry.
	// Default: "1.3.6.1.5.5.7.3.2" (Client Authentication).
	EKU string

	// SubjectSuffix, when non-empty, requires the cert Subject CN to end with
	// this string (case-insensitive). Used as disambiguation in stores that
	// hold multiple Client Authentication certs.
	SubjectSuffix string

	// SANURIPrefix, when non-empty, requires the cert to carry a SAN URI
	// starting with this prefix (e.g. "adcomputer:" for AD CS template-bound
	// stable identity per ADR-0029 Katman 1).
	SANURIPrefix string

	// Issuers, when non-empty, scopes the Windows cert store lookup to
	// certificates issued by one of these subject DNs. Used by the
	// certtostore-backed Windows provider as the FindIssuerStr filter; the
	// agent CertFilter does NOT treat issuer match as a security gate —
	// that remains the backend's job (Codex F1 absorb). Setting Issuers
	// helps when LocalMachine\My holds many corp certs and the agent
	// wants to skip non-AD-CS chains during enumeration.
	Issuers []string

	// RequirePrivateKey requires that the cert handle expose a usable
	// crypto.Signer. The Windows implementation guarantees the signer is
	// backed by the original (possibly non-exportable) key — Codex F7
	// absorb.
	RequirePrivateKey bool

	// RequireValidNow requires NotBefore <= now < NotAfter.
	RequireValidNow bool
}

// DefaultCertFilter returns the production default: Client Authentication
// EKU + private key required + valid time required + no subject/SAN
// disambiguation.
func DefaultCertFilter() CertFilter {
	return CertFilter{
		EKU:               "1.3.6.1.5.5.7.3.2",
		RequirePrivateKey: true,
		RequireValidNow:   true,
	}
}

// CertMaterial is the loaded cert handle, ready to be plugged into a
// tls.Config. The TLSCertificate.PrivateKey MUST be a crypto.Signer; the
// Windows implementation returns a signer that calls NCryptSignHash via CNG,
// so non-exportable TPM-backed keys work — Codex F7 absorb.
type CertMaterial struct {
	TLSCertificate   tls.Certificate
	Leaf             *x509.Certificate
	ThumbprintSHA256 string // canonical for token binding and audit (Codex F10)
	ThumbprintSHA1   string // diagnostic only (Windows UI cross-reference)
}

// AutoEnrollRequest is the POST /endpoint-enrollments/auto body. Device
// identity is proven by the mTLS client cert (the SAN URI), NOT by this body
// (ADR-0029 Katman 2) — the backend treats hostname/fingerprint as secondary,
// informational fields. The shape MUST match backend AutoEnrollmentRequest
// (com.example.endpointadmin.dto.v1.agent): a FLAT record with camelCase JSON
// keys where machineFingerprint, hostname, osName and agentVersion are
// @NotBlank and osVersion/osBuild/domain/architecture/schemaVersion are
// optional. #149: a previous nested snake_case shape ({os_info{...},
// agent_version}) 400'd because none of the @NotBlank fields bound.
type AutoEnrollRequest struct {
	MachineFingerprint string `json:"machineFingerprint"`
	Hostname           string `json:"hostname"`
	OSName             string `json:"osName"`
	OSVersion          string `json:"osVersion,omitempty"`
	OSBuild            string `json:"osBuild,omitempty"`
	Domain             string `json:"domain,omitempty"`
	Architecture       string `json:"architecture,omitempty"`
	AgentVersion       string `json:"agentVersion"`
	SchemaVersion      int    `json:"schemaVersion,omitempty"`
}

// AutoEnrollResponse mirrors backend AutoEnrollmentResponse (camelCase). It is
// a TOKENLESS enrollment confirmation (ADR-0029 M2): the mTLS client cert is
// the continuous credential, so there is NO bearer/service token in the
// response. status is "enrolled" (HTTP 201, fresh device+cert) or
// "already-enrolled" (HTTP 200, idempotent repeat of an active cert).
type AutoEnrollResponse struct {
	DeviceID   string             `json:"deviceId"`
	Status     string             `json:"status"`
	EnrolledAt time.Time          `json:"enrolledAt"`
	CertInfo   AutoEnrollCertInfo `json:"certInfo"`
}

// AutoEnrollCertInfo mirrors backend AutoEnrollmentResponse.CertInfo — the
// server's view of the cert it bound to the device. thumbprint is a
// lowercase-hex SHA-256 over the DER cert (HexFormat.of().formatHex), the
// same canonical form the agent computes via ThumbprintSHA256Hex.
type AutoEnrollCertInfo struct {
	SANURI     string    `json:"sanUri"`
	ObjectGUID string    `json:"objectGuid"`
	Thumbprint string    `json:"thumbprint"`
	NotAfter   time.Time `json:"notAfter"`
}

const (
	// StatusEnrolled / StatusAlreadyEnrolled are the only backend
	// AutoEnrollmentResponse.status values (201 fresh / 200 idempotent).
	StatusEnrolled        = "enrolled"
	StatusAlreadyEnrolled = "already-enrolled"
)

// ErrInvalidEnrollResponse is returned by AutoEnrollResponse.Validate when the
// decoded /auto response violates the tokenless contract. The runner treats it
// as fatal for the reconcile — a drifted/forged response must not be persisted.
var ErrInvalidEnrollResponse = errors.New("auto-enroll response invalid")

// Validate enforces the tokenless /auto response contract (#149): a usable
// enrollment confirmation must carry a device id, a recognised status, and a
// cert thumbprint that MATCHES the cert the agent actually presented on the
// mTLS handshake. The thumbprint match is a fail-closed proof the backend
// enrolled THIS cert; both sides are lowercase-hex DER SHA-256 so the compare
// is exact after normalisation.
func (r AutoEnrollResponse) Validate(localThumbprintSHA256 string) error {
	if strings.TrimSpace(r.DeviceID) == "" {
		return fmt.Errorf("%w: response deviceId empty", ErrInvalidEnrollResponse)
	}
	if r.Status != StatusEnrolled && r.Status != StatusAlreadyEnrolled {
		return fmt.Errorf("%w: unexpected status %q", ErrInvalidEnrollResponse, r.Status)
	}
	got := normalizeThumbprint(r.CertInfo.Thumbprint)
	if got == "" {
		return fmt.Errorf("%w: response cert thumbprint empty", ErrInvalidEnrollResponse)
	}
	// Contract: the backend thumbprint MUST equal the cert the agent
	// presented. An empty local thumbprint means there is nothing to bind
	// against — fail closed rather than skip the proof.
	want := normalizeThumbprint(localThumbprintSHA256)
	if want == "" {
		return fmt.Errorf("%w: no local cert thumbprint to match the response against", ErrInvalidEnrollResponse)
	}
	if got != want {
		return fmt.Errorf("%w: response cert thumbprint does not match presented cert", ErrInvalidEnrollResponse)
	}
	return nil
}

// normalizeThumbprint canonicalises a hex thumbprint for comparison: lowercase,
// no colon/space separators. Agent (hex.EncodeToString) and backend
// (HexFormat.of) already emit this form; normalisation is defence against an
// upstream that inserts colons or uppercases.
func normalizeThumbprint(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.ReplaceAll(s, ":", "")
	s = strings.ReplaceAll(s, " ", "")
	return s
}

// TokenRefreshResponse is the backend response to
// POST /service-token/refresh. The refresh must be performed over the same
// mTLS cert; an expired refresh window forces the agent into the idempotent
// auto-enroll reissue path (Codex F11 absorb).
type TokenRefreshResponse struct {
	ServiceToken   string    `json:"service_token"`
	TokenExpiresAt time.Time `json:"token_expires_at"`
	ServerTime     time.Time `json:"server_time,omitempty"`
}

// HeartbeatRequest mirrors backend AgentHeartbeatRequest and omits
// agent-id-style fields because the cert (or legacy HMAC credential) provides
// identity. The backend Java record uses default Jackson camelCase, so these
// tags intentionally match internal/protocol.HeartbeatRequest.
type HeartbeatRequest struct {
	Hostname     string    `json:"hostname"`
	OSType       string    `json:"osType"`
	Architecture string    `json:"architecture"`
	AgentVersion string    `json:"agentVersion"`
	OSVersion    string    `json:"osVersion,omitempty"`
	State        string    `json:"state"`
	Capabilities []string  `json:"capabilities"`
	Timestamp    time.Time `json:"timestamp"`
}

// HeartbeatResponse carries the optional CRL-outage grace window signal from
// the backend (ADR-0029 R24 bounded formula). grace_until is the
// backend-computed deadline; the agent does NOT recompute it (Codex Q4
// absorb), it only enforces serverTime > graceUntil → fail-closed, plus local
// NotAfter as defense-in-depth.
type HeartbeatResponse struct {
	Accepted    bool       `json:"accepted"`
	DeviceID    string     `json:"deviceId,omitempty"`
	Status      string     `json:"status"`
	ServerTime  time.Time  `json:"serverTime"`
	GraceWindow bool       `json:"graceWindow,omitempty"`
	GraceUntil  *time.Time `json:"graceUntil,omitempty"`
}

// AgentCommand and CommandResult wire shapes are reused from the existing
// protocol package (paths and signing differ, but the payload schema is
// identical — saf JSON, HMAC alanı yok).
