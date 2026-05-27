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
// Wire contract is snake_case (backend Katman 2 must use
// PropertyNamingStrategies.SNAKE_CASE or @JsonProperty) — Codex F12 absorb.
package autoenroll

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
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

// OSInfo is the os-shape payload submitted on auto-enroll. Snake_case wire
// per Codex F12 absorb.
type OSInfo struct {
	OSType       string `json:"os_type"`
	OSVersion    string `json:"os_version,omitempty"`
	Architecture string `json:"architecture"`
}

// AutoEnrollRequest is the POST /endpoint-enrollments/auto body. Identity is
// NOT carried in the body — the backend derives it from the client cert
// (ADR-0029 Katman 2). Only host self-description travels in JSON.
type AutoEnrollRequest struct {
	OSInfo       OSInfo `json:"os_info"`
	AgentVersion string `json:"agent_version"`
}

// AutoEnrollResponse is the backend response. The service_token is
// cert-bound (its validity requires the same mTLS cert in the TLS handshake
// — token alone is not sufficient).
type AutoEnrollResponse struct {
	DeviceID         string    `json:"device_id"`
	ServiceToken     string    `json:"service_token"`
	TokenExpiresAt   time.Time `json:"token_expires_at"`
	IsExistingDevice bool      `json:"is_existing_device"`
	ServerTime       time.Time `json:"server_time,omitempty"`
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

// HeartbeatRequest mirrors the existing protocol.HeartbeatRequest shape but
// uses snake_case for the auto-enroll wire and omits agent-id-style fields
// (cert provides identity).
type HeartbeatRequest struct {
	Hostname     string    `json:"hostname"`
	OSType       string    `json:"os_type"`
	Architecture string    `json:"architecture"`
	AgentVersion string    `json:"agent_version"`
	OSVersion    string    `json:"os_version,omitempty"`
	State        string    `json:"state"`
	Capabilities []string  `json:"capabilities"`
	Timestamp    time.Time `json:"timestamp"`
}

// HeartbeatResponse carries the optional CRL-outage grace window signal from
// the backend (ADR-0029 R24 bounded formula). grace_until is the
// backend-computed deadline; the agent does NOT recompute it (Codex Q4
// absorb), it only enforces server_time > grace_until → fail-closed, plus
// local NotAfter as defense-in-depth.
type HeartbeatResponse struct {
	Accepted    bool       `json:"accepted"`
	DeviceID    string     `json:"device_id,omitempty"`
	Status      string     `json:"status"`
	ServerTime  time.Time  `json:"server_time"`
	GraceWindow bool       `json:"grace_window,omitempty"`
	GraceUntil  *time.Time `json:"grace_until,omitempty"`
}

// AgentCommand and CommandResult wire shapes are reused from the existing
// protocol package (paths and signing differ, but the payload schema is
// identical — saf JSON, HMAC alanı yok).
