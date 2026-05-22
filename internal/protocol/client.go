package protocol

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"platform-agent/internal/security"
)

// ErrNoCommand is returned by NextCommand when the backend has no command
// queued (HTTP 204).
var ErrNoCommand = errors.New("no command available")

// Client is the agent's HTTP client for the endpoint-admin-service agent API.
// BE-011: it dials the gateway's external /api/v1/endpoint-agent route but
// signs the backend-visible /api/v1/agent canonical path.
type Client struct {
	baseURL       *url.URL // external base, e.g. https://host/api/v1/endpoint-agent
	signingPrefix string   // backend-visible path prefix, e.g. /api/v1/agent
	httpClient    *http.Client
	credentialID  string // X-Device-Credential-Id
	secret        string // device HMAC key
	deviceID      string
	now           func() time.Time
}

// NewClient builds a Client. baseURL is the external API base the agent dials
// (normally under /api/v1/endpoint-agent). signingPathPrefix is the
// backend-visible path prefix used for HMAC signing; when empty it is derived
// from baseURL via DeriveSigningPathPrefix.
func NewClient(baseURL, signingPathPrefix string, httpClient *http.Client) (*Client, error) {
	parsed, err := url.Parse(strings.TrimRight(baseURL, "/"))
	if err != nil {
		return nil, fmt.Errorf("parse api url: %w", err)
	}
	if parsed.Scheme == "" || parsed.Host == "" {
		return nil, fmt.Errorf("api url must include scheme and host")
	}
	prefix := strings.TrimSpace(signingPathPrefix)
	if prefix == "" {
		prefix = DeriveSigningPathPrefix(parsed.Path)
	}
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 30 * time.Second}
	}
	return &Client{
		baseURL:       parsed,
		signingPrefix: strings.TrimRight(prefix, "/"),
		httpClient:    httpClient,
		now:           time.Now,
	}, nil
}

// SetIdentity sets the device credential used to sign subsequent requests.
func (c *Client) SetIdentity(credentialID, secret, deviceID string) {
	c.credentialID = strings.TrimSpace(credentialID)
	c.secret = strings.TrimSpace(secret)
	c.deviceID = strings.TrimSpace(deviceID)
}

// CredentialID returns the device-credential key id (X-Device-Credential-Id).
func (c *Client) CredentialID() string { return c.credentialID }

// DeviceID returns the enrolled device id.
func (c *Client) DeviceID() string { return c.deviceID }

// SigningPathPrefix returns the backend-visible path prefix used for HMAC
// signing (exposed for diagnostics and tests).
func (c *Client) SigningPathPrefix() string { return c.signingPrefix }

// IsEnrolled reports whether the client holds a device credential.
func (c *Client) IsEnrolled() bool {
	return c.credentialID != "" && c.secret != ""
}

// Enroll consumes an enrollment token and, on success, installs the returned
// device credential into the client.
func (c *Client) Enroll(ctx context.Context, request EnrollRequest) (EnrollResponse, error) {
	var response EnrollResponse
	if err := c.do(ctx, reqEnroll, "", request, &response); err != nil {
		return EnrollResponse{}, err
	}
	c.SetIdentity(response.CredentialKeyID, response.Secret, response.DeviceID)
	return response, nil
}

// Heartbeat sends a signed heartbeat.
func (c *Client) Heartbeat(ctx context.Context, request HeartbeatRequest) (HeartbeatResponse, error) {
	var response HeartbeatResponse
	if err := c.do(ctx, reqHeartbeat, "", request, &response); err != nil {
		return HeartbeatResponse{}, err
	}
	return response, nil
}

// NextCommand polls for the next queued command. It returns ErrNoCommand when
// the backend responds 204.
func (c *Client) NextCommand(ctx context.Context) (AgentCommand, error) {
	var response AgentCommand
	err := c.do(ctx, reqNextCommand, "", nil, &response)
	if errors.Is(err, ErrNoCommand) {
		return AgentCommand{}, ErrNoCommand
	}
	if err != nil {
		return AgentCommand{}, err
	}
	return response, nil
}

// SubmitResult reports a command result. commandId is the URL path segment;
// claimId travels in the body and is mandatory.
func (c *Client) SubmitResult(ctx context.Context, result CommandResult) error {
	if strings.TrimSpace(result.CommandID) == "" {
		return fmt.Errorf("command result is missing a command id")
	}
	if strings.TrimSpace(result.ClaimID) == "" {
		// BE-011: the backend requires claimId (@NotBlank). A result with no
		// claim id can never be accepted — fail fast rather than POST it.
		return fmt.Errorf("command result is missing a claim id")
	}
	return c.do(ctx, reqCommandResult(result.CommandID), "", result.ToWire(), nil)
}

// do executes one agent request. It dials the external path and, when the
// request is signed, covers the backend-visible canonical path with an HMAC
// signature.
func (c *Client) do(ctx context.Context, spec agentRequest, query string, payload, out interface{}) error {
	body, err := marshalBody(payload)
	if err != nil {
		return err
	}

	dialURL := c.baseURL.String() + spec.suffix
	if query != "" {
		dialURL += "?" + query
	}
	request, err := http.NewRequestWithContext(ctx, spec.method, dialURL, bodyReader(body))
	if err != nil {
		return err
	}
	request.Header.Set("Accept", "application/json")
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if spec.signed {
		if err := c.sign(request, spec.suffix, query, body); err != nil {
			return err
		}
	}

	response, err := c.httpClient.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()

	if response.StatusCode == http.StatusNoContent {
		return ErrNoCommand
	}
	if response.StatusCode < 200 || response.StatusCode > 299 {
		data, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
		return fmt.Errorf("%s %s returned %d: %s",
			spec.method, spec.suffix, response.StatusCode, strings.TrimSpace(string(data)))
	}
	if out == nil {
		io.Copy(io.Discard, response.Body)
		return nil
	}
	return json.NewDecoder(response.Body).Decode(out)
}

// sign covers the request with the device-credential HMAC that the backend's
// DeviceCredentialAuthenticationFilter verifies. The canonical string uses the
// backend-visible /api/v1/agent path (signingPrefix + suffix), NOT the dialed
// /api/v1/endpoint-agent path, because the gateway rewrites the path before
// the backend computes its own canonical string.
func (c *Client) sign(request *http.Request, suffix, query string, body []byte) error {
	if !c.IsEnrolled() {
		return fmt.Errorf("device credential is required for a signed request")
	}
	timestamp := c.now().UTC().Format(time.RFC3339Nano)
	nonce, err := randomNonce()
	if err != nil {
		return err
	}
	canonicalPath := c.signingPrefix + suffix
	canonical := security.CanonicalRequest(
		request.Method, canonicalPath, query, timestamp, nonce, security.BodyHashHex(body))
	request.Header.Set("X-Device-Credential-Id", c.credentialID)
	request.Header.Set("X-Request-Timestamp", timestamp)
	request.Header.Set("X-Request-Nonce", nonce)
	request.Header.Set("X-Signature", security.Sign(c.secret, canonical))
	return nil
}

func marshalBody(payload interface{}) ([]byte, error) {
	if payload == nil {
		return nil, nil
	}
	return json.Marshal(payload)
}

func bodyReader(body []byte) io.Reader {
	if body == nil {
		return nil
	}
	return bytes.NewReader(body)
}

func randomNonce() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}
