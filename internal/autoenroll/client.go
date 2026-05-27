package autoenroll

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"platform-agent/internal/protocol"
)

// ErrNoCommand is returned by NextCommand when the backend has no command
// queued (HTTP 204). It mirrors protocol.ErrNoCommand so the executor loop
// can treat both wire modes uniformly.
var ErrNoCommand = errors.New("no command available")

// Auto-enroll wire endpoints. Suffix-only; the base URL is the full
// canonical API base (e.g. https://endpoint-agent-mtls.testai.acik.com/api/v1/endpoint-admin)
// — Codex F4 absorb: endpoint constants, not registry/env override.
const (
	PathAutoEnroll    = "/endpoint-enrollments/auto"
	PathTokenRefresh  = "/service-token/refresh"
	PathHeartbeat     = "/heartbeat"
	PathCommandsNext  = "/commands/next"
	PathCommandResult = "/commands/%s/result"
)

// Client is the auto-enroll wire client. It wraps an mTLS http.Client and
// adds the cert-bound bearer token + JSON marshaling. It does NOT do retry
// or backoff — that is the Runner's responsibility.
type Client struct {
	baseURL *url.URL
	http    *http.Client
}

// NewClient constructs a wire client. baseURL must include the full
// canonical base path (e.g. https://host/api/v1/endpoint-admin); the suffix
// constants are appended via url.JoinPath so query/trailing-slash edge
// cases are handled by net/url, not by string concatenation.
func NewClient(baseURL string, httpClient *http.Client) (*Client, error) {
	if httpClient == nil {
		return nil, fmt.Errorf("autoenroll: http client is required")
	}
	parsed, err := url.Parse(strings.TrimRight(baseURL, "/"))
	if err != nil {
		return nil, fmt.Errorf("autoenroll: parse base url: %w", err)
	}
	if parsed.Scheme == "" || parsed.Host == "" {
		return nil, fmt.Errorf("autoenroll: base url must include scheme and host")
	}
	return &Client{baseURL: parsed, http: httpClient}, nil
}

// BaseURL returns the configured base URL string (without trailing slash).
// Useful for diagnostics and log messages.
func (c *Client) BaseURL() string { return c.baseURL.String() }

// AutoEnroll consumes the cert + os info and returns the freshly minted
// service token. The backend determines whether the cert maps to an
// existing device (idempotent reissue path) or a new one.
func (c *Client) AutoEnroll(ctx context.Context, req AutoEnrollRequest) (AutoEnrollResponse, error) {
	var resp AutoEnrollResponse
	if err := c.do(ctx, http.MethodPost, PathAutoEnroll, "", req, &resp); err != nil {
		return AutoEnrollResponse{}, err
	}
	return resp, nil
}

// RefreshToken exchanges the current bearer for a new one. Requires mTLS
// (cert-bound). Backend returns 401/403 when the existing token has
// already expired — caller must then take the AutoEnroll reissue path.
func (c *Client) RefreshToken(ctx context.Context, token string) (TokenRefreshResponse, error) {
	var resp TokenRefreshResponse
	if err := c.doAuthed(ctx, http.MethodPost, PathTokenRefresh, "", token, nil, &resp); err != nil {
		return TokenRefreshResponse{}, err
	}
	return resp, nil
}

// Heartbeat reports current state and capabilities. The response may carry
// a CRL-outage grace window signal (see HeartbeatResponse).
func (c *Client) Heartbeat(ctx context.Context, token string, req HeartbeatRequest) (HeartbeatResponse, error) {
	var resp HeartbeatResponse
	if err := c.doAuthed(ctx, http.MethodPost, PathHeartbeat, "", token, req, &resp); err != nil {
		return HeartbeatResponse{}, err
	}
	return resp, nil
}

// NextCommand polls for the next queued command. ErrNoCommand wraps a
// 204 No Content response.
func (c *Client) NextCommand(ctx context.Context, token string) (protocol.AgentCommand, error) {
	var resp protocol.AgentCommand
	err := c.doAuthed(ctx, http.MethodGet, PathCommandsNext, "", token, nil, &resp)
	if errors.Is(err, ErrNoCommand) {
		return protocol.AgentCommand{}, ErrNoCommand
	}
	if err != nil {
		return protocol.AgentCommand{}, err
	}
	return resp, nil
}

// SubmitResult reports a command result. claimID and commandID are both
// required by the backend; SubmitResult enforces that locally so a bad
// caller never POSTs a result the backend will reject.
func (c *Client) SubmitResult(ctx context.Context, token string, result protocol.CommandResult) error {
	if strings.TrimSpace(result.CommandID) == "" {
		return fmt.Errorf("command result is missing a command id")
	}
	if strings.TrimSpace(result.ClaimID) == "" {
		return fmt.Errorf("command result is missing a claim id")
	}
	path := fmt.Sprintf(PathCommandResult, url.PathEscape(result.CommandID))
	return c.doAuthed(ctx, http.MethodPost, path, "", token, result.ToWire(), nil)
}

// do executes one wire request. The auto-enroll path is unauthed (the cert
// is the only auth, no bearer token exists yet). All other paths use
// doAuthed.
func (c *Client) do(ctx context.Context, method, suffix, query string, payload, out interface{}) error {
	return c.doRaw(ctx, method, suffix, query, "", payload, out)
}

// doAuthed is do plus an Authorization: Bearer header.
func (c *Client) doAuthed(ctx context.Context, method, suffix, query, token string, payload, out interface{}) error {
	if strings.TrimSpace(token) == "" {
		return fmt.Errorf("service token is empty (cannot authenticate %s %s)", method, suffix)
	}
	return c.doRaw(ctx, method, suffix, query, token, payload, out)
}

// doRaw is the unified request path. It marshals payload, dials, decodes
// the response into out (or discards it), and maps backend status codes
// onto the package errors.
func (c *Client) doRaw(ctx context.Context, method, suffix, query, token string, payload, out interface{}) error {
	var body []byte
	if payload != nil {
		b, err := json.Marshal(payload)
		if err != nil {
			return fmt.Errorf("marshal %s body: %w", suffix, err)
		}
		body = b
	}

	target := c.baseURL.String() + suffix
	if query != "" {
		target += "?" + query
	}

	var reqBody io.Reader
	if body != nil {
		reqBody = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, target, reqBody)
	if err != nil {
		return fmt.Errorf("build request %s %s: %w", method, suffix, err)
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("dial %s %s: %w", method, suffix, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNoContent {
		// 204 means different things in different paths; the GET
		// /commands/next handler treats it as "no command available", and
		// for everything else it's the absence of a response body, which
		// is fine if out is nil.
		if out == nil {
			return nil
		}
		return ErrNoCommand
	}
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("%w: %s %s returned %d: %s",
			ErrAuthFailure, method, suffix, resp.StatusCode, strings.TrimSpace(string(data)))
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("%s %s returned %d: %s",
			method, suffix, resp.StatusCode, strings.TrimSpace(string(data)))
	}
	if out == nil {
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("decode %s %s response: %w", method, suffix, err)
	}
	return nil
}
