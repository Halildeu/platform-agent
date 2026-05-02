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

var ErrNoCommand = errors.New("no command available")

type Client struct {
	baseURL    *url.URL
	httpClient *http.Client
	agentID    string
	secret     string
	installID  string
	now        func() time.Time
}

func NewClient(baseURL string, httpClient *http.Client) (*Client, error) {
	parsed, err := url.Parse(strings.TrimRight(baseURL, "/"))
	if err != nil {
		return nil, fmt.Errorf("parse api url: %w", err)
	}
	if parsed.Scheme == "" || parsed.Host == "" {
		return nil, fmt.Errorf("api url must include scheme and host")
	}
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 30 * time.Second}
	}
	return &Client{
		baseURL:    parsed,
		httpClient: httpClient,
		now:        time.Now,
	}, nil
}

func (c *Client) SetIdentity(agentID string, secret string, installID string) {
	c.agentID = strings.TrimSpace(agentID)
	c.secret = strings.TrimSpace(secret)
	c.installID = strings.TrimSpace(installID)
}

func (c *Client) AgentID() string {
	return c.agentID
}

func (c *Client) InstallID() string {
	return c.installID
}

func (c *Client) Enroll(ctx context.Context, request EnrollRequest) (EnrollResponse, error) {
	var response EnrollResponse
	err := c.doJSON(ctx, http.MethodPost, "/enroll", request, &response, false)
	if err != nil {
		return EnrollResponse{}, err
	}
	c.SetIdentity(response.AgentID, response.AgentSecret, response.InstallID)
	return response, nil
}

func (c *Client) Heartbeat(ctx context.Context, request HeartbeatRequest) (HeartbeatResponse, error) {
	var response HeartbeatResponse
	err := c.doJSON(ctx, http.MethodPost, "/heartbeat", request, &response, true)
	if err != nil {
		return HeartbeatResponse{}, err
	}
	return response, nil
}

func (c *Client) NextCommand(ctx context.Context) (AgentCommand, error) {
	var response AgentCommand
	err := c.doJSON(ctx, http.MethodGet, "/commands/next", nil, &response, true)
	if errors.Is(err, ErrNoCommand) {
		return AgentCommand{}, ErrNoCommand
	}
	if err != nil {
		return AgentCommand{}, err
	}
	return response, nil
}

func (c *Client) SubmitResult(ctx context.Context, result CommandResult) error {
	path := fmt.Sprintf("/commands/%s/result", url.PathEscape(result.CommandID))
	return c.doJSON(ctx, http.MethodPost, path, result, nil, true)
}

func (c *Client) doJSON(ctx context.Context, method string, relativePath string, payload interface{}, out interface{}, signed bool) error {
	body, err := marshalBody(payload)
	if err != nil {
		return err
	}

	endpoint := c.resolve(relativePath)
	request, err := http.NewRequestWithContext(ctx, method, endpoint.String(), bytes.NewReader(body))
	if err != nil {
		return err
	}
	request.Header.Set("Accept", "application/json")
	if payload != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if signed {
		if err := c.sign(request, body); err != nil {
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
		return fmt.Errorf("%s %s returned %d: %s", method, relativePath, response.StatusCode, strings.TrimSpace(string(data)))
	}
	if out == nil {
		io.Copy(io.Discard, response.Body)
		return nil
	}
	return json.NewDecoder(response.Body).Decode(out)
}

func (c *Client) sign(request *http.Request, body []byte) error {
	if c.agentID == "" || c.secret == "" {
		return fmt.Errorf("agent identity is required for signed request")
	}
	timestamp := c.now().UnixMilli()
	nonce, err := randomNonce()
	if err != nil {
		return err
	}
	signature := security.SignRequest(c.secret, request.Method, request.URL.Path, timestamp, nonce, body)
	request.Header.Set("X-Agent-Id", c.agentID)
	request.Header.Set("X-Agent-Timestamp", fmt.Sprintf("%d", timestamp))
	request.Header.Set("X-Agent-Nonce", nonce)
	request.Header.Set("X-Agent-Signature", signature)
	return nil
}

func (c *Client) resolve(relativePath string) *url.URL {
	clone := *c.baseURL
	clone.Path = strings.TrimRight(c.baseURL.Path, "/") + "/" + strings.TrimLeft(relativePath, "/")
	return &clone
}

func marshalBody(payload interface{}) ([]byte, error) {
	if payload == nil {
		return nil, nil
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	return data, nil
}

func randomNonce() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}
