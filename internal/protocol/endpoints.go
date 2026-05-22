package protocol

import (
	"net/http"
	"net/url"
	"strings"
)

// BE-011 endpoint-definition layer. Every agent→backend operation has two
// paths that must NOT be conflated:
//
//   - the EXTERNAL path the agent dials — under /api/v1/endpoint-agent/**,
//     the permitAll route the api-gateway exposes;
//   - the CANONICAL path the HMAC signature covers — the backend-visible
//     /api/v1/agent/** path, because the gateway rewrites
//     endpoint-agent/(.*) -> agent/$1 before forwarding and the backend's
//     DeviceCredentialAuthenticationFilter signs request.getRequestURI()
//     (the post-rewrite path).
//
// Keeping both in one place avoids scattering the rewrite assumption across
// the client (Codex 019e5000 Q3).

// DeriveSigningPathPrefix derives the backend-visible (canonical) path prefix
// from the external API base path the agent dials. When the path contains the
// gateway "/endpoint-agent" path SEGMENT it is rewritten to "/agent"; a base
// path that already targets the backend directly (already "/agent") is
// returned unchanged. Trailing slashes are trimmed. The match is
// segment-boundary aware — "/endpoint-agent" is only rewritten when followed
// by "/" or the end of the path, so e.g. "/foo/endpoint-agent-extra" is left
// alone (Codex 019e5000 hardening).
func DeriveSigningPathPrefix(externalBasePath string) string {
	trimmed := strings.TrimRight(externalBasePath, "/")
	const segment = "/endpoint-agent"
	if idx := strings.Index(trimmed, segment); idx >= 0 {
		rest := trimmed[idx+len(segment):]
		if rest == "" || strings.HasPrefix(rest, "/") {
			return trimmed[:idx] + "/agent" + rest
		}
	}
	return trimmed
}

// agentRequest is one agent→backend operation. suffix is appended to BOTH the
// external base URL (for the HTTP dial) and the signing path prefix (for the
// HMAC canonical string).
type agentRequest struct {
	method string
	suffix string
	signed bool
}

var (
	// reqEnroll — POST /enrollments/consume. Unsigned: the backend filter's
	// shouldNotFilter() excludes exactly this path because no device
	// credential exists until enrollment completes.
	reqEnroll = agentRequest{method: http.MethodPost, suffix: "/enrollments/consume", signed: false}

	// reqHeartbeat — POST /heartbeat, signed with the device credential.
	reqHeartbeat = agentRequest{method: http.MethodPost, suffix: "/heartbeat", signed: true}

	// reqNextCommand — GET /commands/next, signed. HTTP 204 means no command.
	reqNextCommand = agentRequest{method: http.MethodGet, suffix: "/commands/next", signed: true}
)

// reqCommandResult builds the signed POST /commands/{commandId}/result spec.
func reqCommandResult(commandID string) agentRequest {
	return agentRequest{
		method: http.MethodPost,
		suffix: "/commands/" + url.PathEscape(commandID) + "/result",
		signed: true,
	}
}
