package selfupdate

import (
	"context"
	"io"
	"net/http"
	"net/url"
)

// DownloadResult is local-only download evidence. Body must be consumed and
// closed by the caller; it is never serialized to the backend.
type DownloadResult struct {
	Body       io.ReadCloser
	InitialURL string
	FinalURL   string
	Redirects  []string
	StatusCode int
}

// OpenDownload opens a candidate binary stream under the same URL policy used
// by preflight. It manually follows redirects so every hop is independently
// checked; a redirect cannot escape the allowlist or downgrade the scheme.
//
// transport is a RoundTripper, not an http.Client, by design: this helper owns
// redirect behavior and always disables net/http's automatic redirect follow.
func OpenDownload(ctx context.Context, rawURL string, pol URLPolicy, transport http.RoundTripper) (DownloadResult, ErrorCode, string) {
	if _, code, reason := CheckURL(rawURL, pol); code != "" {
		return DownloadResult{}, code, reason
	}
	if transport == nil {
		transport = http.DefaultTransport
	}
	client := &http.Client{
		Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	current := rawURL
	var redirects []string
	for {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, current, nil)
		if err != nil {
			return DownloadResult{}, ErrURLRejected, "build download request failed"
		}
		req.Header.Set("User-Agent", "EndpointAgentSelfUpdate/1")

		resp, err := client.Do(req)
		if err != nil {
			return DownloadResult{}, ErrDownloadFailed, "download request failed"
		}
		if isRedirectStatus(resp.StatusCode) {
			next, code, reason := resolveAndValidateRedirect(rawURL, current, resp.Header.Get("Location"), redirects, pol)
			_ = resp.Body.Close()
			if code != "" {
				return DownloadResult{}, code, reason
			}
			redirects = append(redirects, next)
			current = next
			continue
		}
		if resp.StatusCode != http.StatusOK {
			_ = resp.Body.Close()
			return DownloadResult{}, ErrDownloadFailed, "download returned non-200 status"
		}
		return DownloadResult{
			Body:       resp.Body,
			InitialURL: rawURL,
			FinalURL:   current,
			Redirects:  append([]string(nil), redirects...),
			StatusCode: resp.StatusCode,
		}, "", ""
	}
}

// StageCandidateFromDownload opens the payload URL and then delegates to the
// reader-based staging flow. It still does not wire command execution or
// activation; it only turns the already-authorized catalog URL into a bounded
// candidate stream.
func StageCandidateFromDownload(ctx context.Context, in StageCandidateInput, transport http.RoundTripper) (StageResult, ActivationPlan) {
	dl, code, reason := OpenDownload(ctx, in.Preflight.Payload.BinaryURL, in.Preflight.URLPolicy, transport)
	if code != "" {
		return Failed(code, reason), ActivationPlan{}
	}
	defer dl.Body.Close()
	in.Candidate = dl.Body
	return StageCandidateFromReader(in)
}

func resolveAndValidateRedirect(initial, current, location string, prior []string, pol URLPolicy) (string, ErrorCode, string) {
	if location == "" {
		return "", ErrURLRejected, "redirect missing location"
	}
	base, err := url.Parse(current)
	if err != nil {
		return "", ErrURLRejected, "unparseable current url"
	}
	loc, err := url.Parse(location)
	if err != nil {
		return "", ErrURLRejected, "unparseable redirect location"
	}
	next := base.ResolveReference(loc).String()
	hops := append(append([]string(nil), prior...), next)
	if code, reason := CheckRedirectChain(initial, hops, pol); code != "" {
		return "", code, reason
	}
	return next, "", ""
}

func isRedirectStatus(status int) bool {
	switch status {
	case http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther, http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
		return true
	default:
		return false
	}
}
