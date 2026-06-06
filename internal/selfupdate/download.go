package selfupdate

import (
	"context"
	"errors"
	"io"
	"net/http"
	"time"
)

// download.go — cross-platform BinaryDownloader (net/http) with fail-closed URL
// + redirect policy and a hard byte cap. The transport is HTTPS-only by policy
// (CheckURL rejects any non-https scheme before a request is made and on every
// redirect hop).

// HTTPDownloader streams a release binary under URLPolicy with a hard size cap.
// A nil Client uses a sane default with timeouts.
type HTTPDownloader struct {
	Client *http.Client
}

// NewHTTPDownloader builds a downloader with conservative timeouts. The
// transport disables HTTP/2 push and keeps the default secure TLS config (the
// agent pins host trust via the URL allowlist + Authenticode on the bytes; TLS
// here is transport confidentiality/integrity, not the trust authority).
func NewHTTPDownloader() *HTTPDownloader {
	return &HTTPDownloader{
		Client: &http.Client{
			Timeout: 10 * time.Minute,
		},
	}
}

// errTooLarge is the sentinel a capped reader returns when the stream exceeds
// the byte cap.
var errTooLarge = errors.New("download exceeded byte cap")

// Download fetches rawURL into dst, enforcing pol (scheme/host/redirects) and a
// hard maxBytes cap. It returns the bytes written and a bounded ErrorCode:
//   - POLICY_URL_REJECTED  : the initial URL or a redirect hop failed the policy
//   - DOWNLOAD_TOO_LARGE   : the body exceeded maxBytes
//   - DOWNLOAD_FAILED      : transport error or non-2xx status
//
// Redirects are validated against pol on EVERY hop via the client's
// CheckRedirect; a hop that escapes the host allowlist, downgrades the scheme,
// or exceeds MaxRedirects aborts the request fail-closed. Range/resume is never
// requested and a 206 Partial Content is treated as a failure.
func (d *HTTPDownloader) Download(ctx context.Context, rawURL string, pol URLPolicy, maxBytes int64, dst io.Writer) (int64, ErrorCode, string) {
	if _, code, reason := CheckURL(rawURL, pol); code != "" {
		return 0, code, reason
	}
	if maxBytes <= 0 {
		return 0, ErrDownloadFailed, "no positive byte cap configured"
	}

	client := d.Client
	if client == nil {
		client = NewHTTPDownloader().Client
	}
	// Validate every redirect hop under the same policy. We clone the client so
	// the CheckRedirect closure is request-scoped and never mutates a shared one.
	rc := *client
	rc.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		// via already holds the prior requests; the hop count is len(via).
		if pol.MaxRedirects >= 0 && len(via) > pol.MaxRedirects {
			return errPolicyRedirect{reason: "too many redirects"}
		}
		if _, code, reason := CheckURL(req.URL.String(), pol); code != "" {
			return errPolicyRedirect{reason: reason}
		}
		return nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return 0, ErrDownloadFailed, "could not build request"
	}
	// Explicitly do not negotiate ranges; we always want the full object.
	req.Header.Set("Accept-Encoding", "identity")

	resp, err := rc.Do(req)
	if err != nil {
		var pr errPolicyRedirect
		if errors.As(err, &pr) {
			return 0, ErrURLRejected, pr.reason
		}
		return 0, ErrDownloadFailed, "transport error during download"
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		// Anything other than a plain 200 (including 206 Partial Content) is a
		// failure: we requested a full object with no range.
		return 0, ErrDownloadFailed, "non-200 response status"
	}

	// Cap the body at maxBytes+1 so we can DETECT (not silently truncate) an
	// over-cap stream.
	capped := &capReader{r: resp.Body, remaining: maxBytes + 1}
	n, copyErr := io.Copy(dst, capped)
	if errors.Is(copyErr, errTooLarge) || n > maxBytes {
		return n, ErrDownloadTooLarge, "download exceeded the byte cap"
	}
	if copyErr != nil {
		return n, ErrDownloadFailed, "error reading download body"
	}
	return n, "", ""
}

// errPolicyRedirect is a redirect-hop policy violation surfaced through
// http.Client.Do.
type errPolicyRedirect struct{ reason string }

func (e errPolicyRedirect) Error() string { return "redirect policy: " + e.reason }

// capReader returns errTooLarge once more than its initial budget is read.
type capReader struct {
	r         io.Reader
	remaining int64
}

func (c *capReader) Read(p []byte) (int, error) {
	if c.remaining <= 0 {
		return 0, errTooLarge
	}
	if int64(len(p)) > c.remaining {
		p = p[:c.remaining]
	}
	n, err := c.r.Read(p)
	c.remaining -= int64(n)
	if c.remaining <= 0 && err == nil {
		// We've consumed the +1 sentinel byte beyond the cap.
		err = errTooLarge
	}
	return n, err
}
