package selfupdate

import (
	"net"
	"net/url"
	"strings"
)

// URLPolicy is the fail-closed download-URL policy (Codex 019e94fd checklist
// #6). The AllowedHosts set is explicit (the backend release catalog's
// canonical ASCII hostnames). There is no substring/suffix matching — only
// exact, case-insensitive hostname equality.
type URLPolicy struct {
	AllowedHosts []string // e.g. {"github.com", "objects.githubusercontent.com"}
	MaxRedirects int      // hard cap on redirect hops (e.g. 5)
}

// CanonicalURL is a validated, normalized download URL (no userinfo, lowercased
// ASCII host, https only).
type CanonicalURL struct {
	Scheme string
	Host   string
	Port   string // "" or "443"
	Path   string
	Raw    string
}

func (pol URLPolicy) hostAllowed(host string) bool {
	for _, h := range pol.AllowedHosts {
		if strings.EqualFold(strings.TrimSpace(h), host) {
			return true
		}
	}
	return false
}

// CheckURL canonicalizes rawURL and enforces, fail-closed:
//   - scheme is exactly https (no scheme downgrade);
//   - no userinfo (no user:pass@host);
//   - host is ASCII (IDN must be pre-encoded to punycode by the catalog —
//     the agent does not normalize Unicode, it refuses it);
//   - host is NOT an IP literal (v4 or v6);
//   - port is empty or 443;
//   - host is in the explicit allowlist.
//
// Returns ErrURLRejected + a bounded reason on any violation.
func CheckURL(rawURL string, pol URLPolicy) (CanonicalURL, ErrorCode, string) {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return CanonicalURL{}, ErrURLRejected, "unparseable url"
	}
	if !strings.EqualFold(u.Scheme, "https") {
		return CanonicalURL{}, ErrURLRejected, "scheme must be https"
	}
	if u.User != nil {
		return CanonicalURL{}, ErrURLRejected, "userinfo not allowed in url"
	}
	if u.Opaque != "" {
		return CanonicalURL{}, ErrURLRejected, "opaque url not allowed"
	}
	host := u.Hostname()
	if host == "" {
		return CanonicalURL{}, ErrURLRejected, "empty host"
	}
	if !isASCII(host) {
		return CanonicalURL{}, ErrURLRejected, "non-ascii host (idn must be punycode-encoded)"
	}
	host = strings.ToLower(host)
	if net.ParseIP(host) != nil {
		return CanonicalURL{}, ErrURLRejected, "ip-literal host not allowed"
	}
	port := u.Port()
	if port != "" && port != "443" {
		return CanonicalURL{}, ErrURLRejected, "non-443 port not allowed"
	}
	if !pol.hostAllowed(host) {
		return CanonicalURL{}, ErrURLRejected, "host not in allowlist"
	}
	return CanonicalURL{Scheme: "https", Host: host, Port: port, Path: u.Path, Raw: rawURL}, "", ""
}

// CheckRedirectChain validates the initial URL plus EVERY redirect hop under
// the SAME policy: the hop count must not exceed MaxRedirects, and each hop
// must independently satisfy CheckURL (so a redirect cannot escape the host
// allowlist or downgrade the scheme). hops is the ordered list of redirect
// Location targets the HTTP client followed.
func CheckRedirectChain(initial string, hops []string, pol URLPolicy) (ErrorCode, string) {
	if pol.MaxRedirects >= 0 && len(hops) > pol.MaxRedirects {
		return ErrURLRejected, "too many redirects"
	}
	if _, code, reason := CheckURL(initial, pol); code != "" {
		return code, reason
	}
	for _, h := range hops {
		if _, code, reason := CheckURL(h, pol); code != "" {
			return code, reason
		}
	}
	return "", ""
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}
