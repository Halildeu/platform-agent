package selfupdate

import "testing"

func TestCheckURL(t *testing.T) {
	pol := URLPolicy{AllowedHosts: []string{"github.com", "objects.githubusercontent.com"}, MaxRedirects: 5}
	cases := []struct {
		name    string
		url     string
		wantErr bool
	}{
		{"https allowlisted ok", "https://github.com/Halildeu/platform-agent/releases/download/v1/agent.exe", false},
		{"case-insensitive host ok", "https://GitHub.com/x", false},
		{"explicit 443 ok", "https://github.com:443/x", false},
		{"second allowlisted host ok", "https://objects.githubusercontent.com/x", false},
		{"http scheme rejected", "http://github.com/x", true},
		{"ftp scheme rejected", "ftp://github.com/x", true},
		{"userinfo rejected", "https://user:pass@github.com/x", true},
		{"ipv4 literal rejected", "https://192.168.1.10/x", true},
		{"ipv6 literal rejected", "https://[::1]/x", true},
		{"public ipv4 literal rejected", "https://93.184.216.34/x", true},
		{"non-443 port rejected", "https://github.com:8443/x", true},
		{"decimal ip literal rejected", "https://2130706433/x", true},
		{"hex ip literal rejected", "https://0x7f000001/x", true},
		{"octal ip literal rejected", "https://0177.0.0.1/x", true},
		{"short-form ip literal rejected", "https://127.1/x", true},
		{"host not in allowlist rejected", "https://evil.example/x", true},
		{"non-ascii host rejected", "https://пример.example/x", true},
		{"empty rejected", "", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, code, reason := CheckURL(c.url, pol)
			gotErr := code != ""
			if gotErr != c.wantErr {
				t.Errorf("CheckURL(%q) err=%v (code=%q reason=%q), want err=%v", c.url, gotErr, code, reason, c.wantErr)
			}
			if gotErr && code != ErrURLRejected {
				t.Errorf("CheckURL(%q) code=%q, want POLICY_URL_REJECTED", c.url, code)
			}
		})
	}
}

func TestCheckRedirectChain(t *testing.T) {
	pol := URLPolicy{AllowedHosts: []string{"github.com", "objects.githubusercontent.com"}, MaxRedirects: 3}

	if code, _ := CheckRedirectChain(
		"https://github.com/a",
		[]string{"https://objects.githubusercontent.com/b"},
		pol,
	); code != "" {
		t.Errorf("clean chain rejected: %q", code)
	}

	if code, _ := CheckRedirectChain(
		"https://github.com/a",
		[]string{"https://a.example", "https://b.example", "https://c.example", "https://d.example"},
		pol,
	); code != ErrURLRejected {
		t.Errorf("too-many-redirects not rejected, code=%q", code)
	}

	if code, _ := CheckRedirectChain(
		"https://github.com/a",
		[]string{"https://evil.example/b"},
		pol,
	); code != ErrURLRejected {
		t.Errorf("off-allowlist redirect hop not rejected, code=%q", code)
	}

	if code, _ := CheckRedirectChain(
		"https://github.com/a",
		[]string{"http://github.com/b"},
		pol,
	); code != ErrURLRejected {
		t.Errorf("scheme-downgrade redirect hop not rejected, code=%q", code)
	}
}
