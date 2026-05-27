package autoenroll

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"net/url"
	"testing"
	"time"
)

func mustParseURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse url %q: %v", raw, err)
	}
	return u
}

// makeCert builds a minimal *x509.Certificate with raw bytes set so the
// thumbprint helpers produce stable values. The raw payload is the marker
// suffix; tests use it only to differentiate certs.
func makeCert(t *testing.T, cn, marker string, notBefore, notAfter time.Time, eku []x509.ExtKeyUsage, unknownEKU []string, sanURIs []string) *x509.Certificate {
	t.Helper()
	uris := make([]*url.URL, 0, len(sanURIs))
	for _, s := range sanURIs {
		uris = append(uris, mustParseURL(t, s))
	}
	unknown := make([]asn1.ObjectIdentifier, 0, len(unknownEKU))
	for _, raw := range unknownEKU {
		oid, err := parseOID(raw)
		if err != nil {
			t.Fatalf("parse oid %q: %v", raw, err)
		}
		unknown = append(unknown, oid)
	}
	return &x509.Certificate{
		Subject:            pkix.Name{CommonName: cn},
		NotBefore:          notBefore,
		NotAfter:           notAfter,
		ExtKeyUsage:        eku,
		UnknownExtKeyUsage: unknown,
		URIs:               uris,
		Raw:                []byte("cert:" + marker),
	}
}

func parseOID(raw string) (asn1.ObjectIdentifier, error) {
	parts := make([]int, 0, 4)
	cur := 0
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		if c == '.' {
			parts = append(parts, cur)
			cur = 0
			continue
		}
		if c < '0' || c > '9' {
			return nil, &parseError{raw: raw}
		}
		cur = cur*10 + int(c-'0')
	}
	parts = append(parts, cur)
	return asn1.ObjectIdentifier(parts), nil
}

type parseError struct{ raw string }

func (e *parseError) Error() string { return "bad oid: " + e.raw }

func TestFilterCandidates_EKUClientAuthAccepts(t *testing.T) {
	now := time.Date(2026, 5, 27, 12, 0, 0, 0, time.UTC)
	c := makeCert(t, "host.acik.local", "a",
		now.Add(-time.Hour), now.Add(24*time.Hour),
		[]x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, nil, nil)
	got := FilterCandidates([]*x509.Certificate{c}, DefaultCertFilter(), now)
	if len(got) != 1 {
		t.Fatalf("expected 1 eligible, got %d", len(got))
	}
}

func TestFilterCandidates_RejectsExpired(t *testing.T) {
	now := time.Date(2026, 5, 27, 12, 0, 0, 0, time.UTC)
	c := makeCert(t, "host.acik.local", "a",
		now.Add(-48*time.Hour), now.Add(-time.Hour),
		[]x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, nil, nil)
	if got := FilterCandidates([]*x509.Certificate{c}, DefaultCertFilter(), now); len(got) != 0 {
		t.Fatalf("expected 0 eligible (expired), got %d", len(got))
	}
}

func TestFilterCandidates_RejectsFuture(t *testing.T) {
	now := time.Date(2026, 5, 27, 12, 0, 0, 0, time.UTC)
	c := makeCert(t, "host.acik.local", "a",
		now.Add(time.Hour), now.Add(48*time.Hour),
		[]x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, nil, nil)
	if got := FilterCandidates([]*x509.Certificate{c}, DefaultCertFilter(), now); len(got) != 0 {
		t.Fatalf("expected 0 eligible (future NotBefore), got %d", len(got))
	}
}

func TestFilterCandidates_RejectsWrongEKU(t *testing.T) {
	now := time.Date(2026, 5, 27, 12, 0, 0, 0, time.UTC)
	c := makeCert(t, "host.acik.local", "a",
		now.Add(-time.Hour), now.Add(24*time.Hour),
		[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, nil, nil)
	if got := FilterCandidates([]*x509.Certificate{c}, DefaultCertFilter(), now); len(got) != 0 {
		t.Fatalf("expected 0 eligible (Server Auth EKU only), got %d", len(got))
	}
}

func TestFilterCandidates_AcceptsUnknownEKUOID(t *testing.T) {
	now := time.Date(2026, 5, 27, 12, 0, 0, 0, time.UTC)
	c := makeCert(t, "host.acik.local", "a",
		now.Add(-time.Hour), now.Add(24*time.Hour),
		nil, []string{"1.3.6.1.5.5.7.3.2"}, nil)
	if got := FilterCandidates([]*x509.Certificate{c}, DefaultCertFilter(), now); len(got) != 1 {
		t.Fatalf("expected 1 eligible via UnknownExtKeyUsage, got %d", len(got))
	}
}

func TestFilterCandidates_SubjectSuffix(t *testing.T) {
	now := time.Date(2026, 5, 27, 12, 0, 0, 0, time.UTC)
	a := makeCert(t, "agent.acik.local", "a",
		now.Add(-time.Hour), now.Add(24*time.Hour),
		[]x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, nil, nil)
	b := makeCert(t, "vpn.other.example", "b",
		now.Add(-time.Hour), now.Add(24*time.Hour),
		[]x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, nil, nil)
	f := DefaultCertFilter()
	f.SubjectSuffix = ".acik.local"
	got := FilterCandidates([]*x509.Certificate{a, b}, f, now)
	if len(got) != 1 || got[0] != a {
		t.Fatalf("expected only acik.local cert, got %v", got)
	}
}

func TestFilterCandidates_SANURIPrefix(t *testing.T) {
	now := time.Date(2026, 5, 27, 12, 0, 0, 0, time.UTC)
	a := makeCert(t, "agent", "a",
		now.Add(-time.Hour), now.Add(24*time.Hour),
		[]x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, nil,
		[]string{"adcomputer:b8d8c8ff-0000-0000-0000-000000000001"})
	b := makeCert(t, "agent", "b",
		now.Add(-time.Hour), now.Add(24*time.Hour),
		[]x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, nil,
		[]string{"otherprefix:value"})
	f := DefaultCertFilter()
	f.SANURIPrefix = "adcomputer:"
	got := FilterCandidates([]*x509.Certificate{a, b}, f, now)
	if len(got) != 1 || got[0] != a {
		t.Fatalf("expected only adcomputer SAN cert, got %v", got)
	}
}

func TestSelectLatest_LatestNotBeforeWins(t *testing.T) {
	now := time.Date(2026, 5, 27, 12, 0, 0, 0, time.UTC)
	older := makeCert(t, "agent", "older",
		now.Add(-48*time.Hour), now.Add(48*time.Hour),
		[]x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, nil, nil)
	newer := makeCert(t, "agent", "newer",
		now.Add(-time.Hour), now.Add(48*time.Hour),
		[]x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, nil, nil)
	selected := SelectLatest([]*x509.Certificate{older, newer})
	if selected != newer {
		t.Fatalf("expected newer (later NotBefore), got %v", selected)
	}
}

func TestSelectLatest_TieBreakByNotAfter(t *testing.T) {
	now := time.Date(2026, 5, 27, 12, 0, 0, 0, time.UTC)
	short := makeCert(t, "agent", "short",
		now.Add(-time.Hour), now.Add(24*time.Hour),
		[]x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, nil, nil)
	long := makeCert(t, "agent", "long",
		now.Add(-time.Hour), now.Add(72*time.Hour),
		[]x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, nil, nil)
	selected := SelectLatest([]*x509.Certificate{short, long})
	if selected != long {
		t.Fatalf("expected long (greater NotAfter), got %v", selected)
	}
}

func TestSelectLatest_TieBreakByThumbprint(t *testing.T) {
	now := time.Date(2026, 5, 27, 12, 0, 0, 0, time.UTC)
	a := makeCert(t, "agent", "AAA",
		now.Add(-time.Hour), now.Add(24*time.Hour),
		[]x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, nil, nil)
	b := makeCert(t, "agent", "ZZZ",
		now.Add(-time.Hour), now.Add(24*time.Hour),
		[]x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, nil, nil)
	// Both identical NotBefore + NotAfter → SHA-256 ASC sort decides.
	expected := a
	if ThumbprintSHA256Hex(b) < ThumbprintSHA256Hex(a) {
		expected = b
	}
	selected := SelectLatest([]*x509.Certificate{a, b})
	if selected != expected {
		t.Fatalf("expected ASC-thumbprint tie-break to pick the smaller hex; want raw=%q, got raw=%q",
			expected.Raw, selected.Raw)
	}
}

func TestSelectLatest_NilWhenEmpty(t *testing.T) {
	if SelectLatest(nil) != nil {
		t.Fatal("expected nil from empty input")
	}
}
