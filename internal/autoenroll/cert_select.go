package autoenroll

import (
	"crypto/x509"
	"sort"
	"strings"
	"time"
)

// FilterCandidates narrows a slice of x509 certs down to those eligible
// under filter. Used by the Windows cert store implementation and by tests
// that drive the selection logic without a real store. Time-based checks
// use now so tests can pin the clock.
func FilterCandidates(certs []*x509.Certificate, filter CertFilter, now time.Time) []*x509.Certificate {
	out := make([]*x509.Certificate, 0, len(certs))
	for _, c := range certs {
		if c == nil {
			continue
		}
		if filter.RequireValidNow {
			if now.Before(c.NotBefore) || !now.Before(c.NotAfter) {
				continue
			}
		}
		if filter.EKU != "" && !hasEKU(c, filter.EKU) {
			continue
		}
		if filter.SubjectSuffix != "" && !strings.HasSuffix(strings.ToLower(c.Subject.CommonName), strings.ToLower(filter.SubjectSuffix)) {
			continue
		}
		if filter.SANURIPrefix != "" && !hasSANURIPrefix(c, filter.SANURIPrefix) {
			continue
		}
		out = append(out, c)
	}
	return out
}

// SelectLatest picks the preferred cert from eligible candidates following
// the deterministic order:
//
//  1. latest NotBefore (newest mint wins — covers AD CS renewal overlap),
//  2. then longest NotAfter (deepest validity wins),
//  3. then SHA-256 thumbprint hex ASC (stable tie-break).
//
// Returns nil when candidates is empty. Codex Q5 + F1 absorb.
func SelectLatest(candidates []*x509.Certificate) *x509.Certificate {
	ranked := RankCandidates(candidates)
	if len(ranked) == 0 {
		return nil
	}
	return ranked[0]
}

// RankCandidates returns the candidates sorted by the same order used
// by SelectLatest. Useful when the caller wants to try candidates in
// preference order — e.g. acquire the signer for the newest cert and
// fall back to the next one if the private key handle is missing
// (Codex F12 absorb).
func RankCandidates(candidates []*x509.Certificate) []*x509.Certificate {
	if len(candidates) == 0 {
		return nil
	}
	sorted := make([]*x509.Certificate, len(candidates))
	copy(sorted, candidates)
	sort.SliceStable(sorted, func(i, j int) bool {
		a, b := sorted[i], sorted[j]
		if !a.NotBefore.Equal(b.NotBefore) {
			return a.NotBefore.After(b.NotBefore)
		}
		if !a.NotAfter.Equal(b.NotAfter) {
			return a.NotAfter.After(b.NotAfter)
		}
		return ThumbprintSHA256Hex(a) < ThumbprintSHA256Hex(b)
	})
	return sorted
}

// hasEKU reports whether cert carries the given dotted-OID EKU. Both the
// parsed ExtKeyUsage enum and the raw UnknownExtKeyUsage OID list are
// consulted; that lets unit tests construct certs with explicit OIDs without
// having to map to the limited x509.ExtKeyUsage enum.
func hasEKU(cert *x509.Certificate, dottedOID string) bool {
	for _, u := range cert.UnknownExtKeyUsage {
		if u.String() == dottedOID {
			return true
		}
	}
	if dottedOID == "1.3.6.1.5.5.7.3.2" {
		for _, u := range cert.ExtKeyUsage {
			if u == x509.ExtKeyUsageClientAuth {
				return true
			}
		}
	}
	if dottedOID == "1.3.6.1.5.5.7.3.1" {
		for _, u := range cert.ExtKeyUsage {
			if u == x509.ExtKeyUsageServerAuth {
				return true
			}
		}
	}
	return false
}

// hasSANURIPrefix reports whether cert carries a URI SAN starting with
// prefix (case-insensitive).
func hasSANURIPrefix(cert *x509.Certificate, prefix string) bool {
	pLow := strings.ToLower(prefix)
	for _, u := range cert.URIs {
		if u == nil {
			continue
		}
		if strings.HasPrefix(strings.ToLower(u.String()), pLow) {
			return true
		}
	}
	return false
}
