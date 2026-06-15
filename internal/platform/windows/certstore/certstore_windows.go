//go:build windows

package certstore

import (
	"bytes"
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"platform-agent/internal/autoenroll"
)

// CRYPT_E_NOT_FOUND signals end-of-enumeration from
// CertEnumCertificatesInStore. The constant lives in wincrypt.h; we
// inline the value to avoid pulling in another header-binding package.
const (
	cryptENotFound = 0x80092004

	// CERT_KEY_PROV_INFO_PROP_ID and CERT_NCRYPT_KEY_HANDLE_PROP_ID are
	// private-key association hints on a CertContext. Querying these before
	// CryptAcquireCertificatePrivateKey keeps broad dry-runs from invoking
	// native key acquisition on certs that cannot possibly satisfy the mTLS
	// auto-enroll contract.
	certKeyProvInfoPropID     = 2
	certNCryptKeyHandlePropID = 78
)

var procCertGetCertificateContextProperty = windows.NewLazySystemDLL("crypt32.dll").NewProc("CertGetCertificateContextProperty")

// LoadEligibleCert enumerates LocalMachine\My, applies the agent
// CertFilter (Codex F1 absorb — `SelectLatest` was previously
// unreachable), and returns the CertMaterial for the latest valid cert.
// The returned tls.Certificate.PrivateKey is a cngSigner (see
// cngsigner_windows.go, #147) which implements crypto.Signer via
// NCryptSignHash so non-exportable TPM-backed AD CS keys work unchanged.
//
// The enumeration uses x/sys/windows directly because certtostore's
// CertWithContext returns only the first match against the configured
// issuer list — that is unsafe during AD CS renewal-overlap windows
// where two valid certs share the same Issuer DN. The selection
// algorithm (latest NotBefore, then longest NotAfter, then
// thumbprint ASC) lives in autoenroll.SelectLatest.
func (p *Provider) LoadEligibleCert(ctx context.Context, filter autoenroll.CertFilter) (autoenroll.CertMaterial, error) {
	if err := ctx.Err(); err != nil {
		return autoenroll.CertMaterial{}, err
	}

	storeName, err := windows.UTF16PtrFromString("MY")
	if err != nil {
		return autoenroll.CertMaterial{}, fmt.Errorf("encode store name: %w", err)
	}
	hStore, err := windows.CertOpenStore(
		windows.CERT_STORE_PROV_SYSTEM_W,
		0,
		0,
		windows.CERT_SYSTEM_STORE_LOCAL_MACHINE,
		uintptr(unsafe.Pointer(storeName)),
	)
	if err != nil {
		return autoenroll.CertMaterial{}, fmt.Errorf("open LocalMachine\\My: %w", err)
	}
	defer windows.CertCloseStore(hStore, 0)

	candidates, err := enumerateMyStore(hStore)
	if err != nil {
		freeAllContexts(candidates)
		return autoenroll.CertMaterial{}, err
	}
	if len(candidates) == 0 {
		return autoenroll.CertMaterial{}, autoenroll.ErrNoCertMatch
	}

	leaves := make([]*x509.Certificate, len(candidates))
	for i, c := range candidates {
		leaves[i] = c.leaf
	}
	eligible := autoenroll.FilterCandidates(leaves, filter, time.Now())
	if len(eligible) == 0 {
		freeAllContexts(candidates)
		return autoenroll.CertMaterial{}, autoenroll.ErrNoCertMatch
	}
	ranked := autoenroll.RankCandidates(eligible)

	// Codex F12 absorb: walk ranked candidates and acquire a signer for
	// each in turn. The newest cert wins unless its private key handle
	// is missing — for AD CS renewal-overlap windows where the new cert
	// has been minted but the key/cert binding has not yet propagated,
	// the agent falls back to an older cert that still has a valid
	// signer rather than dying on `acquire CNG signer` for the newest.
	type rankedCtx struct {
		leaf *x509.Certificate
		ctx  *windows.CertContext
	}
	rankedContexts := make([]rankedCtx, 0, len(ranked))
	for _, leaf := range ranked {
		for _, c := range candidates {
			if c.ctx == nil {
				continue
			}
			if bytes.Equal(c.leaf.Raw, leaf.Raw) {
				rankedContexts = append(rankedContexts, rankedCtx{leaf: leaf, ctx: c.ctx})
				c.ctx = nil // mark consumed
				break
			}
		}
	}
	// Free any candidate context not in the eligible set.
	for _, c := range candidates {
		if c.ctx != nil {
			_ = windows.CertFreeCertificateContext(c.ctx)
		}
	}

	var (
		chosenLeaf            *x509.Certificate
		chosenCtx             *windows.CertContext
		chosenKey             crypto.Signer
		cleanupRankedContexts = true
	)
	defer func() {
		if !cleanupRankedContexts {
			return
		}
		for _, rc := range rankedContexts {
			if rc.ctx != nil && rc.ctx != chosenCtx {
				_ = windows.CertFreeCertificateContext(rc.ctx)
			}
		}
	}()

	for _, rc := range rankedContexts {
		signer, err := acquireSigner(rc.ctx, rc.leaf.PublicKey)
		if err == nil && signer != nil {
			chosenLeaf, chosenCtx, chosenKey = rc.leaf, rc.ctx, signer
			break
		}
		// Log via stderr-style hint embedded in error: the autoenroll
		// runner reads only the final returned error, but operators
		// running --dry-run on the box see this chain when stepping
		// through the cert store manually.
		// (We do not return here; we try the next candidate.)
	}
	if chosenLeaf == nil || chosenKey == nil {
		return autoenroll.CertMaterial{}, fmt.Errorf("%w: no eligible cert had an acquireable CNG signer",
			autoenroll.ErrNoCertMatch)
	}
	// #151/#165 live M2 dry-runs on ERP-MOBIL proved that freeing cert
	// contexts after successful CryptAcquireCertificatePrivateKey can
	// access-violate on some providers, including at dry-run process cleanup.
	// On success, cngSigner owns the selected NCrypt handle and retains the
	// selected context for process lifetime; the remaining ranked contexts are
	// also deliberately retained. Auto-enroll loads certs only on
	// startup/rotation, so this favors mTLS correctness over a tiny bounded
	// context leak. The error path still frees ranked contexts so misconfigured
	// retry loops do not grow unbounded.
	cleanupRankedContexts = false
	_ = chosenCtx

	tlsCert := tls.Certificate{
		Certificate: [][]byte{chosenLeaf.Raw},
		PrivateKey:  chosenKey,
		Leaf:        chosenLeaf,
	}

	return autoenroll.CertMaterial{
		TLSCertificate:   tlsCert,
		Leaf:             chosenLeaf,
		ThumbprintSHA256: autoenroll.ThumbprintSHA256Hex(chosenLeaf),
		ThumbprintSHA1:   autoenroll.ThumbprintSHA1Hex(chosenLeaf),
	}, nil
}

// enumerateCandidate is one cert + its duplicated CertContext. The
// context must be freed (via CertFreeCertificateContext) when no longer
// needed; LoadEligibleCert handles that for both the selected and
// non-selected paths.
type enumerateCandidate struct {
	leaf *x509.Certificate
	ctx  *windows.CertContext
}

// enumerateMyStore walks hStore via CertEnumCertificatesInStore and
// returns a slice of duplicated cert contexts. CertEnumCertificatesInStore
// frees the previous context as it iterates; we duplicate so the caller
// can hold a handle for the lifetime of the selection algorithm.
func enumerateMyStore(hStore windows.Handle) ([]enumerateCandidate, error) {
	var candidates []enumerateCandidate
	var prev *windows.CertContext
	for {
		ctx, err := windows.CertEnumCertificatesInStore(hStore, prev)
		if err != nil {
			if isCryptENotFound(err) {
				break
			}
			return candidates, fmt.Errorf("enumerate cert store: %w", err)
		}
		if ctx == nil {
			break
		}
		prev = ctx

		// Snapshot the DER bytes so we can keep using the leaf after the
		// underlying context is freed.
		if ctx.Length == 0 || ctx.EncodedCert == nil {
			continue
		}
		der := unsafe.Slice(ctx.EncodedCert, ctx.Length)
		buf := make([]byte, len(der))
		copy(buf, der)
		leaf, err := x509.ParseCertificate(buf)
		if err != nil {
			continue
		}

		dup := windows.CertDuplicateCertificateContext(ctx)
		if dup == nil {
			continue
		}
		candidates = append(candidates, enumerateCandidate{leaf: leaf, ctx: dup})
	}
	return candidates, nil
}

// freeAllContexts releases every cert context in the slice. Safe to
// call with a partially-populated slice (no panic on nil contexts).
func freeAllContexts(candidates []enumerateCandidate) {
	for _, c := range candidates {
		if c.ctx != nil {
			_ = windows.CertFreeCertificateContext(c.ctx)
		}
	}
}

// isCryptENotFound reports whether err carries the CRYPT_E_NOT_FOUND
// sentinel that CertEnumCertificatesInStore returns when the loop ends.
func isCryptENotFound(err error) bool {
	var errno syscall.Errno
	if errors.As(err, &errno) && uint32(errno) == cryptENotFound {
		return true
	}
	// CertEnumCertificatesInStore in some builds wraps the errno; fall
	// back to a string check so the loop terminates rather than panics.
	return err != nil && errors.Is(err, syscall.Errno(cryptENotFound))
}

// acquireSigner now lives in cngsigner_windows.go (#147): it acquires the CNG
// private key with .NET-equivalent flags (SILENT | PREFER_NCRYPT, no cache) and
// returns a cngSigner, avoiding the certtostore.CertKey access-violation on
// valid PCP/TPM keys.

func hasPrivateKeyBinding(ctx *windows.CertContext) bool {
	if ctx == nil {
		return false
	}
	return certContextPropertyPresent(ctx, certKeyProvInfoPropID) ||
		certContextPropertyPresent(ctx, certNCryptKeyHandlePropID)
}

func certContextPropertyPresent(ctx *windows.CertContext, propID uint32) bool {
	var size uint32
	r, _, _ := procCertGetCertificateContextProperty.Call(
		uintptr(unsafe.Pointer(ctx)),
		uintptr(propID),
		0,
		uintptr(unsafe.Pointer(&size)),
	)
	return r != 0 && size > 0
}
