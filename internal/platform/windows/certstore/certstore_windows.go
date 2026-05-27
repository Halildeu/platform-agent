//go:build windows

package certstore

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"syscall"
	"time"
	"unsafe"

	"github.com/google/certtostore"
	"golang.org/x/sys/windows"

	"platform-agent/internal/autoenroll"
)

// CRYPT_E_NOT_FOUND signals end-of-enumeration from
// CertEnumCertificatesInStore. The constant lives in wincrypt.h; we
// inline the value to avoid pulling in another header-binding package.
const cryptENotFound = 0x80092004

// LoadEligibleCert enumerates LocalMachine\My, applies the agent
// CertFilter (Codex F1 absorb — `SelectLatest` was previously
// unreachable), and returns the CertMaterial for the latest valid cert.
// The returned tls.Certificate.PrivateKey is a *certtostore.Key, which
// implements crypto.Signer via NCryptSignHash so non-exportable
// TPM-backed AD CS keys work unchanged (Codex F7 absorb).
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
	selected := autoenroll.SelectLatest(eligible)
	if selected == nil {
		freeAllContexts(candidates)
		return autoenroll.CertMaterial{}, autoenroll.ErrNoCertMatch
	}

	// Hold onto the selected context; free everything else.
	var selectedCtx *windows.CertContext
	for _, c := range candidates {
		if selectedCtx == nil && bytes.Equal(c.leaf.Raw, selected.Raw) {
			selectedCtx = c.ctx
			continue
		}
		_ = windows.CertFreeCertificateContext(c.ctx)
	}
	if selectedCtx == nil {
		// Theoretically unreachable — SelectLatest returned a leaf we
		// just enumerated — but guard anyway so a future refactor
		// doesn't silently leak a handle.
		return autoenroll.CertMaterial{}, autoenroll.ErrNoCertMatch
	}
	defer windows.CertFreeCertificateContext(selectedCtx)

	signer, err := acquireSigner(selectedCtx)
	if err != nil {
		return autoenroll.CertMaterial{}, fmt.Errorf("acquire CNG signer: %w", err)
	}
	if signer == nil {
		return autoenroll.CertMaterial{}, fmt.Errorf("cert has no private key (non-exportable handle missing)")
	}

	tlsCert := tls.Certificate{
		Certificate: [][]byte{selected.Raw},
		PrivateKey:  signer,
		Leaf:        selected,
	}

	return autoenroll.CertMaterial{
		TLSCertificate:   tlsCert,
		Leaf:             selected,
		ThumbprintSHA256: autoenroll.ThumbprintSHA256Hex(selected),
		ThumbprintSHA1:   autoenroll.ThumbprintSHA1Hex(selected),
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

// acquireSigner wraps certtostore.CertKey so the agent does not have to
// re-implement CryptAcquireCertificatePrivateKey + NCryptSignHash. The
// WinCertStore receiver's storeHandle is unused inside CertKey — the
// call only needs the *windows.CertContext — so we open a throwaway
// store just to expose the method.
func acquireSigner(ctx *windows.CertContext) (*certtostore.Key, error) {
	store, err := certtostore.OpenWinCertStore("Microsoft Platform Crypto Provider", "", nil, nil, false)
	if err != nil {
		return nil, fmt.Errorf("open helper cert store: %w", err)
	}
	defer func() { _ = store.Close() }()
	key, err := store.CertKey(ctx)
	if err != nil {
		return nil, err
	}
	return key, nil
}
