//go:build windows

package certstore

import (
	"crypto"
	"crypto/rsa"
	"errors"
	"fmt"
	"io"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Faz 22.5 Step-2 (#147): the agent's machine-cert private-key acquisition no
// longer routes through certtostore.(*WinCertStore).CertKey. On a valid
// CNG/TPM (Microsoft Platform Crypto Provider) machine key, certtostore's
// CryptAcquireCertificatePrivateKey call (with CRYPT_ACQUIRE_CACHE_FLAG |
// CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG) access-violates (0xc0000005) on at least
// some NCrypt providers, even though .NET's RSACertificateExtensions
// .GetRSAPrivateKey reads the same key fine. We instead acquire with the
// .NET-equivalent flags (SILENT | PREFER_NCRYPT, no cache) and sign via
// NCryptSignHash — proven not to crash on the same key.
const (
	// CryptAcquireCertificatePrivateKey dwFlags (wincrypt.h):
	cryptAcquireSilentFlag       = 0x00000040 // CRYPT_ACQUIRE_SILENT_FLAG
	cryptAcquirePreferNCryptFlag = 0x00020000 // CRYPT_ACQUIRE_PREFER_NCRYPT_KEY_FLAG
	// (0x00010000 is ALLOW_NCRYPT, not PREFER — do not use.)

	certNCryptKeySpec = 0xFFFFFFFF // CERT_NCRYPT_KEY_SPEC

	ncryptPadPKCS1Flag = 0x2 // NCRYPT_PAD_PKCS1_FLAG
	ncryptPadPSSFlag   = 0x8 // NCRYPT_PAD_PSS_FLAG
)

var (
	crypt32Mod   = windows.NewLazySystemDLL("crypt32.dll")
	advapi32Mod  = windows.NewLazySystemDLL("advapi32.dll")
	ncryptMod    = windows.NewLazySystemDLL("ncrypt.dll")
	procAcquire  = crypt32Mod.NewProc("CryptAcquireCertificatePrivateKey")
	procSign     = ncryptMod.NewProc("NCryptSignHash")
	procFreeObj  = ncryptMod.NewProc("NCryptFreeObject")
	procRelCtx   = advapi32Mod.NewProc("CryptReleaseContext")
)

type bcryptPKCS1PaddingInfo struct{ AlgID *uint16 }

type bcryptPSSPaddingInfo struct {
	AlgID *uint16
	Salt  uint32
}

// cngSigner is a crypto.Signer over an NCRYPT_KEY_HANDLE acquired via
// CryptAcquireCertificatePrivateKey. It satisfies tls.Certificate.PrivateKey.
//
// It OWNS the cert context (#147): the NCRYPT key handle keeps an internal
// association to the context on some providers, so the context must outlive the
// key handle. LoadEligibleCert hands ownership here instead of freeing the
// chosen context itself, and the runner closes the signer when the material is
// superseded (see closeCertMaterialSigner) to avoid a per-iteration handle leak.
type cngSigner struct {
	handle    uintptr
	callerFree bool // pfCallerFreeProvOrNCryptKey — only then may we free
	ctx       *windows.CertContext
	pub       crypto.PublicKey
}

func (s *cngSigner) Public() crypto.PublicKey { return s.pub }

// Close frees the NCRYPT key handle (only when the acquire reported
// caller-free) and the owned cert context. Idempotent.
func (s *cngSigner) Close() {
	if s.handle != 0 && s.callerFree {
		_, _, _ = procFreeObj.Call(s.handle) // NCRYPT key spec only (legacy rejected at acquire)
	}
	s.handle = 0
	if s.ctx != nil {
		_ = windows.CertFreeCertificateContext(s.ctx)
		s.ctx = nil
	}
}

func (s *cngSigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if len(digest) == 0 {
		return nil, errors.New("cngSigner: empty digest")
	}
	algID, err := bcryptHashAlgID(opts.HashFunc())
	if err != nil {
		return nil, err
	}
	algPtr, err := windows.UTF16PtrFromString(algID)
	if err != nil {
		return nil, err
	}

	var padInfo unsafe.Pointer
	var flag uintptr
	if pss, ok := opts.(*rsa.PSSOptions); ok {
		salt := pss.SaltLength
		switch salt {
		case rsa.PSSSaltLengthAuto, rsa.PSSSaltLengthEqualsHash:
			salt = opts.HashFunc().Size()
		}
		if salt < 0 {
			return nil, fmt.Errorf("cngSigner: invalid PSS salt length %d", salt)
		}
		info := bcryptPSSPaddingInfo{AlgID: algPtr, Salt: uint32(salt)}
		padInfo = unsafe.Pointer(&info)
		flag = ncryptPadPSSFlag
	} else {
		info := bcryptPKCS1PaddingInfo{AlgID: algPtr}
		padInfo = unsafe.Pointer(&info)
		flag = ncryptPadPKCS1Flag
	}

	// Two-call NCryptSignHash: size, then sign.
	var cb uint32
	r, _, _ := procSign.Call(s.handle, uintptr(padInfo),
		uintptr(unsafe.Pointer(&digest[0])), uintptr(len(digest)),
		0, 0, uintptr(unsafe.Pointer(&cb)), flag)
	if r != 0 {
		return nil, fmt.Errorf("NCryptSignHash(size) failed: NTSTATUS 0x%x", r)
	}
	sig := make([]byte, cb)
	r, _, _ = procSign.Call(s.handle, uintptr(padInfo),
		uintptr(unsafe.Pointer(&digest[0])), uintptr(len(digest)),
		uintptr(unsafe.Pointer(&sig[0])), uintptr(cb),
		uintptr(unsafe.Pointer(&cb)), flag)
	if r != 0 {
		return nil, fmt.Errorf("NCryptSignHash failed: NTSTATUS 0x%x", r)
	}
	return sig[:cb], nil
}

func bcryptHashAlgID(h crypto.Hash) (string, error) {
	switch h {
	case crypto.SHA256:
		return "SHA256", nil
	case crypto.SHA384:
		return "SHA384", nil
	case crypto.SHA512:
		return "SHA512", nil
	case crypto.SHA1:
		return "SHA1", nil
	default:
		return "", fmt.Errorf("cngSigner: unsupported hash %v", h)
	}
}

// acquireSigner obtains a crypto.Signer for the cert's CNG private key using the
// .NET-equivalent flags (SILENT | PREFER_NCRYPT, no cache). pub is the leaf's
// public key (used for crypto.Signer.Public()). #147: this replaces the
// certtostore.CertKey path that access-violates on valid PCP/TPM keys. The
// caller-free + key-spec ownership contract is honored: a legacy CSP handle is
// released (CryptReleaseContext) and rejected; only an NCrypt handle is kept.
func acquireSigner(ctx *windows.CertContext, pub crypto.PublicKey) (crypto.Signer, error) {
	if !hasPrivateKeyBinding(ctx) {
		return nil, errors.New("certificate has no private-key binding")
	}
	var (
		kh         uintptr
		keySpec    uint32
		callerFree int32
	)
	r, _, err := procAcquire.Call(
		uintptr(unsafe.Pointer(ctx)),
		cryptAcquireSilentFlag|cryptAcquirePreferNCryptFlag,
		0, // pvReserved, must be null
		uintptr(unsafe.Pointer(&kh)),
		uintptr(unsafe.Pointer(&keySpec)),
		uintptr(unsafe.Pointer(&callerFree)))
	if r == 0 {
		return nil, fmt.Errorf("CryptAcquireCertificatePrivateKey: %w", err)
	}
	if keySpec != certNCryptKeySpec {
		// Legacy CSP handle (HCRYPTPROV). We only support CNG/NCrypt keys;
		// release per the ownership contract before rejecting.
		if callerFree != 0 && kh != 0 {
			_, _, _ = procRelCtx.Call(kh, 0) // CryptReleaseContext(hProv, 0)
		}
		return nil, errors.New("acquired key is a legacy CSP key, not CNG/NCrypt")
	}
	// The signer takes ownership of the NCrypt key handle (freed only when
	// callerFree) and the cert context. See cngSigner doc.
	return &cngSigner{handle: kh, callerFree: callerFree != 0, ctx: ctx, pub: pub}, nil
}
