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
	ncryptMachineKey   = 0x20

	ncryptAlgorithmProperty = "Algorithm Name" // NCRYPT_ALGORITHM_PROPERTY
)

var (
	crypt32Mod  = windows.NewLazySystemDLL("crypt32.dll")
	advapi32Mod = windows.NewLazySystemDLL("advapi32.dll")
	ncryptMod   = windows.NewLazySystemDLL("ncrypt.dll")
	procAcquire = crypt32Mod.NewProc("CryptAcquireCertificatePrivateKey")
	procSign    = ncryptMod.NewProc("NCryptSignHash")
	procFreeObj = ncryptMod.NewProc("NCryptFreeObject")
	procGetProp = ncryptMod.NewProc("NCryptGetProperty")
	procOpenSP  = ncryptMod.NewProc("NCryptOpenStorageProvider")
	procOpenKey = ncryptMod.NewProc("NCryptOpenKey")
	procRelCtx  = advapi32Mod.NewProc("CryptReleaseContext")
)

type cryptKeyProvInfo struct {
	ContainerName *uint16
	ProvName      *uint16
	ProvType      uint32
	Flags         uint32
	ProvParamLen  uint32
	ProvParam     uintptr
	KeySpec       uint32
}

type keyProviderInfo struct {
	ContainerName string
	ProviderName  string
	ProviderType  uint32
	Flags         uint32
	KeySpec       uint32
}

type bcryptPKCS1PaddingInfo struct{ AlgID *uint16 }

type bcryptPSSPaddingInfo struct {
	AlgID *uint16
	Salt  uint32
}

// cngSigner is a crypto.Signer over an NCRYPT_KEY_HANDLE acquired via
// CryptAcquireCertificatePrivateKey. It satisfies tls.Certificate.PrivateKey.
//
// It keeps the cert context alive (#147): the NCRYPT key handle keeps an
// internal association to the context on some providers, so the context must
// outlive the key handle. ERP-MOBIL M2 dry-run evidence (#165) showed that
// calling CertFreeCertificateContext during process cleanup can still
// access-violate on valid machine certs. The signer therefore frees the NCrypt
// handle when allowed, but deliberately retains the duplicated cert context for
// process lifetime. Cert loads happen on startup/rotation, making this a tiny
// bounded leak rather than a crash-prone cleanup path.
type cngSigner struct {
	handle     uintptr
	provider   uintptr
	callerFree bool // pfCallerFreeProvOrNCryptKey — only then may we free
	ctx        *windows.CertContext
	pub        crypto.PublicKey
}

func (s *cngSigner) Public() crypto.PublicKey { return s.pub }

// Close frees the NCRYPT key handle only when the acquire reported caller-free.
// It intentionally does not call CertFreeCertificateContext; see cngSigner.
// Idempotent.
func (s *cngSigner) Close() {
	if s.handle != 0 && s.callerFree {
		_, _, _ = procFreeObj.Call(s.handle) // NCRYPT key spec only (legacy rejected at acquire)
	}
	if s.provider != 0 {
		_, _, _ = procFreeObj.Call(s.provider)
	}
	s.handle = 0
	s.provider = 0
	s.ctx = nil
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

// acquireSigner obtains a crypto.Signer for the cert's CNG private key. AgentPC2
// live evidence (#1643) proved that CryptAcquireCertificatePrivateKey can still
// access-violate on valid AD CS CNG machine certs. Prefer the explicit provider
// path: read CERT_KEY_PROV_INFO, open the KSP, then NCryptOpenKey by container.
// This avoids the crash-prone native acquire helper entirely for normal AD CS
// machine certificates.
func acquireSigner(ctx *windows.CertContext, pub crypto.PublicKey) (crypto.Signer, error) {
	if !hasPrivateKeyBinding(ctx) {
		return nil, errors.New("certificate has no private-key binding")
	}
	if signer, err := acquireSignerFromKeyProvInfo(ctx, pub); err == nil {
		return signer, nil
	} else if !errors.Is(err, errNoKeyProvInfo) {
		return nil, err
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
	ncryptProbeOK := false
	if keySpec != certNCryptKeySpec {
		ncryptProbeOK = ncryptHandleUsable(kh)
	}
	if !acquireResultIsNCrypt(keySpec, ncryptProbeOK) {
		// Legacy CSP handle (HCRYPTPROV). We only support CNG/NCrypt keys;
		// release per the ownership contract before rejecting.
		if callerFree != 0 && kh != 0 {
			_, _, _ = procRelCtx.Call(kh, 0) // CryptReleaseContext(hProv, 0)
		}
		return nil, fmt.Errorf("acquired key is a legacy CSP key, not CNG/NCrypt (keySpec=0x%x)", keySpec)
	}
	// The signer takes ownership of the NCrypt key handle (freed only when
	// callerFree) and retains the cert context for process lifetime. See
	// cngSigner doc.
	return &cngSigner{handle: kh, callerFree: callerFree != 0, ctx: ctx, pub: pub}, nil
}

var errNoKeyProvInfo = errors.New("certificate has no CERT_KEY_PROV_INFO")

func acquireSignerFromKeyProvInfo(ctx *windows.CertContext, pub crypto.PublicKey) (crypto.Signer, error) {
	info, err := keyProvInfo(ctx)
	if err != nil {
		return nil, err
	}
	providerName := info.ProviderName
	containerName := info.ContainerName
	if providerName == "" || containerName == "" {
		return nil, fmt.Errorf("CERT_KEY_PROV_INFO missing provider/container name")
	}
	if info.ProviderType != 0 {
		return nil, fmt.Errorf("certificate private key provider is legacy CSP, not CNG/KSP (provider=%q type=%d keySpec=0x%x)",
			providerName, info.ProviderType, info.KeySpec)
	}
	providerNamePtr, err := windows.UTF16PtrFromString(providerName)
	if err != nil {
		return nil, fmt.Errorf("encode KSP provider name: %w", err)
	}
	containerNamePtr, err := windows.UTF16PtrFromString(containerName)
	if err != nil {
		return nil, fmt.Errorf("encode KSP container name: %w", err)
	}

	var provider uintptr
	r, _, _ := procOpenSP.Call(
		uintptr(unsafe.Pointer(&provider)),
		uintptr(unsafe.Pointer(providerNamePtr)),
		0,
	)
	if r != 0 {
		return nil, fmt.Errorf("NCryptOpenStorageProvider(%q) failed: NTSTATUS 0x%x", providerName, r)
	}
	var key uintptr
	r, _, _ = procOpenKey.Call(
		provider,
		uintptr(unsafe.Pointer(&key)),
		uintptr(unsafe.Pointer(containerNamePtr)),
		uintptr(info.KeySpec),
		ncryptMachineKey,
	)
	if r != 0 {
		_, _, _ = procFreeObj.Call(provider)
		return nil, fmt.Errorf("NCryptOpenKey(provider=%q container=%q keySpec=0x%x machine=true) failed: NTSTATUS 0x%x",
			providerName, containerName, info.KeySpec, r)
	}
	if !ncryptHandleUsable(key) {
		_, _, _ = procFreeObj.Call(key)
		_, _, _ = procFreeObj.Call(provider)
		return nil, fmt.Errorf("NCryptOpenKey(provider=%q container=%q) returned unusable key handle", providerName, containerName)
	}
	return &cngSigner{handle: key, provider: provider, callerFree: true, ctx: ctx, pub: pub}, nil
}

func keyProvInfo(ctx *windows.CertContext) (*keyProviderInfo, error) {
	var size uint32
	r, _, _ := procCertGetCertificateContextProperty.Call(
		uintptr(unsafe.Pointer(ctx)),
		certKeyProvInfoPropID,
		0,
		uintptr(unsafe.Pointer(&size)),
	)
	if r == 0 || size == 0 {
		return nil, errNoKeyProvInfo
	}
	buf := make([]byte, size)
	r, _, err := procCertGetCertificateContextProperty.Call(
		uintptr(unsafe.Pointer(ctx)),
		certKeyProvInfoPropID,
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)),
	)
	if r == 0 {
		return nil, fmt.Errorf("CertGetCertificateContextProperty(CERT_KEY_PROV_INFO): %w", err)
	}
	if uintptr(len(buf)) < unsafe.Sizeof(cryptKeyProvInfo{}) {
		return nil, fmt.Errorf("CERT_KEY_PROV_INFO too small: %d bytes", len(buf))
	}
	raw := (*cryptKeyProvInfo)(unsafe.Pointer(&buf[0]))
	return &keyProviderInfo{
		ContainerName: windows.UTF16PtrToString(raw.ContainerName),
		ProviderName:  windows.UTF16PtrToString(raw.ProvName),
		ProviderType:  raw.ProvType,
		Flags:         raw.Flags,
		KeySpec:       raw.KeySpec,
	}, nil
}

func acquireResultIsNCrypt(keySpec uint32, ncryptProbeOK bool) bool {
	return keySpec == certNCryptKeySpec || ncryptProbeOK
}

func ncryptHandleUsable(handle uintptr) bool {
	if handle == 0 {
		return false
	}
	prop, err := windows.UTF16PtrFromString(ncryptAlgorithmProperty)
	if err != nil {
		return false
	}
	buf := make([]byte, 512)
	var size uint32
	r, _, _ := procGetProp.Call(
		handle,
		uintptr(unsafe.Pointer(prop)),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
		uintptr(unsafe.Pointer(&size)),
		0,
	)
	return r == 0 && size > 0
}
