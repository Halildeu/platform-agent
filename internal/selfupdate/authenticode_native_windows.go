//go:build windows

package selfupdate

import (
	"crypto/sha1"
	"crypto/x509"
	"encoding/hex"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	cmsgSignerInfoParam = 6
)

var (
	modcrypt32           = windows.NewLazySystemDLL("crypt32.dll")
	procCryptMsgGetParam = modcrypt32.NewProc("CryptMsgGetParam")
	procCryptMsgClose    = modcrypt32.NewProc("CryptMsgClose")
)

// NewNativeAuthenticodeVerifier returns the Windows Authenticode verifier used
// by AG-029 staging before a binary can become an activation candidate.
func NewNativeAuthenticodeVerifier() AuthenticodeVerifier {
	return nativeAuthenticodeVerifier{}
}

type nativeAuthenticodeVerifier struct{}

func (nativeAuthenticodeVerifier) VerifyAuthenticode(path string) (AuthenticodeEvidence, ErrorCode, string) {
	if strings.TrimSpace(path) == "" {
		return AuthenticodeEvidence{}, ErrSignatureInvalid, "candidate path is required for authenticode verification"
	}
	trustEvidence, code, reason := verifyWinTrust(path)
	if code != "" {
		return AuthenticodeEvidence{}, code, reason
	}
	leaf, code, reason := extractPrimarySignerCertificate(path)
	if code != "" {
		return AuthenticodeEvidence{}, code, reason
	}
	return certificateToAuthenticodeEvidence(leaf, time.Now(), trustEvidence), "", ""
}

type winTrustEvidence struct {
	Timestamped bool
	SigningTime time.Time
}

func verifyWinTrust(path string) (winTrustEvidence, ErrorCode, string) {
	path16, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return winTrustEvidence{}, ErrSignatureInvalid, "encode candidate path failed"
	}
	file := &windows.WinTrustFileInfo{
		Size:     uint32(unsafe.Sizeof(windows.WinTrustFileInfo{})),
		FilePath: path16,
	}
	data := &windows.WinTrustData{
		Size:                            uint32(unsafe.Sizeof(windows.WinTrustData{})),
		UIChoice:                        windows.WTD_UI_NONE,
		RevocationChecks:                windows.WTD_REVOKE_WHOLECHAIN,
		UnionChoice:                     windows.WTD_CHOICE_FILE,
		StateAction:                     windows.WTD_STATEACTION_VERIFY,
		FileOrCatalogOrBlobOrSgnrOrCert: unsafe.Pointer(file),
		ProvFlags: windows.WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT |
			windows.WTD_DISABLE_MD2_MD4,
		UIContext: windows.WTD_UICONTEXT_EXECUTE,
	}
	verifyErr := windows.WinVerifyTrustEx(windows.InvalidHWND, &windows.WINTRUST_ACTION_GENERIC_VERIFY_V2, data)
	evidence := winTrustTimestampEvidence(data.StateData)
	data.StateAction = windows.WTD_STATEACTION_CLOSE
	_ = windows.WinVerifyTrustEx(windows.InvalidHWND, &windows.WINTRUST_ACTION_GENERIC_VERIFY_V2, data)
	if verifyErr != nil {
		return winTrustEvidence{}, ErrSignatureInvalid, "authenticode trust verification failed"
	}
	return evidence, "", ""
}

func winTrustTimestampEvidence(state windows.Handle) winTrustEvidence {
	if state == 0 {
		return winTrustEvidence{}
	}
	provData := wTHelperProvDataFromStateData(state)
	if provData == 0 {
		return winTrustEvidence{}
	}
	signer := wTHelperGetProvSignerFromChain(provData, 0, false, 0)
	if signer == nil {
		return winTrustEvidence{}
	}
	var counterSigner *cryptProviderSgnr
	if signer.CsCounterSigners > 0 {
		counterSigner = wTHelperGetProvSignerFromChain(provData, 0, true, 0)
	}
	if signer.CsCounterSigners == 0 && counterSigner == nil {
		return winTrustEvidence{}
	}
	if zeroFiletime(signer.SftVerifyAsOf) {
		return winTrustEvidence{Timestamped: true}
	}
	return winTrustEvidence{
		Timestamped: true,
		SigningTime: filetimeToTime(signer.SftVerifyAsOf),
	}
}

func zeroFiletime(ft windows.Filetime) bool {
	return ft.LowDateTime == 0 && ft.HighDateTime == 0
}

func filetimeToTime(ft windows.Filetime) time.Time {
	return time.Unix(0, ft.Nanoseconds()).UTC()
}

func extractPrimarySignerCertificate(path string) (*x509.Certificate, ErrorCode, string) {
	path16, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, ErrSignatureInvalid, "encode candidate path failed"
	}
	var (
		encoding    uint32
		contentType uint32
		formatType  uint32
		certStore   windows.Handle
		msg         windows.Handle
	)
	err = windows.CryptQueryObject(
		windows.CERT_QUERY_OBJECT_FILE,
		unsafe.Pointer(path16),
		windows.CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
		windows.CERT_QUERY_FORMAT_FLAG_BINARY,
		0,
		&encoding,
		&contentType,
		&formatType,
		&certStore,
		&msg,
		nil,
	)
	if err != nil {
		return nil, ErrSignatureInvalid, "extract authenticode signature failed"
	}
	if certStore != 0 {
		defer func() { _ = windows.CertCloseStore(certStore, 0) }()
	}
	if msg != 0 {
		defer cryptMsgClose(msg)
	}

	signerInfo, code, reason := cryptMsgSignerInfo(msg)
	if code != "" {
		return nil, code, reason
	}
	find := windows.CertInfo{
		Issuer:       signerInfo.Issuer,
		SerialNumber: signerInfo.SerialNumber,
	}
	ctx, err := windows.CertFindCertificateInStore(
		certStore,
		windows.X509_ASN_ENCODING|windows.PKCS_7_ASN_ENCODING,
		0,
		windows.CERT_FIND_SUBJECT_CERT,
		unsafe.Pointer(&find),
		nil,
	)
	if err != nil || ctx == nil {
		return nil, ErrSignatureInvalid, "signer certificate not found"
	}
	defer func() { _ = windows.CertFreeCertificateContext(ctx) }()

	raw := unsafe.Slice(ctx.EncodedCert, int(ctx.Length))
	cert, err := x509.ParseCertificate(append([]byte(nil), raw...))
	if err != nil {
		return nil, ErrSignatureInvalid, "parse signer certificate failed"
	}
	return cert, "", ""
}

func certificateToAuthenticodeEvidence(cert *x509.Certificate, now time.Time, trust winTrustEvidence) AuthenticodeEvidence {
	sum := sha1.Sum(cert.Raw)
	ev := AuthenticodeEvidence{
		ChainValid:        true,
		HasCodeSigningEKU: hasCodeSigningEKU(cert),
		SignerThumbprint:  strings.ToUpper(hex.EncodeToString(sum[:])),
		CurrentTimeValid:  !now.Before(cert.NotBefore) && !now.After(cert.NotAfter),
	}
	if trust.Timestamped {
		ev.Timestamped = true
		ev.SigningTimeValid = !trust.SigningTime.IsZero() &&
			!trust.SigningTime.Before(cert.NotBefore) &&
			!trust.SigningTime.After(cert.NotAfter)
	}
	return ev
}

func hasCodeSigningEKU(cert *x509.Certificate) bool {
	for _, eku := range cert.ExtKeyUsage {
		if eku == x509.ExtKeyUsageCodeSigning {
			return true
		}
	}
	return false
}

func cryptMsgSignerInfo(msg windows.Handle) (*cmsgSignerInfo, ErrorCode, string) {
	if msg == 0 {
		return nil, ErrSignatureInvalid, "signature message handle missing"
	}
	var size uint32
	if err := cryptMsgGetParam(msg, cmsgSignerInfoParam, 0, nil, &size); err != nil {
		return nil, ErrSignatureInvalid, "read signer info size failed"
	}
	if size == 0 {
		return nil, ErrSignatureInvalid, "signer info is empty"
	}
	buf := make([]byte, size)
	if err := cryptMsgGetParam(msg, cmsgSignerInfoParam, 0, unsafe.Pointer(&buf[0]), &size); err != nil {
		return nil, ErrSignatureInvalid, "read signer info failed"
	}
	return (*cmsgSignerInfo)(unsafe.Pointer(&buf[0])), "", ""
}

func cryptMsgGetParam(msg windows.Handle, paramType, index uint32, data unsafe.Pointer, dataLen *uint32) error {
	r1, _, e1 := syscall.SyscallN(
		procCryptMsgGetParam.Addr(),
		uintptr(msg),
		uintptr(paramType),
		uintptr(index),
		uintptr(data),
		uintptr(unsafe.Pointer(dataLen)),
	)
	if r1 == 0 {
		if e1 != 0 {
			return e1
		}
		return syscall.EINVAL
	}
	return nil
}

func cryptMsgClose(msg windows.Handle) {
	syscall.SyscallN(procCryptMsgClose.Addr(), uintptr(msg))
}

type cmsgSignerInfo struct {
	Version                 uint32
	Issuer                  windows.CertNameBlob
	SerialNumber            windows.CryptIntegerBlob
	HashAlgorithm           windows.CryptAlgorithmIdentifier
	HashEncryptionAlgorithm windows.CryptAlgorithmIdentifier
	EncryptedHash           windows.CryptDataBlob
	AuthAttrs               cryptAttributes
	UnauthAttrs             cryptAttributes
}

type cryptAttributes struct {
	Count uint32
	Attr  *cryptAttribute
}

type cryptAttribute struct {
	ObjID  *byte
	Count  uint32
	Values *windows.CryptAttrBlob
}
