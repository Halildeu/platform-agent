package tpmenroll

import (
	"encoding/hex"
	"fmt"
	"math/big"
)

// EKObjectAttributes is the TCG default RSA EK template's TPMA_OBJECT:
// fixedTPM|fixedParent|sensitiveDataOrigin|adminWithPolicy|restricted|decrypt (0x000300b2).
const EKObjectAttributes uint32 = 0x000300b2

// TPMT_SYM_DEF_OBJECT for the EK storage key: AES-128-CFB.
const (
	symAlgAES  = 0x0006
	symAES128  = 128
	symModeCFB = 0x0043
)

// wellKnownRSAEKPolicy is the TCG "low-range" RSA-2048 EK authPolicy
// (PolicySecret(TPM_RH_ENDORSEMENT)); every compliant TPM ships this EK template
// authPolicy, so it is a constant, not per-device. Matches the golden ekPub.
var wellKnownRSAEKPolicy = mustHexBytes("837197674484b3f81a90cc8d46a5d724fd52d76e06520b64f2a1da1b331469aa")

func mustHexBytes(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic("tpmenroll: bad hex constant: " + err.Error())
	}
	return b
}

// BuildRSAStorageEKPublicArea constructs the TPM2B_PUBLIC for an RSA-2048 storage
// Endorsement Key in the TCG default template: nameAlg SHA-256, the well-known EK
// authPolicy, an AES-128-CFB symmetric block, scheme NULL, exponent default. The
// device key + AK use BuildRSASigningPublicArea (signing template); the EK is the
// only storage/decrypt key, hence its own builder. Reproduces the golden ekPub
// byte-for-byte (ektemplate_test.go).
func BuildRSAStorageEKPublicArea(modulus *big.Int) ([]byte, error) {
	if modulus == nil || modulus.Sign() <= 0 {
		return nil, fmt.Errorf("tpmenroll: positive RSA modulus required")
	}
	mod := modulus.Bytes()
	keyBits := len(mod) * 8
	if keyBits < 2048 || keyBits > 16384 {
		return nil, fmt.Errorf("tpmenroll: implausible EK key size %d bits", keyBits)
	}
	w := &tpmtWriter{}
	w.u16(AlgRSA)             // type
	w.u16(AlgSHA256)          // nameAlg
	w.u32(EKObjectAttributes) // objectAttributes
	w.tpm2b(wellKnownRSAEKPolicy)
	// TPMS_RSA_PARMS: symmetric(TPMT_SYM_DEF_OBJECT) ‖ scheme ‖ keyBits ‖ exponent
	w.u16(symAlgAES)  // symmetric.algorithm = AES
	w.u16(symAES128)  // symmetric.keyBits = 128
	w.u16(symModeCFB) // symmetric.mode = CFB
	w.u16(AlgNull)    // scheme = NULL (a decrypt/storage key)
	w.u16(keyBits)
	w.u32(0) // exponent 0 → TPM default 65537
	w.tpm2b(mod)
	return wrapTPM2B(w.b), nil
}
