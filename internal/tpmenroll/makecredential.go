package tpmenroll

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"hash"
)

// SecretBytes is the AES-128 credential size (matches the backend's SECRET_BYTES
// and the golden vector's 16-byte secret).
const SecretBytes = 16

// oaepLabel is the TCG "IDENTITY" label with its mandatory null terminator,
// used by TPM2_MakeCredential's RSA-OAEP of the protection seed.
var oaepLabel = []byte("IDENTITY\x00")

// Credential is the TPM2_MakeCredential output: the idObject the device feeds to
// TPM2_ActivateCredential, plus the OAEP-wrapped seed.
type Credential struct {
	CredentialBlob []byte // idObject = TPM2B(outerHMAC) ‖ encIdentity
	EncSecret      []byte // RSA-OAEP(ekPub, seed)
}

// MakeCredential is the SERVER side (TPM2_MakeCredential). The agent never calls
// it in production — it lives here so the round-trip test can play "backend" and
// drive ActivateCredential without the live service. It is a deliberate port of
// the backend's TpmMakeCredential.make so the two implement the identical wire
// algorithm. seed must be digestSize(nameAlg) bytes (the test injects a fixed
// seed; production randomness is the server's concern).
func MakeCredential(ekPub *rsa.PublicKey, nameAlg int, akName, secret, seed []byte) (*Credential, error) {
	if ekPub == nil {
		return nil, fmt.Errorf("tpmenroll: ekPub required")
	}
	if len(akName) == 0 {
		return nil, fmt.Errorf("tpmenroll: akName (TPM Name) required")
	}
	if len(secret) != SecretBytes {
		return nil, fmt.Errorf("tpmenroll: credential secret must be %d bytes (AES-128)", SecretBytes)
	}
	h, ctor, ds, err := hashFor(nameAlg)
	if err != nil {
		return nil, err
	}
	if len(seed) != ds {
		return nil, fmt.Errorf("tpmenroll: seed must be %d bytes for nameAlg 0x%x", ds, nameAlg)
	}

	encSecret, err := rsa.EncryptOAEP(h(), rand.Reader, ekPub, seed, oaepLabel)
	if err != nil {
		return nil, fmt.Errorf("tpmenroll: OAEP wrap seed: %w", err)
	}

	encIdentity, err := aesCFB(ctor, seed, akName, tpm2bBytes(secret), false)
	if err != nil {
		return nil, err
	}

	outerHMAC, err := integrityHMAC(ctor, seed, ds, encIdentity, akName)
	if err != nil {
		return nil, err
	}

	return &Credential{
		CredentialBlob: concat(tpm2bBytes(outerHMAC), encIdentity),
		EncSecret:      encSecret,
	}, nil
}

// ActivateCredential is the DEVICE side (TPM2_ActivateCredential): recover the
// server's secret using the EK private key (to OAEP-decrypt the seed) and the AK
// Name (which keys the integrity HMAC + storage KDF). A failed integrity check is
// fail-closed. Constant-time HMAC compare. This is what the MockTPMDevice and the
// real go-tpm path expose; recovering the server's secret proves EK↔AK live in
// the same TPM (the backend's V10/V3).
func ActivateCredential(ekPriv *rsa.PrivateKey, nameAlg int, akName, credentialBlob, encSecret []byte) ([]byte, error) {
	if ekPriv == nil {
		return nil, fmt.Errorf("tpmenroll: ek private key required")
	}
	if len(akName) == 0 {
		return nil, fmt.Errorf("tpmenroll: akName required")
	}
	h, ctor, ds, err := hashFor(nameAlg)
	if err != nil {
		return nil, err
	}

	// idObject = TPM2B(outerHMAC) ‖ encIdentity
	if len(credentialBlob) < 2 {
		return nil, fmt.Errorf("tpmenroll: credentialBlob too short")
	}
	hmacLen := int(binary.BigEndian.Uint16(credentialBlob[0:2]))
	if hmacLen != ds || 2+hmacLen > len(credentialBlob) {
		return nil, fmt.Errorf("tpmenroll: bad credentialBlob outer-HMAC length %d", hmacLen)
	}
	outerHMAC := credentialBlob[2 : 2+hmacLen]
	encIdentity := credentialBlob[2+hmacLen:]
	if len(encIdentity) == 0 {
		return nil, fmt.Errorf("tpmenroll: credentialBlob missing encIdentity")
	}

	seed, err := rsa.DecryptOAEP(h(), rand.Reader, ekPriv, encSecret, oaepLabel)
	if err != nil {
		return nil, fmt.Errorf("tpmenroll: OAEP unwrap seed (activation failed): %w", err)
	}
	if len(seed) != ds {
		return nil, fmt.Errorf("tpmenroll: recovered seed wrong size")
	}

	// Verify the outer integrity HMAC BEFORE decrypting (fail-closed, no padding oracle).
	expected, err := integrityHMAC(ctor, seed, ds, encIdentity, akName)
	if err != nil {
		return nil, err
	}
	if !hmac.Equal(expected, outerHMAC) {
		return nil, fmt.Errorf("tpmenroll: credential integrity HMAC mismatch (activation failed)")
	}

	plain, err := aesCFB(ctor, seed, akName, encIdentity, true) // CFB decrypt
	if err != nil {
		return nil, err
	}
	// plain = TPM2B(secret)
	if len(plain) < 2 {
		return nil, fmt.Errorf("tpmenroll: recovered plaintext too short")
	}
	sLen := int(binary.BigEndian.Uint16(plain[0:2]))
	if 2+sLen != len(plain) {
		return nil, fmt.Errorf("tpmenroll: recovered secret TPM2B length mismatch")
	}
	return plain[2 : 2+sLen], nil
}

// aesCFB runs AES-128-CFB128(IV=0) over data with symKey = KDFa(STORAGE, seed,
// akName, 128) — the TPM2_MakeCredential symmetric layer. decrypt=false for Make
// (encrypt), true for Activate (decrypt).
func aesCFB(ctor func() hash.Hash, seed, akName, data []byte, decrypt bool) ([]byte, error) {
	symKey, err := kdfa(ctor, seed, "STORAGE", akName, nil, 128)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(symKey)
	if err != nil {
		return nil, err
	}
	return cfb128(block, make([]byte, aes.BlockSize), data, decrypt), nil
}

// cfb128 is full-block (segment size = block size) CFB, matching the JDK
// "AES/CFB/NoPadding" and the TPM's CFB. We implement it directly rather than use
// crypto/cipher's deprecated NewCFB*; verified against the NIST SP800-38A
// CFB128-AES128 vectors (makecredential_test.go). The feedback register is always
// the CIPHERTEXT block (output when encrypting, input when decrypting); the final
// partial block uses only the needed keystream bytes.
func cfb128(block cipher.Block, iv, data []byte, decrypt bool) []byte {
	bs := block.BlockSize()
	out := make([]byte, len(data))
	feedback := make([]byte, bs)
	copy(feedback, iv)
	ks := make([]byte, bs)
	for i := 0; i < len(data); i += bs {
		block.Encrypt(ks, feedback)
		n := bs
		if r := len(data) - i; r < bs {
			n = r
		}
		for j := 0; j < n; j++ {
			out[i+j] = data[i+j] ^ ks[j]
		}
		// Next feedback = this ciphertext block (only meaningful for full blocks).
		if n == bs {
			if decrypt {
				copy(feedback, data[i:i+bs])
			} else {
				copy(feedback, out[i:i+bs])
			}
		}
	}
	return out
}

func integrityHMAC(ctor func() hash.Hash, seed []byte, ds int, encIdentity, akName []byte) ([]byte, error) {
	hmacKey, err := kdfa(ctor, seed, "INTEGRITY", nil, nil, ds*8)
	if err != nil {
		return nil, err
	}
	m := hmac.New(ctor, hmacKey)
	m.Write(encIdentity)
	m.Write(akName)
	return m.Sum(nil), nil
}

// hashFor returns a single hash, a constructor (for hmac/kdfa), and the digest
// size, for a TPM nameAlg. Rejects weak/unknown algs.
func hashFor(nameAlg int) (func() hash.Hash, func() hash.Hash, int, error) {
	switch nameAlg {
	case AlgSHA256:
		return sha256.New, sha256.New, 32, nil
	case AlgSHA384:
		return sha512.New384, sha512.New384, 48, nil
	case AlgSHA512:
		return sha512.New, sha512.New, 64, nil
	default:
		return nil, nil, 0, fmt.Errorf("tpmenroll: unsupported nameAlg 0x%x", nameAlg)
	}
}

func tpm2bBytes(v []byte) []byte {
	out := make([]byte, 2+len(v))
	binary.BigEndian.PutUint16(out[0:2], uint16(len(v)))
	copy(out[2:], v)
	return out
}

func concat(parts ...[]byte) []byte {
	n := 0
	for _, p := range parts {
		n += len(p)
	}
	out := make([]byte, 0, n)
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}
