package tpmenroll

import (
	"crypto/hmac"
	"encoding/binary"
	"fmt"
	"hash"
)

// kdfa is the TPM 2.0 KDFa (TCG Part 1 §11.4.10.2, SP800-108 counter mode):
//
//	for each block i=1..n: HMAC_h(key, BE32(i) ‖ label ‖ 0x00 ‖ contextU ‖ contextV ‖ BE32(bits))
//
// concatenated, truncated to ceil(bits/8) bytes; if bits is not a byte multiple
// the most-significant bits of the first byte are masked off. A deliberate port
// of the backend's TpmKdfa so the agent's TPM2_ActivateCredential interoperates
// with the server's TPM2_MakeCredential byte-for-byte.
func kdfa(newH func() hash.Hash, key []byte, label string, contextU, contextV []byte, bits int) ([]byte, error) {
	if bits <= 0 {
		return nil, fmt.Errorf("tpmenroll: kdfa bits must be > 0")
	}
	out := make([]byte, 0, ((bits+7)/8)+newH().Size())
	want := (bits + 7) / 8
	var be [4]byte
	counter := uint32(0)
	for len(out) < want {
		counter++
		m := hmac.New(newH, key)
		binary.BigEndian.PutUint32(be[:], counter)
		m.Write(be[:])
		m.Write([]byte(label))
		m.Write([]byte{0x00})
		m.Write(contextU)
		m.Write(contextV)
		binary.BigEndian.PutUint32(be[:], uint32(bits))
		m.Write(be[:])
		out = m.Sum(out)
	}
	out = out[:want]
	if rem := bits % 8; rem != 0 {
		out[0] &= byte((1 << rem) - 1)
	}
	return out, nil
}
