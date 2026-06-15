package tpmenroll

import "fmt"

// TPM_GENERATED / TPMI_ST_ATTEST (TCG Part 2).
const (
	tpmGenerated    = 0xFF544347
	stAttestCertify = 0x8017
	stAttestQuote   = 0x8018
	clockInfoLen    = 17 // clock(8)+resetCount(4)+restartCount(4)+safe(1)
	firmwareVersLen = 8
)

// PCRSelection is one TPML_PCR_SELECTION entry: a bank (hashAlg) + its bitmap.
type PCRSelection struct {
	HashAlg int
	Bitmap  []byte
}

// AttestInfo is a parsed TPMS_ATTEST, the structure a TPM signs in TPM2_Certify
// (V4) and TPM2_Quote (V5). A deliberate port of the backend's TpmsAttest parser
// so the agent's produced attestations parse identically (big-endian,
// bounds-checked, fully consumed).
type AttestInfo struct {
	Type            int
	QualifiedSigner []byte
	ExtraData       []byte
	CertifiedName   []byte         // CERTIFY only
	PCRSelections   []PCRSelection // QUOTE only
	PCRDigest       []byte         // QUOTE only
}

func (a *AttestInfo) IsCertify() bool { return a.Type == stAttestCertify }
func (a *AttestInfo) IsQuote() bool   { return a.Type == stAttestQuote }

// ParseAttest parses a TPMS_ATTEST (the inverse of the marshalers below; used to
// round-trip our own output and to cross-check the golden quote/certify attests).
func ParseAttest(raw []byte) (*AttestInfo, error) {
	if raw == nil {
		return nil, fmt.Errorf("tpmenroll: attest bytes required")
	}
	c := &cursor{b: raw}
	magic, err := c.u32("magic")
	if err != nil {
		return nil, err
	}
	if magic != tpmGenerated {
		return nil, fmt.Errorf("tpmenroll: not TPM_GENERATED (magic=0x%x)", magic)
	}
	typ, err := c.u16("type")
	if err != nil {
		return nil, err
	}
	qualifiedSigner, err := c.tpm2b("qualifiedSigner")
	if err != nil {
		return nil, err
	}
	extraData, err := c.tpm2b("extraData")
	if err != nil {
		return nil, err
	}
	if err := c.skip(clockInfoLen, "clockInfo"); err != nil {
		return nil, err
	}
	if err := c.skip(firmwareVersLen, "firmwareVersion"); err != nil {
		return nil, err
	}
	info := &AttestInfo{Type: typ, QualifiedSigner: qualifiedSigner, ExtraData: extraData}
	switch typ {
	case stAttestCertify:
		if info.CertifiedName, err = c.tpm2b("certifyInfo.name"); err != nil {
			return nil, err
		}
		if _, err = c.tpm2b("certifyInfo.qualifiedName"); err != nil {
			return nil, err
		}
	case stAttestQuote:
		count, err := c.u32("pcrSelection.count")
		if err != nil {
			return nil, err
		}
		if count > 16 {
			return nil, fmt.Errorf("tpmenroll: implausible PCR selection count %d", count)
		}
		for i := uint32(0); i < count; i++ {
			hashAlg, err := c.u16("pcrSelect.hashAlg")
			if err != nil {
				return nil, err
			}
			n, err := c.u8("pcrSelect.sizeofSelect")
			if err != nil {
				return nil, err
			}
			bitmap, err := c.take(n, "pcrSelect.bitmap")
			if err != nil {
				return nil, err
			}
			info.PCRSelections = append(info.PCRSelections, PCRSelection{HashAlg: hashAlg, Bitmap: bitmap})
		}
		if info.PCRDigest, err = c.tpm2b("quoteInfo.pcrDigest"); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("tpmenroll: unsupported attest type 0x%x", typ)
	}
	if err := c.requireFullyConsumed(); err != nil {
		return nil, err
	}
	return info, nil
}

// MarshalCertifyAttest builds a TPMS_ATTEST(CERTIFY): the AK attests that
// certifiedName (the device key's TPM Name) is TPM-resident. clockInfo +
// firmwareVersion are fixed zero blocks (the verifier skips them).
func MarshalCertifyAttest(qualifiedSigner, extraData, certifiedName []byte) []byte {
	w := &tpmtWriter{}
	w.u32(tpmGenerated)
	w.u16(stAttestCertify)
	w.tpm2b(qualifiedSigner)
	w.tpm2b(extraData)
	w.b = append(w.b, make([]byte, clockInfoLen+firmwareVersLen)...)
	w.tpm2b(certifiedName)
	w.tpm2b(nil) // qualifiedName (empty; consumed-not-validated by the verifier)
	return w.b
}

// MarshalQuoteAttest builds a TPMS_ATTEST(QUOTE) over extraData (the issued
// nonce) with the attested PCR banks + aggregate digest.
func MarshalQuoteAttest(qualifiedSigner, extraData []byte, sels []PCRSelection, pcrDigest []byte) []byte {
	w := &tpmtWriter{}
	w.u32(tpmGenerated)
	w.u16(stAttestQuote)
	w.tpm2b(qualifiedSigner)
	w.tpm2b(extraData)
	w.b = append(w.b, make([]byte, clockInfoLen+firmwareVersLen)...)
	w.u32(uint32(len(sels)))
	for _, s := range sels {
		w.u16(s.HashAlg)
		w.u8(len(s.Bitmap))
		w.b = append(w.b, s.Bitmap...)
	}
	w.tpm2b(pcrDigest)
	return w.b
}

// --- small reader/writer extensions (same package as cursor/tpmtWriter) ---

func (w *tpmtWriter) u8(v int) { w.b = append(w.b, byte(v)) }

func (c *cursor) u8(field string) (int, error) {
	if c.pos+1 > len(c.b) {
		return 0, fmt.Errorf("tpmenroll: truncated reading %s (u8)", field)
	}
	v := int(c.b[c.pos])
	c.pos++
	return v, nil
}

func (c *cursor) take(n int, field string) ([]byte, error) {
	if c.pos+n > len(c.b) {
		return nil, fmt.Errorf("tpmenroll: truncated reading %s (%d bytes)", field, n)
	}
	out := make([]byte, n)
	copy(out, c.b[c.pos:c.pos+n])
	c.pos += n
	return out, nil
}

func (c *cursor) skip(n int, field string) error {
	if c.pos+n > len(c.b) {
		return fmt.Errorf("tpmenroll: %s overruns buffer", field)
	}
	c.pos += n
	return nil
}
