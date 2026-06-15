// Package tpmenroll is the platform-agent side of the Faz 22.3B (ADR-0039)
// AD-CS-less device enrollment: TPM 2.0 attestation + Vault-PKI issued client
// cert, parallel to the AD CS machine-cert path in internal/autoenroll (which
// this package does NOT touch).
//
// This file is the TPM2B_PUBLIC / TPMT_PUBLIC wire layer — a deliberate Go port
// of the backend verifier's hand-parser
// (endpoint-admin-service .../tpmattest/TpmPublicArea.java) so the two sides
// agree byte-for-byte. The decisive cross-language check is ComputeName(): for
// the same TPM2B_PUBLIC it MUST equal the TPM-emitted ak.name that the backend
// validates (verifier V11). tpm2public_test.go pins this against the shared
// ground-truth swtpm golden vector (testdata/golden-rsa.json).
//
// TCG TPM 2.0 Part 2: TPMT_PUBLIC = type(UINT16) ‖ nameAlg(UINT16) ‖
// objectAttributes(UINT32) ‖ authPolicy(TPM2B) ‖ parameters ‖ unique.
// The TPM Name = UINT16(nameAlg) ‖ H_nameAlg(pubArea). All multi-byte fields
// are big-endian (TCG Part 1 marshaling).
package tpmenroll

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash"
	"math/big"
)

// TPMI_ALG_HASH (nameAlg / scheme hash).
const (
	AlgSHA256 = 0x000B
	AlgSHA384 = 0x000C
	AlgSHA512 = 0x000D
)

// TPMI_ALG_PUBLIC (key type) + signature schemes.
const (
	AlgRSA    = 0x0001
	AlgECC    = 0x0023
	AlgNull   = 0x0010
	AlgRSASSA = 0x0014
	AlgRSAPSS = 0x0016
	AlgECDSA  = 0x0018
)

// TPMI_ECC_CURVE.
const (
	ECCNistP256 = 0x0003
	ECCNistP384 = 0x0004
)

// TPMA_OBJECT bits (TCG Part 2).
const (
	objFixedTPM            = 1 << 1
	objFixedParent         = 1 << 4
	objSensitiveDataOrigin = 1 << 5
	objRestricted          = 1 << 16
	objDecrypt             = 1 << 17
	objSign                = 1 << 18
)

// PublicArea is a parsed TPMT_PUBLIC. The raw pubArea bytes are retained verbatim
// so ComputeName() hashes exactly what the TPM emitted and MarshalTPM2B() round-trips.
type PublicArea struct {
	typ              int
	nameAlg          int
	objectAttributes uint32
	pubArea          []byte // the TPMT_PUBLIC bytes WITHOUT any TPM2B size prefix

	parsed *parsedParams // lazily populated by params()
}

type parsedParams struct {
	schemeAlg     int
	schemeHashAlg int
	keyBits       int
	curveID       int
	rsaModulus    *big.Int
	rsaExponent   *big.Int
	eccX          *big.Int
	eccY          *big.Int
}

// ParsePublicArea parses a TPMT_PUBLIC. When isTPM2B is true the input is a
// TPM2B_PUBLIC (a UINT16 size prefix whose value MUST equal the remaining
// length — a mismatch is rejected, mirroring the backend's strict check); this
// is what `tpm2_create*  -u` and the wire envelope carry.
func ParsePublicArea(raw []byte, isTPM2B bool) (*PublicArea, error) {
	pa := raw
	if isTPM2B {
		if len(raw) < 2 {
			return nil, fmt.Errorf("tpmenroll: TPM2B_PUBLIC too short for its size prefix")
		}
		declared := int(binary.BigEndian.Uint16(raw[0:2]))
		if declared != len(raw)-2 {
			return nil, fmt.Errorf("tpmenroll: TPM2B_PUBLIC size mismatch: declared=%d actual=%d", declared, len(raw)-2)
		}
		pa = raw[2:]
	}
	if len(pa) < 8 {
		return nil, fmt.Errorf("tpmenroll: TPMT_PUBLIC too short (%d bytes)", len(pa))
	}
	// Copy so an external mutation of raw can't change our retained pubArea.
	buf := make([]byte, len(pa))
	copy(buf, pa)
	return &PublicArea{
		typ:              int(binary.BigEndian.Uint16(buf[0:2])),
		nameAlg:          int(binary.BigEndian.Uint16(buf[2:4])),
		objectAttributes: binary.BigEndian.Uint32(buf[4:8]),
		pubArea:          buf,
	}, nil
}

func (p *PublicArea) Type() int                { return p.typ }
func (p *PublicArea) NameAlg() int             { return p.nameAlg }
func (p *PublicArea) ObjectAttributes() uint32 { return p.objectAttributes }

// PubArea returns a copy of the raw TPMT_PUBLIC bytes (no TPM2B prefix).
func (p *PublicArea) PubArea() []byte {
	out := make([]byte, len(p.pubArea))
	copy(out, p.pubArea)
	return out
}

// MarshalTPM2B re-serializes as a TPM2B_PUBLIC (UINT16 size ‖ pubArea). For an
// area produced by ParsePublicArea(raw, true) this returns raw byte-for-byte.
func (p *PublicArea) MarshalTPM2B() []byte {
	out := make([]byte, 2+len(p.pubArea))
	binary.BigEndian.PutUint16(out[0:2], uint16(len(p.pubArea)))
	copy(out[2:], p.pubArea)
	return out
}

func (p *PublicArea) IsRestricted() bool  { return p.objectAttributes&objRestricted != 0 }
func (p *PublicArea) IsSign() bool        { return p.objectAttributes&objSign != 0 }
func (p *PublicArea) IsDecrypt() bool     { return p.objectAttributes&objDecrypt != 0 }
func (p *PublicArea) IsFixedTPM() bool    { return p.objectAttributes&objFixedTPM != 0 }
func (p *PublicArea) IsFixedParent() bool { return p.objectAttributes&objFixedParent != 0 }
func (p *PublicArea) IsSensitiveDataOrigin() bool {
	return p.objectAttributes&objSensitiveDataOrigin != 0
}

// IsRestrictedSigningKey is the backend V11 AK shape: a TPM-resident, TPM-generated
// restricted signing key that cannot also decrypt — restricted ∧ sign ∧ ¬decrypt ∧
// fixedTPM ∧ fixedParent ∧ sensitiveDataOrigin (TCG TPMA_OBJECT).
func (p *PublicArea) IsRestrictedSigningKey() bool {
	return p.IsRestricted() && p.IsSign() && !p.IsDecrypt() &&
		p.IsFixedTPM() && p.IsFixedParent() && p.IsSensitiveDataOrigin()
}

// ComputeName is the TPM Name = UINT16(nameAlg) ‖ H_nameAlg(pubArea), compared to
// the TPM-emitted ak.name by the backend (V11).
func (p *PublicArea) ComputeName() ([]byte, error) {
	h, err := newHash(p.nameAlg)
	if err != nil {
		return nil, err
	}
	h.Write(p.pubArea)
	digest := h.Sum(nil)
	name := make([]byte, 2+len(digest))
	binary.BigEndian.PutUint16(name[0:2], uint16(p.nameAlg))
	copy(name[2:], digest)
	return name, nil
}

// ComputeNameHex is ComputeName as lowercase hex.
func (p *PublicArea) ComputeNameHex() (string, error) {
	name, err := p.ComputeName()
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(name), nil
}

func newHash(alg int) (hash.Hash, error) {
	switch alg {
	case AlgSHA256:
		return sha256.New(), nil
	case AlgSHA384:
		return sha512.New384(), nil
	case AlgSHA512:
		return sha512.New(), nil
	default:
		return nil, fmt.Errorf("tpmenroll: unsupported/disallowed nameAlg 0x%x", alg)
	}
}

// KeyBits is the RSA modulus bit-length, or the ECC curve strength (256/384).
func (p *PublicArea) KeyBits() (int, error) {
	pp, err := p.params()
	if err != nil {
		return 0, err
	}
	return pp.keyBits, nil
}

// SigningSchemeAlg is the key's intrinsic signing scheme (RSASSA/RSAPSS/ECDSA) or AlgNull.
func (p *PublicArea) SigningSchemeAlg() (int, error) {
	pp, err := p.params()
	if err != nil {
		return 0, err
	}
	return pp.schemeAlg, nil
}

// ECCCurveID is the TPMI_ECC_CURVE, or 0 for non-ECC.
func (p *PublicArea) ECCCurveID() (int, error) {
	if p.typ != AlgECC {
		return 0, nil
	}
	pp, err := p.params()
	if err != nil {
		return 0, err
	}
	return pp.curveID, nil
}

// PublicKey reconstructs the crypto.PublicKey from the TPM unique area
// (RSA modulus/exponent or ECC point).
func (p *PublicArea) PublicKey() (crypto.PublicKey, error) {
	pp, err := p.params()
	if err != nil {
		return nil, err
	}
	switch p.typ {
	case AlgRSA:
		return &rsa.PublicKey{N: pp.rsaModulus, E: int(pp.rsaExponent.Int64())}, nil
	case AlgECC:
		curve, err := eccCurve(pp.curveID)
		if err != nil {
			return nil, err
		}
		return &ecdsa.PublicKey{Curve: curve, X: pp.eccX, Y: pp.eccY}, nil
	default:
		return nil, fmt.Errorf("tpmenroll: unsupported TPM key type 0x%x", p.typ)
	}
}

func eccCurve(id int) (elliptic.Curve, error) {
	switch id {
	case ECCNistP256:
		return elliptic.P256(), nil
	case ECCNistP384:
		return elliptic.P384(), nil
	default:
		return nil, fmt.Errorf("tpmenroll: unsupported ECC curve 0x%x", id)
	}
}

func (p *PublicArea) params() (*parsedParams, error) {
	if p.parsed != nil {
		return p.parsed, nil
	}
	pp, err := p.parseParametersAndUnique()
	if err != nil {
		return nil, err
	}
	p.parsed = pp
	return pp, nil
}

// parseParametersAndUnique mirrors the backend's big-endian, explicit-length,
// fully-consumed (T-9) parse of the TPMT_PUBLIC parameters + unique area.
func (p *PublicArea) parseParametersAndUnique() (*parsedParams, error) {
	r := &cursor{b: p.pubArea, pos: 8} // skip type(2)+nameAlg(2)+objectAttributes(4)
	if err := r.skipTPM2B("authPolicy"); err != nil {
		return nil, err
	}
	switch p.typ {
	case AlgRSA:
		symAlg, err := r.u16("rsa.symAlg")
		if err != nil {
			return nil, err
		}
		if symAlg != AlgNull { // storage/restricted-decrypt only: sym keyBits + mode
			if _, err := r.u16("rsa.sym.keyBits"); err != nil {
				return nil, err
			}
			if _, err := r.u16("rsa.sym.mode"); err != nil {
				return nil, err
			}
		}
		schemeAlg, err := r.u16("rsa.schemeAlg")
		if err != nil {
			return nil, err
		}
		schemeHash := 0
		if schemeAlg != AlgNull {
			if schemeHash, err = r.u16("rsa.schemeHash"); err != nil {
				return nil, err
			}
		}
		keyBits, err := r.u16("rsa.keyBits")
		if err != nil {
			return nil, err
		}
		exp, err := r.u32("rsa.exponent")
		if err != nil {
			return nil, err
		}
		exponent := big.NewInt(65537)
		if exp != 0 {
			exponent = big.NewInt(int64(exp))
		}
		modulus, err := r.tpm2b("rsa.unique")
		if err != nil {
			return nil, err
		}
		if err := r.requireFullyConsumed(); err != nil {
			return nil, err
		}
		return &parsedParams{
			schemeAlg: schemeAlg, schemeHashAlg: schemeHash, keyBits: keyBits,
			rsaModulus: new(big.Int).SetBytes(modulus), rsaExponent: exponent,
		}, nil
	case AlgECC:
		symAlg, err := r.u16("ecc.symAlg")
		if err != nil {
			return nil, err
		}
		if symAlg != AlgNull {
			if _, err := r.u16("ecc.sym.keyBits"); err != nil {
				return nil, err
			}
			if _, err := r.u16("ecc.sym.mode"); err != nil {
				return nil, err
			}
		}
		schemeAlg, err := r.u16("ecc.schemeAlg")
		if err != nil {
			return nil, err
		}
		schemeHash := 0
		if schemeAlg != AlgNull {
			if schemeHash, err = r.u16("ecc.schemeHash"); err != nil {
				return nil, err
			}
		}
		curveID, err := r.u16("ecc.curveId")
		if err != nil {
			return nil, err
		}
		kdfAlg, err := r.u16("ecc.kdfAlg")
		if err != nil {
			return nil, err
		}
		if kdfAlg != AlgNull {
			if _, err := r.u16("ecc.kdfHash"); err != nil {
				return nil, err
			}
		}
		x, err := r.tpm2b("ecc.x")
		if err != nil {
			return nil, err
		}
		y, err := r.tpm2b("ecc.y")
		if err != nil {
			return nil, err
		}
		if err := r.requireFullyConsumed(); err != nil {
			return nil, err
		}
		bits := 0
		switch curveID {
		case ECCNistP384:
			bits = 384
		case ECCNistP256:
			bits = 256
		}
		return &parsedParams{
			schemeAlg: schemeAlg, schemeHashAlg: schemeHash, keyBits: bits, curveID: curveID,
			eccX: new(big.Int).SetBytes(x), eccY: new(big.Int).SetBytes(y),
		}, nil
	default:
		return nil, fmt.Errorf("tpmenroll: unsupported TPM key type 0x%x", p.typ)
	}
}

// cursor is a bounds-checked big-endian reader over a TPM structure.
type cursor struct {
	b   []byte
	pos int
}

func (c *cursor) u16(field string) (int, error) {
	if c.pos+2 > len(c.b) {
		return 0, fmt.Errorf("tpmenroll: truncated reading %s (u16)", field)
	}
	v := int(binary.BigEndian.Uint16(c.b[c.pos : c.pos+2]))
	c.pos += 2
	return v, nil
}

func (c *cursor) u32(field string) (uint32, error) {
	if c.pos+4 > len(c.b) {
		return 0, fmt.Errorf("tpmenroll: truncated reading %s (u32)", field)
	}
	v := binary.BigEndian.Uint32(c.b[c.pos : c.pos+4])
	c.pos += 4
	return v, nil
}

func (c *cursor) tpm2b(field string) ([]byte, error) {
	n, err := c.u16(field + ".size")
	if err != nil {
		return nil, err
	}
	if c.pos+n > len(c.b) {
		return nil, fmt.Errorf("tpmenroll: truncated reading %s (declared %d)", field, n)
	}
	out := make([]byte, n)
	copy(out, c.b[c.pos:c.pos+n])
	c.pos += n
	return out, nil
}

func (c *cursor) skipTPM2B(field string) error {
	n, err := c.u16(field + ".size")
	if err != nil {
		return err
	}
	if c.pos+n > len(c.b) {
		return fmt.Errorf("tpmenroll: truncated skipping %s (declared %d)", field, n)
	}
	c.pos += n
	return nil
}

func (c *cursor) requireFullyConsumed() error {
	if c.pos != len(c.b) {
		return fmt.Errorf("tpmenroll: TPMT_PUBLIC not fully consumed (%d trailing bytes)", len(c.b)-c.pos)
	}
	return nil
}
