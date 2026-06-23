package attestation

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

const Version = 1

var validProtectionLevels = map[string]struct{}{
	"SOFTWARE":              {},
	"TEE":                   {},
	"SECURE_ELEMENT_OR_TPM": {},
}

var validSignatureAlgorithms = map[string]struct{}{
	"SHA256withECDSA": {},
	"SHA256withRSA":   {},
}

type Config struct {
	SLSA      SLSAConfig
	DeviceKey DeviceKeyConfig
}

type SLSAConfig struct {
	BinaryDigest       string
	BuilderID          string
	PredicateHash      string
	PredicateSignature string
}

type DeviceKeyConfig struct {
	KeyDerB64       string
	ProtectionLevel string
	NonExportable   *bool
	SignatureB64    string
	Algorithm       string
	ChainDerB64     []string
}

type envelope struct {
	Version   int                `json:"v"`
	SLSA      *slsaEnvelope      `json:"slsa,omitempty"`
	DeviceKey *deviceKeyEnvelope `json:"deviceKey,omitempty"`
}

type slsaEnvelope struct {
	BinaryDigest       string `json:"binaryDigest"`
	BuilderID          string `json:"builderId"`
	SLSAPredicateHash  string `json:"slsaPredicateHash"`
	PredicateSignature string `json:"predicateSignature"`
}

type deviceKeyEnvelope struct {
	KeyDer          string   `json:"keyDer"`
	ProtectionLevel string   `json:"protectionLevel"`
	NonExportable   bool     `json:"nonExportable"`
	Signature       string   `json:"signature"`
	Algorithm       string   `json:"algorithm"`
	ChainDer        []string `json:"chainDer"`
}

func BuildEvidenceB64(cfg Config) (string, error) {
	env, configured, err := buildEnvelope(cfg)
	if err != nil {
		return "", err
	}
	if !configured {
		return "", nil
	}
	raw, err := json.Marshal(env)
	if err != nil {
		return "", fmt.Errorf("remote-bridge attestation envelope marshal: %w", err)
	}
	return base64.StdEncoding.EncodeToString(raw), nil
}

func buildEnvelope(cfg Config) (envelope, bool, error) {
	out := envelope{Version: Version}
	configured := false

	if cfg.SLSA.configured() {
		slsa, err := cfg.SLSA.envelope()
		if err != nil {
			return envelope{}, false, err
		}
		out.SLSA = slsa
		configured = true
	}

	if cfg.DeviceKey.configured() {
		deviceKey, err := cfg.DeviceKey.envelope()
		if err != nil {
			return envelope{}, false, err
		}
		out.DeviceKey = deviceKey
		configured = true
	}

	return out, configured, nil
}

func (c SLSAConfig) configured() bool {
	return anyNonBlank(
		c.BinaryDigest,
		c.BuilderID,
		c.PredicateHash,
		c.PredicateSignature,
	)
}

func (c SLSAConfig) envelope() (*slsaEnvelope, error) {
	binaryDigest := strings.TrimSpace(c.BinaryDigest)
	builderID := strings.TrimSpace(c.BuilderID)
	predicateHash := strings.TrimSpace(c.PredicateHash)
	predicateSignature := strings.TrimSpace(c.PredicateSignature)
	if binaryDigest == "" || builderID == "" || predicateHash == "" || predicateSignature == "" {
		return nil, errors.New("remote-bridge SLSA attestation config requires binary digest, builder id, predicate hash, and predicate signature")
	}
	return &slsaEnvelope{
		BinaryDigest:       binaryDigest,
		BuilderID:          builderID,
		SLSAPredicateHash:  predicateHash,
		PredicateSignature: predicateSignature,
	}, nil
}

func (c DeviceKeyConfig) configured() bool {
	return anyNonBlank(
		c.KeyDerB64,
		c.ProtectionLevel,
		c.SignatureB64,
		c.Algorithm,
	) || c.NonExportable != nil || len(c.ChainDerB64) > 0
}

func (c DeviceKeyConfig) envelope() (*deviceKeyEnvelope, error) {
	keyDer := strings.TrimSpace(c.KeyDerB64)
	protectionLevel := strings.TrimSpace(c.ProtectionLevel)
	signature := strings.TrimSpace(c.SignatureB64)
	algorithm := strings.TrimSpace(c.Algorithm)
	chain := trimNonBlank(c.ChainDerB64)

	if keyDer == "" || protectionLevel == "" || c.NonExportable == nil || signature == "" || algorithm == "" || len(chain) == 0 {
		return nil, errors.New("remote-bridge device-key attestation config requires key, protection level, non-exportable flag, signature, algorithm, and attestation chain")
	}
	if _, ok := validProtectionLevels[protectionLevel]; !ok {
		return nil, fmt.Errorf("remote-bridge device-key attestation protection level %q is not supported", protectionLevel)
	}
	if _, ok := validSignatureAlgorithms[algorithm]; !ok {
		return nil, fmt.Errorf("remote-bridge device-key attestation signature algorithm %q is not supported", algorithm)
	}
	if err := requireStandardB64("device-key DER", keyDer); err != nil {
		return nil, err
	}
	if err := requireStandardB64("device-key signature", signature); err != nil {
		return nil, err
	}
	for i, value := range chain {
		if err := requireStandardB64(fmt.Sprintf("device-key chain DER[%d]", i), value); err != nil {
			return nil, err
		}
	}

	return &deviceKeyEnvelope{
		KeyDer:          keyDer,
		ProtectionLevel: protectionLevel,
		NonExportable:   *c.NonExportable,
		Signature:       signature,
		Algorithm:       algorithm,
		ChainDer:        chain,
	}, nil
}

func requireStandardB64(label, value string) error {
	if strings.ContainsAny(value, " \t\r\n") {
		return fmt.Errorf("remote-bridge %s must be single-line standard base64", label)
	}
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return fmt.Errorf("remote-bridge %s must be valid standard base64: %w", label, err)
	}
	if len(decoded) == 0 {
		return fmt.Errorf("remote-bridge %s must decode to non-empty bytes", label)
	}
	return nil
}

func trimNonBlank(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

func anyNonBlank(values ...string) bool {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return true
		}
	}
	return false
}
