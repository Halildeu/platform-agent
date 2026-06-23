package attestation

import (
	"encoding/base64"
	"strings"
	"testing"
)

func boolPtr(v bool) *bool { return &v }

func TestBuildEvidenceB64ReturnsEmptyWhenNoStructuredEvidenceConfigured(t *testing.T) {
	got, err := BuildEvidenceB64(Config{})
	if err != nil {
		t.Fatalf("BuildEvidenceB64: %v", err)
	}
	if got != "" {
		t.Fatalf("BuildEvidenceB64 = %q, want empty", got)
	}
}

func TestBuildEvidenceB64SLSAOnly(t *testing.T) {
	got, err := BuildEvidenceB64(Config{
		SLSA: SLSAConfig{
			BinaryDigest:       "sha256:bin",
			BuilderID:          "builder",
			PredicateHash:      "sha256:predicate",
			PredicateSignature: "sig",
		},
	})
	if err != nil {
		t.Fatalf("BuildEvidenceB64: %v", err)
	}
	wantJSON := `{"v":1,"slsa":{"binaryDigest":"sha256:bin","builderId":"builder","slsaPredicateHash":"sha256:predicate","predicateSignature":"sig"}}`
	want := base64.StdEncoding.EncodeToString([]byte(wantJSON))
	if got != want {
		t.Fatalf("BuildEvidenceB64 = %q, want %q", got, want)
	}
}

func TestBuildEvidenceB64DeviceKeyOnly(t *testing.T) {
	got, err := BuildEvidenceB64(Config{
		DeviceKey: DeviceKeyConfig{
			KeyDerB64:       "AQID",
			ProtectionLevel: "SECURE_ELEMENT_OR_TPM",
			NonExportable:   boolPtr(true),
			SignatureB64:    "BAU=",
			Algorithm:       "SHA256withECDSA",
			ChainDerB64:     []string{"Bgc=", "CAk="},
		},
	})
	if err != nil {
		t.Fatalf("BuildEvidenceB64: %v", err)
	}
	wantJSON := `{"v":1,"deviceKey":{"keyDer":"AQID","protectionLevel":"SECURE_ELEMENT_OR_TPM","nonExportable":true,"signature":"BAU=","algorithm":"SHA256withECDSA","chainDer":["Bgc=","CAk="]}}`
	want := base64.StdEncoding.EncodeToString([]byte(wantJSON))
	if got != want {
		t.Fatalf("BuildEvidenceB64 = %q, want %q", got, want)
	}
}

func TestBuildEvidenceB64SLSAAndDeviceKey(t *testing.T) {
	got, err := BuildEvidenceB64(Config{
		SLSA: SLSAConfig{
			BinaryDigest:       "sha256:bin",
			BuilderID:          "builder",
			PredicateHash:      "sha256:predicate",
			PredicateSignature: "sig",
		},
		DeviceKey: DeviceKeyConfig{
			KeyDerB64:       "AQID",
			ProtectionLevel: "SECURE_ELEMENT_OR_TPM",
			NonExportable:   boolPtr(false),
			SignatureB64:    "BAU=",
			Algorithm:       "SHA256withRSA",
			ChainDerB64:     []string{"Bgc="},
		},
	})
	if err != nil {
		t.Fatalf("BuildEvidenceB64: %v", err)
	}
	decoded, err := base64.StdEncoding.DecodeString(got)
	if err != nil {
		t.Fatalf("decode output: %v", err)
	}
	text := string(decoded)
	for _, want := range []string{
		`"v":1`,
		`"slsa"`,
		`"deviceKey"`,
		`"nonExportable":false`,
		`"algorithm":"SHA256withRSA"`,
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("decoded envelope %s missing %s", text, want)
		}
	}
}

func TestBuildEvidenceB64RejectsPartialSLSAConfig(t *testing.T) {
	_, err := BuildEvidenceB64(Config{
		SLSA: SLSAConfig{BinaryDigest: "sha256:bin"},
	})
	if err == nil {
		t.Fatal("BuildEvidenceB64 accepted partial SLSA config")
	}
}

func TestBuildEvidenceB64RejectsPartialDeviceKeyConfig(t *testing.T) {
	_, err := BuildEvidenceB64(Config{
		DeviceKey: DeviceKeyConfig{
			KeyDerB64:       "AQID",
			ProtectionLevel: "SECURE_ELEMENT_OR_TPM",
			NonExportable:   boolPtr(true),
		},
	})
	if err == nil {
		t.Fatal("BuildEvidenceB64 accepted partial device-key config")
	}
}

func TestBuildEvidenceB64RejectsMalformedDeviceKeyConfig(t *testing.T) {
	cases := map[string]DeviceKeyConfig{
		"bad key base64": {
			KeyDerB64:       "not-base64!",
			ProtectionLevel: "SECURE_ELEMENT_OR_TPM",
			NonExportable:   boolPtr(true),
			SignatureB64:    "BAU=",
			Algorithm:       "SHA256withECDSA",
			ChainDerB64:     []string{"Bgc="},
		},
		"unknown protection": {
			KeyDerB64:       "AQID",
			ProtectionLevel: "TPM2",
			NonExportable:   boolPtr(true),
			SignatureB64:    "BAU=",
			Algorithm:       "SHA256withECDSA",
			ChainDerB64:     []string{"Bgc="},
		},
		"unknown algorithm": {
			KeyDerB64:       "AQID",
			ProtectionLevel: "SECURE_ELEMENT_OR_TPM",
			NonExportable:   boolPtr(true),
			SignatureB64:    "BAU=",
			Algorithm:       "ED25519",
			ChainDerB64:     []string{"Bgc="},
		},
		"empty decoded chain": {
			KeyDerB64:       "AQID",
			ProtectionLevel: "SECURE_ELEMENT_OR_TPM",
			NonExportable:   boolPtr(true),
			SignatureB64:    "BAU=",
			Algorithm:       "SHA256withECDSA",
			ChainDerB64:     []string{""},
		},
	}
	for name, deviceKey := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := BuildEvidenceB64(Config{DeviceKey: deviceKey})
			if err == nil {
				t.Fatal("BuildEvidenceB64 accepted malformed device-key config")
			}
		})
	}
}
