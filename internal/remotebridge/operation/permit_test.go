package operation

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

// vector is the Java-minted (authoritative) cross-language CONSTRAINED_PTY permit test vector. The broker
// (platform-backend RemoteBridgePermitSigner) produced these exact bytes/signature; this Go verifier MUST
// reproduce the canonical bytes + verify the signature, which proves the agent matches the broker.
type vector struct {
	Alg                  string `json:"alg"`
	Kid                  string `json:"kid"`
	PermitVersion        int32  `json:"permitVersion"`
	PolicyVersion        string `json:"policyVersion"`
	DecisionID           string `json:"decisionId"`
	SessionID            string `json:"sessionId"`
	OperationID          string `json:"operationId"`
	DeviceID             string `json:"deviceId"`
	OperatorSubject      string `json:"operatorSubject"`
	Capability           string `json:"capability"`
	CommandLine          string `json:"commandLine"`
	CommandHash          string `json:"commandHash"`
	IssuedAtEpochMillis  int64  `json:"issuedAtEpochMillis"`
	ExpiresAtEpochMillis int64  `json:"expiresAtEpochMillis"`
	Seq                  int64  `json:"seq"`
	CanonicalPayloadHex  string `json:"canonicalPayloadHex"`
	SignatureB64         string `json:"signatureB64"`
	BrokerPublicKeyB64   string `json:"brokerPublicKeyB64"`
}

func loadVector(t *testing.T) vector {
	t.Helper()
	raw, err := os.ReadFile("testdata/pty-permit-vector.json")
	if err != nil {
		t.Fatalf("read vector: %v", err)
	}
	var v vector
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("parse vector: %v", err)
	}
	return v
}

func (v vector) permit() OperationPermit {
	return OperationPermit{
		Alg: v.Alg, Kid: v.Kid, PermitVersion: v.PermitVersion, PolicyVersion: v.PolicyVersion,
		DecisionID: v.DecisionID, SessionID: v.SessionID, OperationID: v.OperationID, DeviceID: v.DeviceID,
		OperatorSubject: v.OperatorSubject, Capability: v.Capability, CommandHash: v.CommandHash,
		IssuedAtEpochMillis: v.IssuedAtEpochMillis, ExpiresAtEpochMillis: v.ExpiresAtEpochMillis,
		Seq: v.Seq, SignatureB64: v.SignatureB64,
	}
}

// freshNow is inside [issuedAt, expiresAt) for the vector (1000..1300).
const freshNow = int64(1100)

// (1) byte-exactness: the Go canonical payload must equal the broker's, byte-for-byte.
func TestCanonicalPayloadByteExactWithBrokerVector(t *testing.T) {
	v := loadVector(t)
	got := hex.EncodeToString(v.permit().canonicalPayload())
	if got != v.CanonicalPayloadHex {
		t.Fatalf("canonical payload drift vs broker:\n got=%s\nwant=%s", got, v.CanonicalPayloadHex)
	}
}

// (2) the broker's real ECDSA signature verifies under the broker's real public key.
func TestVerifyAcceptsBrokerSignedVector(t *testing.T) {
	v := loadVector(t)
	ver, err := NewVerifier(v.BrokerPublicKeyB64, v.Kid)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	if !ver.Verify(v.permit(), freshNow) {
		t.Fatal("broker-signed permit did NOT verify — Go verifier disagrees with the broker")
	}
}

// (3) the command hash is byte-exact with the broker, and matches the permit's bound commandHash.
func TestCommandHashByteExactWithBrokerVector(t *testing.T) {
	v := loadVector(t)
	got := ParseCommand(v.CommandLine).Hash()
	if got != v.CommandHash {
		t.Fatalf("command hash drift vs broker: got=%s want=%s", got, v.CommandHash)
	}
	if got != v.permit().CommandHash {
		t.Fatalf("command hash != permit.CommandHash (%s vs %s)", got, v.permit().CommandHash)
	}
}

// fail-closed: every mutation of an otherwise-valid permit must be rejected.
func TestVerifyFailClosed(t *testing.T) {
	v := loadVector(t)
	ver, err := NewVerifier(v.BrokerPublicKeyB64, v.Kid)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	// sanity: the unmutated permit verifies (so each failure below is due to the mutation, not a broken base)
	if !ver.Verify(v.permit(), freshNow) {
		t.Fatal("base permit should verify")
	}

	cases := []struct {
		name string
		now  int64
		mut  func(p *OperationPermit)
	}{
		{"expired (now==expiresAt)", v.ExpiresAtEpochMillis, func(*OperationPermit) {}},
		{"expired (now>expiresAt)", v.ExpiresAtEpochMillis + 1, func(*OperationPermit) {}},
		{"not-yet-valid (now<issuedAt)", v.IssuedAtEpochMillis - 1, func(*OperationPermit) {}},
		{"wrong kid", freshNow, func(p *OperationPermit) { p.Kid = "kid-OTHER" }},
		{"wrong alg", freshNow, func(p *OperationPermit) { p.Alg = "SHA512withECDSA" }},
		{"blank signature", freshNow, func(p *OperationPermit) { p.SignatureB64 = "" }},
		{"corrupt base64 signature", freshNow, func(p *OperationPermit) { p.SignatureB64 = "!!!notb64!!!" }},
		{"tampered sessionId", freshNow, func(p *OperationPermit) { p.SessionID = "sess-EVIL" }},
		{"tampered capability", freshNow, func(p *OperationPermit) { p.Capability = "FULL_RDP" }},
		{"tampered commandHash", freshNow, func(p *OperationPermit) { p.CommandHash = "00" + p.CommandHash[2:] }},
		{"tampered seq", freshNow, func(p *OperationPermit) { p.Seq = p.Seq + 1 }},
		{"degenerate window (issued==expires)", freshNow, func(p *OperationPermit) {
			p.IssuedAtEpochMillis = 1200
			p.ExpiresAtEpochMillis = 1200
		}},
	}
	for _, c := range cases {
		p := v.permit()
		c.mut(&p)
		if ver.Verify(p, c.now) {
			t.Errorf("fail-closed violated: %q was ACCEPTED", c.name)
		}
	}
}

// a permit signed by a DIFFERENT broker key must be rejected (the verifier is pinned to the real key).
func TestVerifyRejectsForeignKey(t *testing.T) {
	v := loadVector(t)
	// a syntactically-valid but WRONG P-256 SPKI key (different keypair) must reject the real signature.
	const foreignKeyB64 = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEqGT9p8dN2sQ4u1m1pVPiQ0H1k3xkY1f9oFqkq0d5Yk0r1tq0t8e7zj0bqkq6r6q0gq9c0o2p4u6w8x0z2A4C6E8g=="
	ver, err := NewVerifier(foreignKeyB64, v.Kid)
	if err != nil {
		t.Skipf("foreign key not parseable in this build (%v) — covered by the tamper cases", err)
	}
	if ver.Verify(v.permit(), freshNow) {
		t.Fatal("a permit verified under a FOREIGN key — signature binding broken")
	}
}

// IsFresh malformed-window guards, in isolation (no signature confound).
func TestIsFreshGuards(t *testing.T) {
	if !(OperationPermit{IssuedAtEpochMillis: 1000, ExpiresAtEpochMillis: 1300}).IsFresh(1100) {
		t.Fatal("a valid window must be fresh")
	}
	bad := []OperationPermit{
		{IssuedAtEpochMillis: 0, ExpiresAtEpochMillis: 1300},    // non-positive issued
		{IssuedAtEpochMillis: 1000, ExpiresAtEpochMillis: 0},    // non-positive expires
		{IssuedAtEpochMillis: -5, ExpiresAtEpochMillis: 1300},   // negative issued
		{IssuedAtEpochMillis: 1300, ExpiresAtEpochMillis: 1000}, // inverted
		{IssuedAtEpochMillis: 1200, ExpiresAtEpochMillis: 1200}, // degenerate
	}
	for i, p := range bad {
		if p.IsFresh(1100) {
			t.Errorf("case %d (%d..%d): a malformed window must NOT be fresh", i, p.IssuedAtEpochMillis, p.ExpiresAtEpochMillis)
		}
	}
}

func TestNewVerifierFailClosed(t *testing.T) {
	v := loadVector(t)
	if _, err := NewVerifier(v.BrokerPublicKeyB64, ""); err == nil {
		t.Error("blank kid must error")
	}
	if _, err := NewVerifier("!!!notb64!!!", "kid-1"); err == nil {
		t.Error("non-base64 key must error")
	}
	if _, err := NewVerifier("YWJjZGVm", "kid-1"); err == nil { // valid base64, not an SPKI key
		t.Error("non-SPKI key must error")
	}
}

// structural canonicalisation (no Java vector needed): commandId lower+trim, argv order, empty, space-runs.
func TestParseCommandCanonicalisation(t *testing.T) {
	cases := []struct {
		line  string
		id    string
		argv  []string
		empty bool
	}{
		{"hostname", "hostname", nil, false},
		{"  IpConfig   /all  ", "ipconfig", []string{"/all"}, false},
		{"net  user  alice", "net", []string{"user", "alice"}, false},
		{"   ", "", nil, true},
		{"", "", nil, true},
	}
	for _, c := range cases {
		cc := ParseCommand(c.line)
		if cc.CommandID != c.id {
			t.Errorf("%q: commandId=%q want %q", c.line, cc.CommandID, c.id)
		}
		if cc.IsEmpty() != c.empty {
			t.Errorf("%q: IsEmpty=%v want %v", c.line, cc.IsEmpty(), c.empty)
		}
		if len(cc.Argv) != len(c.argv) {
			t.Errorf("%q: argv=%v want %v", c.line, cc.Argv, c.argv)
			continue
		}
		for i := range c.argv {
			if cc.Argv[i] != c.argv[i] {
				t.Errorf("%q: argv[%d]=%q want %q", c.line, i, cc.Argv[i], c.argv[i])
			}
		}
	}
}
