package autoenroll

import (
	"encoding/json"
	"errors"
	"testing"
	"time"
)

// TestBuildAutoEnrollRequest_BackendContract is the #149 regression guard.
//
// The auto-enroll body MUST be a FLAT object with camelCase keys matching
// backend AutoEnrollmentRequest (com.example.endpointadmin.dto.v1.agent), and
// the four @NotBlank fields (machineFingerprint, hostname, osName,
// agentVersion) MUST be present and non-empty. The earlier nested snake_case
// shape ({os_info{...}, agent_version}) silently passed Go round-trip tests
// but 400'd on the wire because none of those fields bound — so this test
// asserts the MARSHALED JSON, not just the Go struct.
func TestBuildAutoEnrollRequest_BackendContract(t *testing.T) {
	req := buildAutoEnrollRequest("0.2.0-test")

	// 1. @NotBlank fields must be populated by buildAutoEnrollRequest on any
	//    supported runtime (Collect guarantees hostname/osName/arch/version;
	//    MachineFingerprint is a deterministic sha256, never blank).
	if req.MachineFingerprint == "" {
		t.Error("machineFingerprint is blank (backend @NotBlank)")
	}
	if req.Hostname == "" {
		t.Error("hostname is blank (backend @NotBlank)")
	}
	if req.OSName == "" {
		t.Error("osName is blank (backend @NotBlank)")
	}
	if req.AgentVersion == "" {
		t.Error("agentVersion is blank (backend @NotBlank)")
	}

	// 2. The marshaled JSON must be flat camelCase, carry the required keys,
	//    carry NO stale keys, and emit ONLY keys the backend record declares.
	raw, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var body map[string]json.RawMessage
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	for _, k := range []string{"machineFingerprint", "hostname", "osName", "agentVersion"} {
		if _, ok := body[k]; !ok {
			t.Errorf("required key %q missing from wire body %s", k, raw)
		}
	}

	// The pre-#149 shape must be gone (these keys 400'd on the live backend).
	for _, k := range []string{"os_info", "agent_version", "os_type", "os_version"} {
		if _, ok := body[k]; ok {
			t.Errorf("stale pre-#149 key %q present in wire body %s", k, raw)
		}
	}

	// Every emitted key must belong to backend AutoEnrollmentRequest so a
	// future field drift (typo / wrong casing / extra field) is caught here
	// instead of as a runtime 400.
	known := map[string]bool{
		"machineFingerprint": true,
		"hostname":           true,
		"osName":             true,
		"osVersion":          true,
		"osBuild":            true,
		"domain":             true,
		"architecture":       true,
		"agentVersion":       true,
		"schemaVersion":      true,
	}
	for k := range body {
		if !known[k] {
			t.Errorf("key %q is not a backend AutoEnrollmentRequest field — wire body %s", k, raw)
		}
	}
}

// TestAutoEnrollResponse_DecodeAndValidate is the #149 response-side regression
// guard. The backend returns a FLAT camelCase, TOKENLESS body
// {deviceId,status,enrolledAt,certInfo{...}} — there is no service_token. This
// test asserts the agent decodes that exact shape and that Validate fails
// closed on a drifted/forged response (bad status, missing fields, or a cert
// thumbprint that does not match the cert the agent presented on the mTLS
// handshake).
func TestAutoEnrollResponse_DecodeAndValidate(t *testing.T) {
	const localThumb = "0a1b2c3d4e5f60718293a4b5c6d7e8f900112233445566778899aabbccddeeff"
	// Exactly the bytes the backend emits (camelCase, nested certInfo).
	backendJSON := `{
		"deviceId": "11111111-2222-3333-4444-555555555555",
		"status": "enrolled",
		"enrolledAt": "2026-06-13T10:00:00Z",
		"certInfo": {
			"sanUri": "adcomputer:99999999-8888-7777-6666-555555555555",
			"objectGuid": "99999999-8888-7777-6666-555555555555",
			"thumbprint": "` + localThumb + `",
			"notAfter": "2027-06-13T10:00:00Z"
		}
	}`

	var resp AutoEnrollResponse
	if err := json.Unmarshal([]byte(backendJSON), &resp); err != nil {
		t.Fatalf("decode backend response: %v", err)
	}
	if resp.DeviceID == "" || resp.Status != StatusEnrolled || resp.CertInfo.Thumbprint != localThumb {
		t.Fatalf("decode mapped wrong fields: %+v", resp)
	}
	if resp.CertInfo.SANURI == "" || resp.EnrolledAt.IsZero() {
		t.Fatalf("decode dropped certInfo/enrolledAt: %+v", resp)
	}

	// Happy path: thumbprint matches the presented cert (case/format normalised).
	if err := resp.Validate(localThumb); err != nil {
		t.Fatalf("Validate happy path: %v", err)
	}
	if err := resp.Validate("0A1B2C3D4E5F60718293A4B5C6D7E8F900112233445566778899AABBCCDDEEFF"); err != nil {
		t.Fatalf("Validate must normalise case before comparing: %v", err)
	}

	// Fail-closed cases.
	cases := map[string]struct {
		mutate func(*AutoEnrollResponse)
		local  string
	}{
		"thumbprint_mismatch":    {func(r *AutoEnrollResponse) {}, "deadbeef"},
		"empty_local_thumbprint": {func(r *AutoEnrollResponse) {}, ""},
		"empty_device_id":        {func(r *AutoEnrollResponse) { r.DeviceID = "" }, localThumb},
		"unknown_status":         {func(r *AutoEnrollResponse) { r.Status = "pending" }, localThumb},
		"empty_thumbprint":       {func(r *AutoEnrollResponse) { r.CertInfo.Thumbprint = "" }, localThumb},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			r := resp
			tc.mutate(&r)
			if err := r.Validate(tc.local); !errors.Is(err, ErrInvalidEnrollResponse) {
				t.Fatalf("expected ErrInvalidEnrollResponse, got %v", err)
			}
		})
	}

	// "already-enrolled" (HTTP 200 idempotent) is also a valid status.
	r := resp
	r.Status = StatusAlreadyEnrolled
	if err := r.Validate(localThumb); err != nil {
		t.Fatalf("already-enrolled must be valid: %v", err)
	}
}

func TestHeartbeatRequest_BackendContract(t *testing.T) {
	req := HeartbeatRequest{
		Hostname:     "ERP-MOBIL",
		OSType:       "WINDOWS",
		Architecture: "amd64",
		AgentVersion: "0.2.0-test",
		OSVersion:    "Windows Server 2022",
		State:        "ONLINE",
		Capabilities: []string{"COLLECT_INVENTORY"},
		Timestamp:    time.Date(2026, 6, 14, 18, 0, 0, 0, time.UTC),
	}
	raw, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal heartbeat: %v", err)
	}
	var body map[string]json.RawMessage
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatalf("unmarshal heartbeat: %v", err)
	}

	for _, k := range []string{"hostname", "osType", "architecture", "agentVersion", "osVersion", "state", "capabilities", "timestamp"} {
		if _, ok := body[k]; !ok {
			t.Errorf("heartbeat key %q missing from wire body %s", k, raw)
		}
	}
	for _, k := range []string{"os_type", "agent_version", "os_version"} {
		if _, ok := body[k]; ok {
			t.Errorf("stale snake_case heartbeat key %q present in wire body %s", k, raw)
		}
	}
}
