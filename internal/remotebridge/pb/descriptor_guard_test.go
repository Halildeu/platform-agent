package remotebridgepb

// Generated-code drift guard (Codex T-3 revision #6): the proto is vendored
// and the generated Go is committed, so nothing in CI recompiles the .proto.
// These tests pin the WIRE-RELEVANT shape — service/RPC names, frozen field
// numbers, oneof payload range, enum numbers — via protobuf reflection, so a
// careless regeneration or a hand edit that changes the wire contract fails
// the suite without needing protoc.

import (
	"testing"

	"google.golang.org/protobuf/reflect/protoreflect"
)

func requireFieldNumbers(t *testing.T, md protoreflect.MessageDescriptor, want map[string]int32) {
	t.Helper()
	if md.Fields().Len() != len(want) {
		t.Errorf("%s: has %d fields, want %d", md.FullName(), md.Fields().Len(), len(want))
	}
	for name, num := range want {
		fd := md.Fields().ByName(protoreflect.Name(name))
		if fd == nil {
			t.Errorf("%s: field %q missing", md.FullName(), name)
			continue
		}
		if int32(fd.Number()) != num {
			t.Errorf("%s.%s: field number %d, want %d", md.FullName(), name, fd.Number(), num)
		}
	}
}

func TestServiceShapeFrozen(t *testing.T) {
	svc := File_remote_bridge_proto.Services().ByName("RemoteBridge")
	if svc == nil {
		t.Fatal("service RemoteBridge missing")
	}
	if got, want := string(svc.FullName()), "endpointadmin.remotebridge.v1.RemoteBridge"; got != want {
		t.Fatalf("service full name %q, want %q", got, want)
	}
	for _, name := range []string{"Connect", "Data"} {
		m := svc.Methods().ByName(protoreflect.Name(name))
		if m == nil {
			t.Errorf("rpc %s missing", name)
			continue
		}
		if !m.IsStreamingClient() || !m.IsStreamingServer() {
			t.Errorf("rpc %s must be bidi streaming", name)
		}
		if got, want := string(m.Input().FullName()), "endpointadmin.remotebridge.v1.Envelope"; got != want {
			t.Errorf("rpc %s input %q, want %q", name, got, want)
		}
		if got, want := string(m.Output().FullName()), "endpointadmin.remotebridge.v1.Envelope"; got != want {
			t.Errorf("rpc %s output %q, want %q", name, got, want)
		}
	}
}

func TestEnvelopeWireShapeFrozen(t *testing.T) {
	md := (&Envelope{}).ProtoReflect().Descriptor()
	requireFieldNumbers(t, md, map[string]int32{
		"session_id":           1,
		"device_id":            2,
		"channel_type":         3,
		"frame_seq":            4,
		"stream_id":            5,
		"sent_at_epoch_millis": 6,
		"agent_hello":          10,
		"session_request":      11,
		"consent_prompt":       12,
		"consent_result":       13,
		"operation_request":    14,
		"operation_permit":     15,
		"kill":                 16,
		"audit_event":          17,
		"heartbeat":            18,
		"data_frame":           19,
		"error":                20,
		"operation_dispatch":   21,
	})
	payload := md.Oneofs().ByName("payload")
	if payload == nil {
		t.Fatal("oneof payload missing")
	}
	if got, want := payload.Fields().Len(), 12; got != want {
		t.Fatalf("oneof payload has %d members, want %d", got, want)
	}
	for i := 0; i < payload.Fields().Len(); i++ {
		fd := payload.Fields().Get(i)
		if fd.Number() < 10 || fd.Number() > 21 {
			t.Errorf("oneof member %s outside the frozen 10-21 range: %d", fd.Name(), fd.Number())
		}
	}
}

func TestOperationPermitWireShapeFrozen(t *testing.T) {
	requireFieldNumbers(t, (&OperationPermit{}).ProtoReflect().Descriptor(), map[string]int32{
		"alg":                     1,
		"kid":                     2,
		"permit_version":          3,
		"policy_version":          4,
		"decision_id":             5,
		"session_id":              6,
		"operation_id":            7,
		"device_id":               8,
		"operator_subject":        9,
		"capability":              10,
		"command_hash":            11,
		"issued_at_epoch_millis":  12,
		"expires_at_epoch_millis": 13,
		"seq":                     14,
		"signature_b64":           15,
	})
}

func TestAgentHelloWireShapeFrozen(t *testing.T) {
	requireFieldNumbers(t, (&AgentHello{}).ProtoReflect().Descriptor(), map[string]int32{
		"agent_version":            1,
		"device_id":                2,
		"cert_fingerprint":         3,
		"attestation_evidence_b64": 4,
		"protocol_version":         5,
		"advertised_capabilities":  6,
	})
}

func TestKillAndHeartbeatWireShapeFrozen(t *testing.T) {
	requireFieldNumbers(t, (&Kill{}).ProtoReflect().Descriptor(), map[string]int32{
		"session_id":             1,
		"kill_reason":            2,
		"issued_at_epoch_millis": 3,
	})
	requireFieldNumbers(t, (&Heartbeat{}).ProtoReflect().Descriptor(), map[string]int32{
		"heartbeat_interval_millis":     1,
		"lease_expires_at_epoch_millis": 2,
		"protocol_version":              3,
	})
	requireFieldNumbers(t, (&ErrorFrame{}).ProtoReflect().Descriptor(), map[string]int32{
		"code":      1,
		"detail":    2,
		"retryable": 3,
	})
}

func requireEnumNumbers(t *testing.T, ed protoreflect.EnumDescriptor, want map[string]int32) {
	t.Helper()
	if ed.Values().Len() != len(want) {
		t.Errorf("%s: has %d values, want %d", ed.FullName(), ed.Values().Len(), len(want))
	}
	for name, num := range want {
		vd := ed.Values().ByName(protoreflect.Name(name))
		if vd == nil {
			t.Errorf("%s: value %q missing", ed.FullName(), name)
			continue
		}
		if int32(vd.Number()) != num {
			t.Errorf("%s.%s: number %d, want %d", ed.FullName(), name, vd.Number(), num)
		}
	}
}

func TestEnumsFrozen(t *testing.T) {
	requireEnumNumbers(t, Capability(0).Descriptor(), map[string]int32{
		"CAPABILITY_UNSPECIFIED": 0,
		"VIEW_ONLY":              1,
		"CONSTRAINED_PTY":        2,
	})
	requireEnumNumbers(t, ChannelType(0).Descriptor(), map[string]int32{
		"CHANNEL_TYPE_UNSPECIFIED": 0,
		"CONTROL":                  1,
		"DATA":                     2,
	})
	requireEnumNumbers(t, WireOperation(0).Descriptor(), map[string]int32{
		"WIRE_OPERATION_UNSPECIFIED": 0,
		"SCREEN_VIEW":                1,
		"PTY_COMMAND":                2,
	})
}
