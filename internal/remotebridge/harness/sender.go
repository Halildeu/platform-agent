package harness

import (
	"fmt"
	"sync"
	"time"

	pb "platform-agent/internal/remotebridge/pb"
)

// controlSender is THE serialized outbound write path for one CONTROL
// stream (the agent-side mirror of the broker's ControlStreamHandle): a gRPC
// client stream is not a thread-safe sink, every send goes through one
// mutex, and the outbound Envelope.frameSeq is stamped contiguous-from-0 —
// the T-2b broker closes the stream on any gap or replay.
//
// It also enforces the directional allowlist LOCALLY: the broker accepts
// only agent_hello / consent_result / audit_event / heartbeat / error
// inbound on CONTROL. send refuses anything else before it can reach the
// wire — a non-allowlisted payload here is a programming error, not a
// negotiation.
type controlSender struct {
	mu      sync.Mutex
	stream  pb.RemoteBridge_ConnectClient
	nextSeq int64
}

func (s *controlSender) sendHello(hello *pb.AgentHello) error {
	return s.send(&pb.Envelope{Payload: &pb.Envelope_AgentHello{AgentHello: hello}})
}

func (s *controlSender) sendError(code string, retryable bool) error {
	return s.send(&pb.Envelope{Payload: &pb.Envelope_Error{Error: &pb.ErrorFrame{
		Code:      code,
		Retryable: retryable,
	}}})
}

func (s *controlSender) sendSessionError(sessionID, code string, retryable bool) error {
	return s.send(&pb.Envelope{
		SessionId: sessionID,
		Payload: &pb.Envelope_Error{Error: &pb.ErrorFrame{
			Code:      code,
			Retryable: retryable,
		}},
	})
}

func (s *controlSender) sendConsentResult(result *pb.ConsentResult) error {
	return s.send(&pb.Envelope{
		SessionId: result.GetSessionId(),
		Payload:   &pb.Envelope_ConsentResult{ConsentResult: result},
	})
}

// send stamps channel/seq/sentAt and writes. The payload must already be on
// the agent-allowed CONTROL set.
func (s *controlSender) send(env *pb.Envelope) error {
	if !agentMaySend(env) {
		return fmt.Errorf("payload %T is not agent-sendable on CONTROL", env.GetPayload())
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	env.ChannelType = pb.ChannelType_CONTROL
	env.FrameSeq = s.nextSeq
	env.SentAtEpochMillis = time.Now().UnixMilli()
	if err := s.stream.Send(env); err != nil {
		return err
	}
	s.nextSeq++
	return nil
}

// agentMaySend is the agent→broker CONTROL allowlist (wire-contract
// directional rule, enforced by the T-2b broker; re-enforced here so a bug
// cannot even attempt to inject broker authority from the endpoint).
func agentMaySend(env *pb.Envelope) bool {
	switch env.GetPayload().(type) {
	case *pb.Envelope_AgentHello,
		*pb.Envelope_ConsentResult,
		*pb.Envelope_AuditEvent,
		*pb.Envelope_Heartbeat,
		*pb.Envelope_Error:
		return true
	default:
		return false
	}
}
