package harness

import (
	"context"
	"errors"
	"time"

	"google.golang.org/grpc"

	"platform-agent/internal/remotebridge/operation"
	pb "platform-agent/internal/remotebridge/pb"
	"platform-agent/internal/remotebridge/ptyexec"
)

// PTYDispatcher executes ONE broker-authorized CONSTRAINED_PTY operation and streams its pseudo-console output
// via send (the bridge DATA stream). The production implementation is *ptyexec.PtyOperationHandler (slice-5a);
// the harness depends on this seam — not the concrete type — so the dispatch WIRING (decode → DATA stream →
// frames → CONTROL error) is testable without a real pseudo-console (the crypto/gate/ConPTY are tested in the
// ptyexec + operation packages). A nil dispatcher leaves the harness in its idle T-3 mode: an inbound
// operation_dispatch is a protocol defect (disabled-by-default).
type PTYDispatcher interface {
	Handle(ctx context.Context, permit operation.OperationPermit, commandLine, streamID string,
		send func(*pb.DataFrame) error, nowEpochMillis int64) (ptyexec.ExecResult, error)
}

// errDispatchDecode marks a broker OperationDispatch that cannot be mapped to a domain permit — a protocol
// defect (the CONTROL stream is closed), never a silent drop.
var errDispatchDecode = errors.New("operation-dispatch-decode-failed")

// dataStreamDrainGrace bounds how long dispatchOperation waits, after CloseSend, for the broker to consume the
// queued output frames and close its half of the DATA stream — a backstop against a misbehaving broker that
// never closes (the goroutine cancels the stream and exits rather than blocking forever). A well-behaved
// broker closes first (io.EOF) and the timer is stopped unused.
const dataStreamDrainGrace = 2 * time.Second

// decodeDispatch maps a broker-pushed pb.OperationDispatch onto the domain (operation.OperationPermit + the
// raw plaintext command). FAIL-CLOSED on a nil dispatch/permit. This is a straight FIELD MAP + presence check:
// the AUTHORITATIVE checks — the ECDSA signature (operation.Verifier), freshness, the per-session seq, and the
// command↔hash binding — are the gate's job (ptyexec.Executor via the dispatcher), never duplicated here. The
// command is carried EXACT/raw (CanonicalCommand canonicalises only for the hash-check; the wire never trims).
func decodeDispatch(d *pb.OperationDispatch) (operation.OperationPermit, string, error) {
	if d == nil || d.GetPermit() == nil {
		return operation.OperationPermit{}, "", errDispatchDecode
	}
	p := d.GetPermit()
	// operationId is the DATA-stream correlation key (the streamID the output frames carry). An empty one
	// cannot correlate the operation's output → fail-closed (Codex 019ecd07 hardening).
	if p.GetOperationId() == "" {
		return operation.OperationPermit{}, "", errDispatchDecode
	}
	permit := operation.OperationPermit{
		Alg:                  p.GetAlg(),
		Kid:                  p.GetKid(),
		PermitVersion:        p.GetPermitVersion(),
		PolicyVersion:        p.GetPolicyVersion(),
		DecisionID:           p.GetDecisionId(),
		SessionID:            p.GetSessionId(),
		OperationID:          p.GetOperationId(),
		DeviceID:             p.GetDeviceId(),
		OperatorSubject:      p.GetOperatorSubject(),
		Capability:           p.GetCapability().String(), // the enum NAME, e.g. "CONSTRAINED_PTY"
		CommandHash:          p.GetCommandHash(),
		IssuedAtEpochMillis:  p.GetIssuedAtEpochMillis(),
		ExpiresAtEpochMillis: p.GetExpiresAtEpochMillis(),
		Seq:                  p.GetSeq(),
		SignatureB64:         p.GetSignatureB64(),
	}
	return permit, d.GetCommandLine(), nil
}

// dispatchOperation runs ONE authorized CONSTRAINED_PTY operation to completion and streams its output over a
// fresh, per-operation DATA stream, then closes it. It runs in its OWN goroutine off the CONTROL recv loop (so
// a long-running command never blocks heartbeats or a KILL) under a CHILD of the stream context: a transport
// KILL, a dropped stream, or ctx cancellation cancels opCtx, which tears the ConPTY child down (the dispatcher
// honours ctx). The command is gated by the dispatcher (verify → capability → hash → seq → allowlist); a
// deny / allowlist-reject / exec error surfaces as a CONTROL ErrorFrame (no DATA payload, no oracle — the
// dispatcher emitted only a terminal EndStream on DATA), and the transport stays up.
func (h *Harness) dispatchOperation(ctx context.Context, conn *grpc.ClientConn,
	permit operation.OperationPermit, commandLine, deviceID string, sender *controlSender) {
	// Device binding — the PRIMARY, dynamic (re-enrollment-aware) check; the
	// harness alone holds the live agent identity. A broker-signed permit carries
	// its target DeviceID as a SIGNED CanonicalPayload field; refuse to execute one
	// minted for a DIFFERENT device even with a valid broker signature, so a
	// misrouted or leaked permit never runs here. (operation.Verifier ALSO binds
	// DeviceID statically as a gate/executor-path backstop.) Fail-closed (no DATA
	// stream, no execution, no oracle beyond a bounded CONTROL code). deviceID is
	// the identity this stream presented in AgentHello and is non-empty (connectOnce
	// only dispatches with one).
	if deviceID == "" || permit.DeviceID != deviceID {
		_ = sender.sendError("operation-device-mismatch", false)
		return
	}
	opCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	dataStream, err := pb.NewRemoteBridgeClient(conn).Data(opCtx)
	if err != nil {
		_ = sender.sendError("data-stream-open-failed", true)
		return
	}
	// The DATA-stream sink: each pb.DataFrame travels as an Envelope.data_frame on the DATA channel. The frame
	// carries its OWN frame_seq (per the wire rule the DATA Envelope.frame_seq stays 0 and stream_id is empty).
	send := func(f *pb.DataFrame) error {
		return dataStream.Send(&pb.Envelope{
			ChannelType: pb.ChannelType_DATA,
			Payload:     &pb.Envelope_DataFrame{DataFrame: f},
		})
	}

	_, herr := h.cfg.PTYDispatcher.Handle(opCtx, permit, commandLine, permit.OperationID, send,
		time.Now().UnixMilli())
	// A Send only QUEUES a frame; CloseSend signals end-of-output. Drain the server's half to EOF BEFORE the
	// deferred cancel fires — otherwise cancelling opCtx would abort frames still in flight (the broker would
	// see Canceled mid-stream and lose the tail, e.g. the terminal EndStream). The broker closes its side once
	// it has consumed everything, so Recv returns io.EOF and the output is fully delivered + cleanly closed.
	_ = dataStream.CloseSend()
	drainTimer := time.AfterFunc(dataStreamDrainGrace, cancel) // bound the drain — never block forever on a bad broker
	for {
		if _, rerr := dataStream.Recv(); rerr != nil {
			break // io.EOF (clean) or a cancellation (teardown / drain grace); not surfaced as an operation error
		}
	}
	drainTimer.Stop()
	if herr != nil {
		// The operation failed (gate-deny / allowlist-reject / exec error). The transport is healthy — report on
		// CONTROL with a bounded, non-revealing code; the DATA stream was already closed with a terminal EndStream.
		_ = sender.sendError("operation-dispatch-failed", false)
	}
}
