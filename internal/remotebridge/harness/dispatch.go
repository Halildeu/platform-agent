package harness

import (
	"context"
	"errors"
	"strings"
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

// ScreenViewDispatcher runs ONE broker-authorized VIEW_ONLY screen-observation operation and streams its
// captured screen frames via send (the bridge DATA stream). The production implementation lives in
// internal/remotebridge/screenview (a later sub-slice); the harness depends on this seam — not the concrete
// type — so the dispatch WIRING (decode → DATA stream → frames → CONTROL error) is testable without a display
// or the Windows capture code. A nil dispatcher leaves the harness disabled-by-default: an inbound VIEW_ONLY
// operation_permit is a protocol defect (LIVE activation is owner-gated, ADR-0034 §13/D10). Unlike the PTY
// path, a VIEW_ONLY permit carries NO command — the agent observes the screen, it executes nothing.
type ScreenViewDispatcher interface {
	Handle(ctx context.Context, permit operation.OperationPermit, streamID string,
		send func(*pb.DataFrame) error, nowEpochMillis int64) error
}

// errPermitDecode marks a broker OperationPermit that cannot be mapped to a domain permit — a protocol defect
// (the CONTROL stream is closed), never a silent drop.
var errPermitDecode = errors.New("operation-permit-decode-failed")

// decodeOperationPermit maps a broker-pushed bare pb.OperationPermit (the VIEW_ONLY push — no OperationDispatch
// wrapper, no command) onto the domain operation.OperationPermit. FAIL-CLOSED on a nil permit or a missing
// session/operation id (the operation id is the DATA-stream correlation key). The AUTHORITATIVE checks
// (signature, freshness, capability, seq) are the operation.Authorizer's job (AuthorizeViewOnly), never
// duplicated here — this is a field map + presence check, mirroring decodeDispatch.
func decodeOperationPermit(p *pb.OperationPermit) (operation.OperationPermit, error) {
	if p == nil {
		return operation.OperationPermit{}, errPermitDecode
	}
	if p.GetOperationId() == "" || p.GetSessionId() == "" {
		return operation.OperationPermit{}, errPermitDecode
	}
	return operation.OperationPermit{
		Alg:                  p.GetAlg(),
		Kid:                  p.GetKid(),
		PermitVersion:        p.GetPermitVersion(),
		PolicyVersion:        p.GetPolicyVersion(),
		DecisionID:           p.GetDecisionId(),
		SessionID:            p.GetSessionId(),
		OperationID:          p.GetOperationId(),
		DeviceID:             p.GetDeviceId(),
		OperatorSubject:      p.GetOperatorSubject(),
		Capability:           p.GetCapability().String(), // the enum NAME, e.g. "VIEW_ONLY"
		CommandHash:          p.GetCommandHash(),
		IssuedAtEpochMillis:  p.GetIssuedAtEpochMillis(),
		ExpiresAtEpochMillis: p.GetExpiresAtEpochMillis(),
		Seq:                  p.GetSeq(),
		SignatureB64:         p.GetSignatureB64(),
	}, nil
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
	// sessionId is the broker/WORM recording boundary for DATA frames. Without it, broker-side audit cannot
	// bind terminal output to the approved session, so fail closed before execution.
	if p.GetSessionId() == "" {
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
		_ = sender.sendSessionError(permit.SessionID, "operation-device-mismatch", false)
		return
	}
	opCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	dataStream, err := pb.NewRemoteBridgeClient(conn).Data(opCtx)
	if err != nil {
		_ = sender.sendSessionError(permit.SessionID, "data-stream-open-failed", true)
		return
	}
	// The DATA-stream sink: each pb.DataFrame travels as an Envelope.data_frame on the DATA channel. The
	// envelope carries the approved session + operation correlation fields required by the broker/WORM
	// recorder; the frame carries ordered PTY bytes and the terminal EndStream marker.
	send := func(f *pb.DataFrame) error {
		return dataStream.Send(&pb.Envelope{
			SessionId:         permit.SessionID,
			StreamId:          permit.OperationID,
			ChannelType:       pb.ChannelType_DATA,
			SentAtEpochMillis: time.Now().UnixMilli(),
			Payload:           &pb.Envelope_DataFrame{DataFrame: f},
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
		_ = sender.sendSessionError(permit.SessionID, dispatchErrorCode(herr), false)
	}
}

func dispatchErrorCode(err error) string {
	if err == nil {
		return ""
	}
	switch {
	case errors.Is(err, ptyexec.ErrNotAuthorized):
		return "operation-dispatch-failed:" + authzReasonCode(err)
	case errors.Is(err, ptyexec.ErrNotAllowlisted):
		return "operation-dispatch-failed:not-allowlisted"
	case errors.Is(err, ptyexec.ErrArgPolicy):
		return "operation-dispatch-failed:arg-policy"
	case errors.Is(err, ptyexec.ErrInvalidOperation):
		return "operation-dispatch-failed:invalid-operation"
	case errors.Is(err, ptyexec.ErrConPTYEmptyOutput):
		return "operation-dispatch-failed:empty-output"
	default:
		return "operation-dispatch-failed:exec-failed"
	}
}

func authzReasonCode(err error) string {
	msg := err.Error()
	for _, reason := range []string{
		operation.ReasonPermitVerifierUnavailable,
		operation.ReasonPermitKidMismatch,
		operation.ReasonPermitAlgMismatch,
		operation.ReasonPermitSignatureMissing,
		operation.ReasonPermitVersionMismatch,
		operation.ReasonPermitDeviceMismatch,
		operation.ReasonPermitNotFresh,
		operation.ReasonPermitSignatureDecode,
		operation.ReasonPermitSignatureInvalid,
		operation.ReasonPermitInvalid,
		operation.ReasonCapabilityNotPTY,
		operation.ReasonCommandTooLong,
		operation.ReasonEmptyCommand,
		operation.ReasonCommandMismatch,
		operation.ReasonSeqInvalid,
		operation.ReasonSeqReplay,
	} {
		if strings.Contains(msg, reason) {
			return reason
		}
	}
	return "not-authorized"
}

// dispatchScreenView runs ONE authorized VIEW_ONLY screen-observation operation and streams its captured frames
// over a fresh, per-operation DATA stream, then closes it. Like dispatchOperation it runs in its OWN goroutine
// off the CONTROL recv loop under a CHILD of the stream context, so a long-lived screen feed never blocks
// heartbeats or a KILL. It registers its cancel under the sessionId so a SESSION-SCOPED kill (which keeps the
// transport up) cancels THIS screen stream; a transport kill cancels the parent stream ctx and so every child
// anyway. Device binding is the PRIMARY dynamic check (refuse a permit minted for another device, even validly
// signed). A handler error surfaces as a bounded CONTROL ErrorFrame; the transport stays up. The dispatcher
// honours ctx cancellation (it must Abort its ViewSession so no frame egresses after the gate closes).
func (h *Harness) dispatchScreenView(ctx context.Context, conn *grpc.ClientConn,
	permit operation.OperationPermit, deviceID string, sender *controlSender) {
	if deviceID == "" || permit.DeviceID != deviceID {
		_ = sender.sendSessionError(permit.SessionID, "operation-device-mismatch", false)
		return
	}
	opCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	// register so a session-scoped KILL (obeyKill) can tear down THIS running screen stream — no frame may
	// egress after a kill, and a session kill keeps the transport up so sctx-cancel alone would not reach it.
	cancelEntry := h.registerScreenCancel(permit.SessionID, cancel)
	defer h.unregisterScreenCancel(permit.SessionID, cancelEntry)

	dataStream, err := pb.NewRemoteBridgeClient(conn).Data(opCtx)
	if err != nil {
		_ = sender.sendSessionError(permit.SessionID, "data-stream-open-failed", true)
		return
	}
	send := func(f *pb.DataFrame) error {
		return dataStream.Send(&pb.Envelope{
			SessionId:         permit.SessionID,
			StreamId:          permit.OperationID,
			ChannelType:       pb.ChannelType_DATA,
			SentAtEpochMillis: time.Now().UnixMilli(),
			Payload:           &pb.Envelope_DataFrame{DataFrame: f},
		})
	}
	herr := h.cfg.ScreenViewDispatcher.Handle(opCtx, permit, permit.OperationID, send, time.Now().UnixMilli())
	// Drain the broker's half to EOF before the deferred cancel fires so the terminal EndStream is delivered
	// (same rationale as dispatchOperation); bound the drain against a broker that never closes.
	_ = dataStream.CloseSend()
	drainTimer := time.AfterFunc(dataStreamDrainGrace, cancel)
	for {
		if _, rerr := dataStream.Recv(); rerr != nil {
			break
		}
	}
	drainTimer.Stop()
	if herr != nil {
		// bounded, non-revealing CONTROL code; the DATA stream was already closed with a terminal EndStream
		_ = sender.sendSessionError(permit.SessionID, "screen-view-failed", false)
	}
}
