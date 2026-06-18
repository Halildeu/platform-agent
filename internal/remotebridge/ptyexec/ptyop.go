package ptyexec

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"time"

	"platform-agent/internal/remotebridge/operation"
	pb "platform-agent/internal/remotebridge/pb"
)

// DefaultExecTimeout bounds a single gated CONSTRAINED_PTY execution. The allowlisted pilot commands are
// short-lived read-only diagnostics; this deadline is the fail-closed backstop against a wedged child — the
// ConPTY runner honours ctx cancellation by terminating the process. NewPtyOperationHandler always yields a
// positive timeout (a <=0 argument takes this default), so an executed command is ALWAYS bounded; output is
// independently bounded by the executor's maxConPTYOutput (8 MiB) cap.
const DefaultExecTimeout = 30 * time.Second

// ErrInvalidOperation is returned for a malformed Handle request (blank stream id / blank command) that is
// refused BEFORE the gated executor runs — fail-closed, no process is ever spawned.
var ErrInvalidOperation = errors.New("ptyexec: invalid pty operation")

// PtyOperationHandler is the agent-side composition of the gated Executor (slice-3c) and the OutputStreamer
// (slice-4): it runs ONE broker-authorized CONSTRAINED_PTY command and streams its pseudo-console output over
// the bridge DATA stream as ordered DataFrames, then a terminal EndStream. It is the capstone of the
// agent-side CONSTRAINED_PTY data path — nothing else composes execute→stream.
//
// Fail-closed + no information-oracle:
//   - a blank stream id / blank command is refused before Execute (no spawn);
//   - a gate-deny / allowlist-reject / exec error streams NO output payload — only a terminal EndStream so the
//     DATA stream stays well-formed — and the error is RETURNED for the caller to surface on the CONTROL
//     stream (an ErrorFrame); the error text never reaches a DATA frame;
//   - any captured partial output is streamed before the terminal EndStream (output → EndStream → error);
//   - a DATA send failure is never swallowed (it is joined with any exec error).
//
// It owns NO stream: the caller injects the DATA send func (the harness owns the live Data stream — slice-5b,
// which is broker/owner-gated). It is disabled-by-default by construction — the idle harness still
// defect-closes an inbound operation_permit; routing a permit here + opening the DATA stream is the
// owner/backend-gated wiring (ADR-0034 §13/D10).
type PtyOperationHandler struct {
	exec        *Executor
	chunk       int
	execTimeout time.Duration
}

// NewPtyOperationHandler builds a handler over a gated executor. chunk<=0 takes DefaultDataFrameChunk (the
// streamer clamps to MaxDataFrameChunk); execTimeout<=0 takes DefaultExecTimeout (so an executed command is
// always bounded). A nil executor is rejected — there would be nothing to gate the command (fail-closed).
func NewPtyOperationHandler(exec *Executor, chunk int, execTimeout time.Duration) (*PtyOperationHandler, error) {
	if exec == nil {
		return nil, errors.New("ptyexec: nil executor")
	}
	if chunk <= 0 {
		chunk = DefaultDataFrameChunk
	}
	if execTimeout <= 0 {
		execTimeout = DefaultExecTimeout
	}
	return &PtyOperationHandler{exec: exec, chunk: chunk, execTimeout: execTimeout}, nil
}

// Handle runs commandLine under permit (the gated executor authorizes + runs it) and streams the captured
// output over the DATA stream identified by streamID via the injected send func, returning the executor's
// ExecResult. See the type doc for the fail-closed contract. nowEpochMillis is the gate's clock; streamID is
// caller-supplied (the caller derives it from the permit so the broker correlates output↔operation).
//
// streamID + send are mandatory and refused when missing (no safe DATA sink). The execution is bounded by the
// handler's execTimeout — a wedged child is torn down on the deadline.
func (h *PtyOperationHandler) Handle(ctx context.Context, permit operation.OperationPermit, commandLine, streamID string, send func(*pb.DataFrame) error, nowEpochMillis int64) (ExecResult, error) {
	if h == nil || h.exec == nil {
		return ExecResult{}, errors.New("ptyexec: nil handler")
	}
	if send == nil {
		return ExecResult{}, errors.New("ptyexec: nil send")
	}
	if strings.TrimSpace(streamID) == "" {
		// No safe DATA sink id — refuse before any frame (output could not be correlated to the operation).
		return ExecResult{}, ErrInvalidOperation
	}
	if strings.TrimSpace(commandLine) == "" {
		// Malformed request: refuse BEFORE the gated executor (no spawn). Emit a lone terminal EndStream so
		// the (already-open) DATA stream is well-formed, then return the error for the CONTROL ErrorFrame.
		endErr := StreamOutput(streamID, PTYContentType, h.chunk, bytes.NewReader(nil), send)
		return ExecResult{}, errors.Join(ErrInvalidOperation, endErr)
	}

	bctx := ctx
	if h.execTimeout > 0 {
		var cancel context.CancelFunc
		bctx, cancel = context.WithTimeout(ctx, h.execTimeout)
		defer cancel()
	}

	res, execErr := h.exec.Execute(bctx, permit, commandLine, nowEpochMillis)

	// Stream whatever output exists, then a terminal EndStream. On a gate-deny the output is empty, so this is
	// a lone EndStream (no payload, no oracle). On an exec error with partial output, the captured bytes are
	// streamed BEFORE the EndStream (output → EndStream → error). The error text never enters a DATA frame.
	streamErr := StreamOutput(streamID, PTYContentType, h.chunk, bytes.NewReader(res.Output), send)

	// The exec error (authorization / execution failure) is what the caller surfaces on CONTROL; a DATA send
	// failure is joined so neither is swallowed and errors.Is still matches each (ErrNotAuthorized, …).
	return res, errors.Join(execErr, streamErr)
}
