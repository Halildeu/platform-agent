package ptyexec

import (
	"context"
	"errors"
	"fmt"

	"platform-agent/internal/remotebridge/operation"
)

// ErrNotAuthorized is returned when the operation gate denies the command — NO process is spawned.
var ErrNotAuthorized = errors.New("ptyexec: command not authorized")

// ExecResult is a completed gated execution's captured output + exit code.
type ExecResult struct {
	Output   []byte
	ExitCode uint32
}

// Executor is the gated CONSTRAINED_PTY executor (slice-3c): it runs a command ONLY after the operation gate
// authorizes it against a broker-signed permit, then resolves it against the allowlist (no-shell ExecPlan)
// and runs it in a pseudo-console. Fail-closed: a gate-deny or an allowlist-reject means NO process is ever
// spawned. It composes the proven pieces — operation.Authorizer (slice-2), BuildExecPlan (slice-3a), and
// RunConPTY (slice-3b).
type Executor struct {
	authz      *operation.Authorizer
	allowlist  map[string]AllowRule
	cols, rows int16
	// run is the ConPTY runner (RunConPTY); a field so tests can inject a recorder/fake and assert that a
	// denied command NEVER reaches execution. It receives the already-authorized ExecPlan so fallback runners
	// can use the no-shell argv directly instead of reparsing a command-line string.
	run func(ctx context.Context, plan ExecPlan, cols, rows int16) ([]byte, uint32, error)
}

// NewExecutor builds the gated executor over a permit verifier + a command allowlist. cols/rows <= 0 take the
// ConPTY defaults. A nil verifier yields a deny-everything gate (fail-closed).
func NewExecutor(verifier *operation.Verifier, allowlist map[string]AllowRule, cols, rows int16) *Executor {
	return NewExecutorWithAuthorizer(operation.NewAuthorizer(verifier), allowlist, cols, rows)
}

// NewExecutorWithAuthorizer builds the gated executor over an ALREADY-CONSTRUCTED operation.Authorizer + a
// command allowlist, so the caller can SHARE one Authorizer — and therefore one per-session seq guard
// (a.lastSeq+a.mu) — across capabilities. The VIEW_ONLY path and the CONSTRAINED_PTY path MUST share the same
// *operation.Authorizer instance or the broker's cross-capability monotonic seq is no longer replay-protected
// (see operation.AuthorizeViewOnly). cols/rows <= 0 take the ConPTY defaults. A nil authorizer is fail-closed:
// Execute returns ErrNotAuthorized (no spawn).
func NewExecutorWithAuthorizer(authz *operation.Authorizer, allowlist map[string]AllowRule, cols, rows int16) *Executor {
	return &Executor{
		authz:     authz,
		allowlist: allowlist,
		cols:      cols,
		rows:      rows,
		run:       defaultConPTYRunner,
	}
}

// Execute authorizes commandLine under permit at now, and ONLY on success resolves the no-shell ExecPlan and
// runs it in a pseudo-console — returning the captured output + exit code. Fail-closed + IN ORDER:
//  1. the operation gate (Authorize: verify / capability / command==permit.commandHash / seq) — deny →
//     ErrNotAuthorized, NO spawn;
//  2. the allowlist (BuildExecPlan) — reject → its error, NO spawn;
//  3. the ConPTY run.
//
// commandLine must be the SAME string the broker bound (the gate hashes it against permit.commandHash; the
// plan re-resolves it) — operation.ParseCommand canonicalises it consistently for both.
func (e *Executor) Execute(ctx context.Context, permit operation.OperationPermit, commandLine string, nowEpochMillis int64) (ExecResult, error) {
	if e == nil || e.run == nil || e.authz == nil {
		return ExecResult{}, ErrNotAuthorized
	}
	if d := e.authz.Authorize(permit, commandLine, nowEpochMillis); !d.Allowed {
		return ExecResult{}, fmt.Errorf("%w: %s", ErrNotAuthorized, d.Reason)
	}
	plan, err := BuildExecPlan(operation.ParseCommand(commandLine), e.allowlist)
	if err != nil {
		return ExecResult{}, err
	}
	out, code, err := e.run(ctx, plan, e.cols, e.rows)
	if err != nil {
		return ExecResult{Output: out, ExitCode: code}, err
	}
	if len(out) == 0 {
		return ExecResult{Output: out, ExitCode: code}, ErrConPTYEmptyOutput
	}
	return ExecResult{Output: out, ExitCode: code}, nil
}
