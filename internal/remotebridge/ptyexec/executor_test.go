package ptyexec

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"sync"
	"testing"

	"platform-agent/internal/remotebridge/operation"
)

// The authoritative cross-language permit vector (same file the operation + backend tests assert), embedded
// so the gated executor is tested against the REAL gate (real ECDSA verify), not a mock.
//
//go:embed testdata/pty-permit-vector.json
var permitVectorJSON []byte

type execVector struct {
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
	SignatureB64         string `json:"signatureB64"`
	BrokerPublicKeyB64   string `json:"brokerPublicKeyB64"`
}

const execFreshNow = int64(1100) // inside the vector's [issuedAt=1000, expiresAt=1300)

func loadExecVector(t *testing.T) (operation.OperationPermit, *operation.Verifier, execVector) {
	t.Helper()
	var v execVector
	if err := json.Unmarshal(permitVectorJSON, &v); err != nil {
		t.Fatalf("parse embedded vector: %v", err)
	}
	ver, err := operation.NewVerifier(v.BrokerPublicKeyB64, v.Kid)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	p := operation.OperationPermit{
		Alg: v.Alg, Kid: v.Kid, PermitVersion: v.PermitVersion, PolicyVersion: v.PolicyVersion,
		DecisionID: v.DecisionID, SessionID: v.SessionID, OperationID: v.OperationID, DeviceID: v.DeviceID,
		OperatorSubject: v.OperatorSubject, Capability: v.Capability, CommandHash: v.CommandHash,
		IssuedAtEpochMillis: v.IssuedAtEpochMillis, ExpiresAtEpochMillis: v.ExpiresAtEpochMillis,
		Seq: v.Seq, SignatureB64: v.SignatureB64,
	}
	return p, ver, v
}

// a recorder run: captures whether/how the ConPTY runner was invoked, returns a canned result.
type recorderRun struct {
	mu      sync.Mutex
	called  bool
	gotExe  string
	gotCmd  string
	retOut  []byte
	retCode uint32
	retErr  error
}

func (r *recorderRun) fn(_ context.Context, exePath, commandLine string, _, _ int16) ([]byte, uint32, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.called = true
	r.gotExe = exePath
	r.gotCmd = commandLine
	return r.retOut, r.retCode, r.retErr
}

func TestExecutorHappyAuthorizesThenRuns(t *testing.T) {
	permit, ver, v := loadExecVector(t)
	rec := &recorderRun{retOut: []byte("RENDERED-OUTPUT"), retCode: 0}
	e := NewExecutor(ver, DefaultAllowlist(), 0, 0)
	e.run = rec.fn

	res, err := e.Execute(context.Background(), permit, v.CommandLine, execFreshNow)
	if err != nil {
		t.Fatalf("authorized hostname should execute: %v", err)
	}
	if !rec.called {
		t.Fatal("the runner was not invoked for an authorized command")
	}
	if rec.gotExe != `C:\Windows\System32\hostname.exe` {
		t.Errorf("ran the wrong binary: %q", rec.gotExe)
	}
	if string(res.Output) != "RENDERED-OUTPUT" || res.ExitCode != 0 {
		t.Errorf("result not propagated: out=%q code=%d", res.Output, res.ExitCode)
	}
}

func TestExecutorDeniedCommandsNeverRun(t *testing.T) {
	permit, ver, v := loadExecVector(t)

	cases := []struct {
		name string
		cmd  string
		now  int64
	}{
		{"wrong command (hash mismatch)", "whoami", execFreshNow},
		{"expired permit", v.CommandLine, v.ExpiresAtEpochMillis},
		{"not-yet-valid permit", v.CommandLine, v.IssuedAtEpochMillis - 1},
	}
	for _, c := range cases {
		rec := &recorderRun{}
		e := NewExecutor(ver, DefaultAllowlist(), 0, 0)
		e.run = rec.fn
		_, err := e.Execute(context.Background(), permit, c.cmd, c.now)
		if !errors.Is(err, ErrNotAuthorized) {
			t.Errorf("%s: expected ErrNotAuthorized, got %v", c.name, err)
		}
		if rec.called {
			t.Errorf("%s: a DENIED command reached execution — fail-closed violated", c.name)
		}
	}
}

func TestExecutorNotAllowlistedNeverRuns(t *testing.T) {
	permit, ver, v := loadExecVector(t)
	rec := &recorderRun{}
	e := NewExecutor(ver, map[string]AllowRule{}, 0, 0) // empty allowlist: even an authorized command resolves to nothing
	e.run = rec.fn
	_, err := e.Execute(context.Background(), permit, v.CommandLine, execFreshNow)
	if !errors.Is(err, ErrNotAllowlisted) {
		t.Errorf("expected ErrNotAllowlisted, got %v", err)
	}
	if rec.called {
		t.Error("a non-allowlisted command reached execution — fail-closed violated")
	}
}

func TestExecutorRunErrorPropagates(t *testing.T) {
	permit, ver, v := loadExecVector(t)
	sentinel := errors.New("conpty boom")
	rec := &recorderRun{retErr: sentinel}
	e := NewExecutor(ver, DefaultAllowlist(), 0, 0)
	e.run = rec.fn
	_, err := e.Execute(context.Background(), permit, v.CommandLine, execFreshNow)
	if !errors.Is(err, sentinel) {
		t.Errorf("run error not propagated: %v", err)
	}
	if !rec.called {
		t.Error("the runner should have been invoked (gate + allowlist passed)")
	}
}

func TestExecutorNilVerifierDenies(t *testing.T) {
	permit, _, v := loadExecVector(t)
	rec := &recorderRun{}
	e := NewExecutor(nil, DefaultAllowlist(), 0, 0) // nil verifier ⇒ deny-everything gate
	e.run = rec.fn
	if _, err := e.Execute(context.Background(), permit, v.CommandLine, execFreshNow); !errors.Is(err, ErrNotAuthorized) {
		t.Errorf("nil verifier must deny: %v", err)
	}
	if rec.called {
		t.Error("nil verifier allowed execution — fail-closed violated")
	}
}
