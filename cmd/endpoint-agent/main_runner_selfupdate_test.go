package main

import (
	"io"
	"log"
	"testing"
	"time"

	"platform-agent/internal/config"
)

func TestNewRunnerWiresSelfUpdateActivationHookWhenAutoActivateEnabled(t *testing.T) {
	cfg := config.Default()
	cfg.APIURL = "https://agent.example.test/api/v1/agent"
	cfg.SelfUpdateAutoActivate = true
	cfg.SelfUpdateActivationTimeout = 3 * time.Minute

	runner, err := newRunner(cfg, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatalf("newRunner: %v", err)
	}
	if runner.SelfUpdateActivation == nil {
		t.Fatalf("SelfUpdateActivation hook was not wired")
	}
}

func TestNewRunnerLeavesSelfUpdateActivationHookDisabledByDefault(t *testing.T) {
	cfg := config.Default()
	cfg.APIURL = "https://agent.example.test/api/v1/agent"

	runner, err := newRunner(cfg, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatalf("newRunner: %v", err)
	}
	if runner.SelfUpdateActivation != nil {
		t.Fatalf("SelfUpdateActivation hook should stay nil by default")
	}
}
