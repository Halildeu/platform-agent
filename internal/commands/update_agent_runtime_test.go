package commands

import (
	"context"
	"testing"

	"platform-agent/internal/protocol"
	"platform-agent/internal/selfupdate"
)

func TestPolicyAwareExecutorDefaultRuntimeDoesNotAdvertiseWithoutPolicy(t *testing.T) {
	executor := NewPolicyAwareExecutor("0.1.0-dev", false, UpdateAgentStagerOptions{
		AllowedHosts:      []string{"github.com"},
		SignerThumbprints: []string{"AABBCC"},
		MaxRedirects:      5,
		HardMaxBytes:      1000,
		Verifier:          fakeUpdateVerifier{},
		VersionReader:     fakeUpdateVersionReader{},
		Downloader:        fakeUpdateDownloader{},
		Staging:           fakeUpdateStaging{},
		PlanWriter:        fakeActivationPlanWriter{},
		CurrentBinaryPath: "/agent/current",
		ServiceName:       "EndpointAgent",
	})

	if hasExecutorCapability(executor, protocol.CommandUpdateAgent) {
		t.Fatal("runtime collaborators without local policy must not advertise UPDATE_AGENT")
	}
}

func TestUpdateAgentStagerOptionsRuntimeReadyRequiresAllRuntimeCollaborators(t *testing.T) {
	base := UpdateAgentStagerOptions{
		AllowedHosts:      []string{"github.com"},
		SignerThumbprints: []string{"AABBCC"},
		MaxRedirects:      5,
		HardMaxBytes:      1000,
	}
	if base.RuntimeReady() {
		t.Fatal("runtime-ready must fail without verifier/downloader/version/staging collaborators")
	}
	base.Verifier = fakeUpdateVerifier{}
	base.VersionReader = fakeUpdateVersionReader{}
	base.Downloader = fakeUpdateDownloader{}
	base.Staging = fakeUpdateStaging{}
	if base.RuntimeReady() {
		t.Fatal("runtime-ready must fail without activation plan collaborator and local activation inputs")
	}
	base.PlanWriter = fakeActivationPlanWriter{}
	base.CurrentBinaryPath = "/agent/current"
	base.ServiceName = "EndpointAgent"
	if !base.RuntimeReady() {
		t.Fatal("runtime-ready should pass when all required collaborators and local policy are present")
	}
}

func TestNewUpdateAgentStagerCarriesOptionalHighWaterAndTempDir(t *testing.T) {
	store := fakeHighWaterStore{}
	stager := NewUpdateAgentStager(UpdateAgentStagerOptions{
		AllowedHosts:      []string{"github.com"},
		SignerThumbprints: []string{"AABBCC"},
		MaxRedirects:      5,
		HardMaxBytes:      1000,
		Verifier:          fakeUpdateVerifier{},
		VersionReader:     fakeUpdateVersionReader{},
		Downloader:        fakeUpdateDownloader{},
		Staging:           fakeUpdateStaging{},
		PlanWriter:        fakeActivationPlanWriter{},
		HighWater:         store,
		TempDir:           t.TempDir(),
		CurrentBinaryPath: "/agent/current",
		ServiceName:       "EndpointAgent",
	})
	if stager == nil {
		t.Fatal("expected stager")
	}
	if stager.HighWater == nil {
		t.Fatal("expected high-water collaborator to be carried")
	}
	if stager.TempDir == "" {
		t.Fatal("expected temp dir to be carried")
	}
	if stager.PlanWriter == nil || stager.CurrentBinaryPath == "" || stager.ServiceName == "" {
		t.Fatal("expected activation plan collaborators to be carried")
	}
}

type fakeHighWaterStore struct{}

func (fakeHighWaterStore) ReadMaxSeen(_ context.Context) (string, error) {
	return "", nil
}

var _ selfupdate.HighWaterStore = fakeHighWaterStore{}
