package commands

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"platform-agent/internal/displaypolicy"
	"platform-agent/internal/protocol"
)

type stubAssetFetcher struct {
	content []byte
	err     error
}

func (f stubAssetFetcher) FetchDisplayPolicyAsset(context.Context, string, int64) ([]byte, error) {
	return f.content, f.err
}

type stubAssetStore struct{ stored map[string][]byte }

func (s *stubAssetStore) Commit(name string, content []byte) (string, error) {
	if s.stored == nil {
		s.stored = map[string][]byte{}
	}
	s.stored[name] = content
	return `C:\ProgramData\EndpointAgent\wallpaper\` + name, nil
}

func pngImage() []byte {
	b := make([]byte, 96)
	copy(b, []byte{0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A})
	for i := 8; i < len(b); i++ {
		b[i] = byte(i * 7)
	}
	return b
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func managedWallpaperCommand(sha string) protocol.AgentCommand {
	return protocol.AgentCommand{
		CommandID: "c-dp", ClaimID: "cl-dp", AttemptNumber: 1,
		Type:           protocol.CommandSetDisplayPolicy,
		Reason:         "corporate wallpaper",
		ClaimExpiresAt: time.Now().Add(time.Minute),
		Payload: map[string]interface{}{
			"operation": "ENFORCE", "revisionId": "rev-1", "deviceId": "dev-1", "policyHash": "h",
			"wallpaper": map[string]interface{}{
				"enabled": true, "style": "FILL", "registryValue": "10", "userCannotChange": true,
				"assetRef": "asset:sha256:" + sha, "assetSha256": sha, "contentType": "image/png",
			},
		},
	}
}

func managedExecutor(fetch displaypolicy.AssetFetcher, store displaypolicy.AssetStore) *LocalExecutor {
	e := NewLocalExecutor([]protocol.CommandType{protocol.CommandSetDisplayPolicy}, "test")
	e.ConfigureManagedWallpaper(fetch, store)
	return e
}

func TestExecute_ManagedWallpaper_RegistryWriterOnlySeesTheVerifiedLocalFile(t *testing.T) {
	img := pngImage()
	sha := sha256Hex(img)
	store := &stubAssetStore{}
	wantPath := `C:\ProgramData\EndpointAgent\wallpaper\` + sha + ".png"

	old := applyDisplayPolicyFn
	defer func() { applyDisplayPolicyFn = old }()
	applied := false
	applyDisplayPolicyFn = func(_ context.Context, cmd displaypolicy.Command) displaypolicy.Result {
		applied = true
		if cmd.Wallpaper == nil || cmd.Wallpaper.AssetRef != wantPath {
			t.Errorf("registry writer got assetRef %q, want the stored file %q", cmd.Wallpaper.AssetRef, wantPath)
		}
		if string(store.stored[sha+".png"]) != string(img) {
			t.Error("registry writer ran before the verified image was stored")
		}
		return displaypolicy.Result{FinalStatus: displaypolicy.StatusSucceeded, Summary: "applied"}
	}

	r := managedExecutor(stubAssetFetcher{content: img}, store).Execute(context.Background(), managedWallpaperCommand(sha))

	if !applied || r.Status != protocol.CommandStatusSucceeded {
		t.Fatalf("status=%s applied=%v summary=%q", r.Status, applied, r.Summary)
	}
	res, ok := r.Details["displayPolicy"].(displaypolicy.Result)
	if !ok || res.Asset == nil || res.Asset.LocalPath != wantPath || res.Asset.Bytes != len(img) {
		t.Fatalf("details do not record the stored image: %#v", r.Details["displayPolicy"])
	}
}

func TestExecute_ManagedWallpaper_UnverifiedDownloadWritesNothing(t *testing.T) {
	img := pngImage()
	sha := sha256Hex(img)
	other := append([]byte(nil), img...)
	other[50] ^= 0xFF
	store := &stubAssetStore{}

	old := applyDisplayPolicyFn
	defer func() { applyDisplayPolicyFn = old }()
	applyDisplayPolicyFn = func(context.Context, displaypolicy.Command) displaypolicy.Result {
		t.Error("registry writer ran for an image that did not verify")
		return displaypolicy.Result{}
	}

	r := managedExecutor(stubAssetFetcher{content: other}, store).Execute(context.Background(), managedWallpaperCommand(sha))

	if r.Status != protocol.CommandStatusFailed {
		t.Fatalf("status = %s, want FAILED", r.Status)
	}
	if len(store.stored) != 0 {
		t.Fatal("an unverified image was stored")
	}
	res, _ := r.Details["displayPolicy"].(displaypolicy.Result)
	if res.FinalStatus != displaypolicy.StatusFailedAsset {
		t.Fatalf("finalStatus = %q, want FAILED_ASSET", res.FinalStatus)
	}
}

func TestExecute_ManagedWallpaper_LongDownloadErrorKeepsTheSummaryWithinTheBackendLimit(t *testing.T) {
	sha := sha256Hex(pngImage())
	old := applyDisplayPolicyFn
	defer func() { applyDisplayPolicyFn = old }()
	applyDisplayPolicyFn = func(context.Context, displaypolicy.Command) displaypolicy.Result {
		t.Error("registry writer ran after a failed download")
		return displaypolicy.Result{}
	}
	huge := errors.New("GET /display-policy-assets returned 502: " + strings.Repeat("ü", 3000))

	r := managedExecutor(stubAssetFetcher{err: huge}, &stubAssetStore{}).Execute(context.Background(), managedWallpaperCommand(sha))

	if r.Status != protocol.CommandStatusFailed {
		t.Fatalf("status = %s, want FAILED", r.Status)
	}
	// AgentCommandResultRequest.summary is @Size(max = 1024) characters.
	if n := len([]rune(r.Summary)); n > 1024 {
		t.Fatalf("summary is %d characters, over the backend limit", n)
	}
	if !strings.Contains(r.Summary, "no registry change") {
		t.Fatalf("summary %q does not say nothing was written", r.Summary)
	}
}

func TestConfigureManagedWallpaper_AdvertisesOnlyWhereItCanApply(t *testing.T) {
	count := func(caps []protocol.CommandType) int {
		n := 0
		for _, c := range caps {
			if c == protocol.CapabilitySetDisplayPolicyManagedAsset {
				n++
			}
		}
		return n
	}

	e := managedExecutor(stubAssetFetcher{}, &stubAssetStore{})
	e.ConfigureManagedWallpaper(stubAssetFetcher{}, &stubAssetStore{})
	if count(e.Capabilities) != 1 {
		t.Fatalf("capabilities = %v, want the managed-asset flag exactly once", e.Capabilities)
	}

	noPolicy := NewLocalExecutor([]protocol.CommandType{protocol.CommandCollectInventory}, "test")
	noPolicy.ConfigureManagedWallpaper(stubAssetFetcher{}, &stubAssetStore{})
	if count(noPolicy.Capabilities) != 0 || noPolicy.DisplayPolicyAssets != nil {
		t.Fatal("advertised managed wallpapers on a build that cannot apply a display policy")
	}

	noStore := NewLocalExecutor([]protocol.CommandType{protocol.CommandSetDisplayPolicy}, "test")
	noStore.ConfigureManagedWallpaper(stubAssetFetcher{}, nil)
	if count(noStore.Capabilities) != 0 {
		t.Fatal("advertised managed wallpapers without a store")
	}
}

func TestExecute_ManagedAssetFlagIsNotACommand(t *testing.T) {
	e := managedExecutor(stubAssetFetcher{}, &stubAssetStore{})
	r := e.Execute(context.Background(), protocol.AgentCommand{
		CommandID: "c-flag", ClaimID: "cl-flag", AttemptNumber: 1,
		Type:           protocol.CapabilitySetDisplayPolicyManagedAsset,
		ClaimExpiresAt: time.Now().Add(time.Minute),
	})
	if r.Status != protocol.CommandStatusUnsupported || !strings.Contains(r.Summary, "capability flag") {
		t.Fatalf("status=%s summary=%q", r.Status, r.Summary)
	}
}
