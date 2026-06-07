//go:build windows

package selfupdate

import (
	"context"
	"fmt"
	"os"
	"testing"
)

func TestStage_ClosesTempFileBeforeVerifier(t *testing.T) {
	s, _, _ := newHappyStager(t)
	s.Verifier = movingFileVerifier{
		ev: AuthenticodeEvidence{
			ChainValid:        true,
			HasCodeSigningEKU: true,
			SignerThumbprint:  goodThumb,
			CurrentTimeValid:  true,
		},
	}

	r := s.Stage(context.Background(), happyPayload(), "1.0.0")
	if r.StageStatus != StageReady {
		t.Fatalf("want ready, got %q/%q reason=%q", r.StageStatus, r.ErrorCode, r.Reason)
	}
}

type movingFileVerifier struct {
	ev AuthenticodeEvidence
}

func (v movingFileVerifier) Verify(_ context.Context, path string) (AuthenticodeEvidence, error) {
	moved := path + ".verifier-move"
	if err := os.Rename(path, moved); err != nil {
		return AuthenticodeEvidence{}, fmt.Errorf("candidate binary is still locked before verifier: %w", err)
	}
	if err := os.Rename(moved, path); err != nil {
		return AuthenticodeEvidence{}, fmt.Errorf("restore candidate binary after verifier move: %w", err)
	}
	return v.ev, nil
}
