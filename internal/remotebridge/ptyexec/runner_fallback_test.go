package ptyexec

import (
	"context"
	"errors"
	"testing"
)

func TestShouldUseDirectCaptureFallback(t *testing.T) {
	t.Parallel()

	t.Run("empty output without cancellation falls back", func(t *testing.T) {
		t.Parallel()
		if !shouldUseDirectCaptureFallback(context.Background(), nil, nil) {
			t.Fatal("expected fallback for empty output")
		}
	})

	t.Run("nonempty output does not fall back", func(t *testing.T) {
		t.Parallel()
		if shouldUseDirectCaptureFallback(context.Background(), []byte("host\r\n"), nil) {
			t.Fatal("did not expect fallback for nonempty output")
		}
	})

	t.Run("output cap does not fall back", func(t *testing.T) {
		t.Parallel()
		if shouldUseDirectCaptureFallback(context.Background(), nil, ErrConPTYOutputCap) {
			t.Fatal("did not expect fallback after output cap")
		}
	})

	t.Run("cancelled context does not fall back", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if shouldUseDirectCaptureFallback(ctx, nil, errors.New("launch failed")) {
			t.Fatal("did not expect fallback after cancellation")
		}
	})
}
