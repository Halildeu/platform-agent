package ptyexec

import (
	"context"
	"errors"
)

func shouldUseDirectCaptureFallback(ctx context.Context, out []byte, err error) bool {
	if len(out) > 0 {
		return false
	}
	if ctx != nil && ctx.Err() != nil {
		return false
	}
	if errors.Is(err, ErrConPTYOutputCap) {
		return false
	}
	return true
}
