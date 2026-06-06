//go:build !windows

package main

import (
	"context"
	"errors"
)

func startSelfUpdateActivationHelperProcess(_ context.Context, _ string, _ []string) error {
	return errors.New("activation helper launch is windows-only")
}
