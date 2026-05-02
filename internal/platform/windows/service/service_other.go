//go:build !windows

package service

import (
	"context"
	"fmt"
)

func IsWindowsService() (bool, error) {
	return false, nil
}

func Run(_ string, _ func(context.Context) error) error {
	return unsupported()
}

func Install(_ Options) error {
	return unsupported()
}

func Uninstall(_ Options) error {
	return unsupported()
}

func Start(_ Options) error {
	return unsupported()
}

func Stop(_ Options) error {
	return unsupported()
}

func QueryStatus(options Options) (StatusSnapshot, error) {
	options = options.Normalized()
	return StatusSnapshot{Name: options.Name, State: "unsupported"}, unsupported()
}

func unsupported() error {
	return fmt.Errorf("windows service commands are only supported on Windows")
}
