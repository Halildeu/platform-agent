//go:build windows

package main

import (
	"context"
	"os/exec"
	"syscall"
)

func startSelfUpdateActivationHelperProcess(ctx context.Context, executable string, args []string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	cmd := exec.Command(executable, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		// DETACHED_PROCESS + CREATE_NEW_PROCESS_GROUP. The helper must survive
		// the parent service process being stopped during activation.
		CreationFlags: 0x00000008 | 0x00000200,
	}
	return cmd.Start()
}
