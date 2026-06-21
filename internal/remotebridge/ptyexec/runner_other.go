//go:build !windows

package ptyexec

import "context"

func defaultConPTYRunner(ctx context.Context, plan ExecPlan, cols, rows int16) ([]byte, uint32, error) {
	return RunConPTY(ctx, plan.ExePath, plan.CommandLine, cols, rows)
}
