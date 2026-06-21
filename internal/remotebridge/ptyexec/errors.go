package ptyexec

import "errors"

// ErrConPTYOutputCap is returned when a command's captured output exceeds the bounded output cap.
// The partial output is truncated to the cap and the child is torn down fail-closed.
var ErrConPTYOutputCap = errors.New("ptyexec: conpty output exceeded cap")

// ErrConPTYEmptyOutput is returned when every bounded execution path completes without producing bytes.
// A silent EndStream-only success is not acceptable evidence for an approved remote operation.
var ErrConPTYEmptyOutput = errors.New("ptyexec: conpty command produced empty output")
