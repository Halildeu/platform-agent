//go:build windows

package ptyexec

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	defaultCols     = 120
	defaultRows     = 30
	conptyReadChunk = 16 * 1024
	// maxConPTYOutput caps captured output fail-closed against a runaway/abusive command.
	maxConPTYOutput = 8 * 1024 * 1024
	// conhostRelayGrace bounds how long we let conhost relay a command's FINAL output to the pipe after the
	// child exits, before closing the pseudo-console. The bulk of output is drained live by the concurrent
	// reader during execution; this only covers the post-exit flush tail. Without it, a fast command's last
	// line can be dropped (conhost hasn't relayed it yet when ClosePseudoConsole tears conhost down).
	conhostRelayGrace = 400 * time.Millisecond
)

// ErrConPTYOutputCap is returned when a command's output exceeds maxConPTYOutput (output is truncated to the
// cap and the child is torn down) — fail-closed against runaway output.
var ErrConPTYOutputCap = errors.New("ptyexec: conpty output exceeded cap")

// RunConPTY spawns exePath (commandLine = CommandLineToArgvW-compatible, NO shell) inside a Windows
// pseudo-console, captures the merged PTY output (bounded by maxConPTYOutput), waits for the process to
// exit, and returns the output + exit code. It runs in the CALLER's session (the session-1
// CreateProcessAsUser variant is slice-3c). Lifecycle-safe + leak-free per the ConPTY footgun list:
//   - the output pipe is DRAINED concurrently while the child runs, so a child writing a full pipe never
//     deadlocks (which would hang the wait);
//   - the pseudo-console is closed only AFTER the child exits (its lifetime spans the child), which then
//     EOFs the reader;
//   - every handle / attribute list is released in reverse order, including on every error path;
//   - ctx cancellation terminates the child (best-effort) so a cancelled session tears the command down.
func RunConPTY(ctx context.Context, exePath, commandLine string, cols, rows int16) (output []byte, exitCode uint32, err error) {
	return runConPTYCapped(ctx, exePath, commandLine, cols, rows, maxConPTYOutput)
}

// runConPTYCapped is RunConPTY with an injectable output cap (tests pass a tiny cap to exercise the
// fail-fast cap path without a multi-MiB command).
func runConPTYCapped(ctx context.Context, exePath, commandLine string, cols, rows int16, maxOutput int) (output []byte, exitCode uint32, err error) {
	if exePath == "" {
		return nil, 0, errors.New("ptyexec: empty exePath")
	}
	if cols <= 0 {
		cols = defaultCols
	}
	if rows <= 0 {
		rows = defaultRows
	}

	// Input pipe: the console reads inputRead; we hold inputWrite but send no input (closed on return).
	var inputRead, inputWrite windows.Handle
	if e := windows.CreatePipe(&inputRead, &inputWrite, nil, 0); e != nil {
		return nil, 0, fmt.Errorf("ptyexec: input pipe: %w", e)
	}
	defer windows.CloseHandle(inputWrite)
	// Output pipe: the console writes outputWrite; we read outputRead.
	var outputRead, outputWrite windows.Handle
	if e := windows.CreatePipe(&outputRead, &outputWrite, nil, 0); e != nil {
		windows.CloseHandle(inputRead)
		return nil, 0, fmt.Errorf("ptyexec: output pipe: %w", e)
	}
	defer windows.CloseHandle(outputRead)

	// Create the pseudo-console over (inputRead, outputWrite).
	var hpc windows.Handle
	if e := windows.CreatePseudoConsole(windows.Coord{X: cols, Y: rows}, inputRead, outputWrite, 0, &hpc); e != nil {
		windows.CloseHandle(inputRead)
		windows.CloseHandle(outputWrite)
		return nil, 0, fmt.Errorf("ptyexec: CreatePseudoConsole: %w", e)
	}
	// The console now owns its refs to inputRead/outputWrite — close OUR copies so outputRead reaches EOF
	// once the console closes (otherwise the reader never EOFs).
	windows.CloseHandle(inputRead)
	windows.CloseHandle(outputWrite)
	// hpc must outlive the child; closed LAST (idempotent).
	var hpcOnce sync.Once
	closeHPC := func() { hpcOnce.Do(func() { windows.ClosePseudoConsole(hpc) }) }
	defer closeHPC()

	// Attribute list carrying the pseudo-console.
	al, e := windows.NewProcThreadAttributeList(1)
	if e != nil {
		return nil, 0, fmt.Errorf("ptyexec: attr list: %w", e)
	}
	defer al.Delete()
	if e := al.Update(windows.PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE, handleAsValue(hpc), unsafe.Sizeof(hpc)); e != nil {
		return nil, 0, fmt.Errorf("ptyexec: attr update: %w", e)
	}

	exe16, e := windows.UTF16PtrFromString(exePath)
	if e != nil {
		return nil, 0, fmt.Errorf("ptyexec: exe path: %w", e)
	}
	cmd16, e := windows.UTF16PtrFromString(commandLine)
	if e != nil {
		return nil, 0, fmt.Errorf("ptyexec: command line: %w", e)
	}

	var siEx windows.StartupInfoEx
	siEx.Cb = uint32(unsafe.Sizeof(siEx))
	siEx.ProcThreadAttributeList = al.List()
	var pi windows.ProcessInformation
	// inheritHandles=FALSE: the pseudo-console attribute (not handle inheritance) wires the child's console.
	if e := windows.CreateProcess(exe16, cmd16, nil, nil, false,
		windows.EXTENDED_STARTUPINFO_PRESENT, nil, nil, &siEx.StartupInfo, &pi); e != nil {
		return nil, 0, fmt.Errorf("ptyexec: CreateProcess: %w", e)
	}
	defer windows.CloseHandle(pi.Thread)
	defer windows.CloseHandle(pi.Process)

	// Drain output CONCURRENTLY while the child runs (a full, undrained pipe would block the child and
	// deadlock the wait). Reap via a select so the wait can NEVER block indefinitely: the reader finishing
	// first (output cap / read error) or ctx cancellation both fail-fast by terminating the child.
	type readResult struct {
		data []byte
		err  error
	}
	readCh := make(chan readResult, 1)
	go func() { data, rerr := readAllCapped(outputRead, maxOutput); readCh <- readResult{data, rerr} }()
	childExited := make(chan struct{})
	go func() { _, _ = windows.WaitForSingleObject(pi.Process, windows.INFINITE); close(childExited) }()

	var res readResult
	select {
	case <-childExited:
		// Normal exit: give conhost a bounded grace to relay the FINAL output to the (still-draining)
		// reader, then close the console so the reader EOFs, then collect.
		time.Sleep(conhostRelayGrace)
		closeHPC()
		res = <-readCh
	case res = <-readCh:
		// The reader stopped FIRST — the output cap was hit or a read error occurred, so the pipe is no
		// longer drained and a still-writing child would block forever. Fail-fast: terminate + close, reap.
		_ = windows.TerminateProcess(pi.Process, 1)
		closeHPC()
		<-childExited
	case <-ctx.Done():
		// Cancelled (e.g. session teardown): terminate the child, close the console, then drain + reap.
		_ = windows.TerminateProcess(pi.Process, 1)
		closeHPC()
		<-childExited
		res = <-readCh
	}

	var code uint32
	if e := windows.GetExitCodeProcess(pi.Process, &code); e != nil {
		return res.data, 0, fmt.Errorf("ptyexec: GetExitCodeProcess: %w", e)
	}
	return res.data, code, res.err
}

// handleAsValue reinterprets a Handle's bit pattern AS an unsafe.Pointer, without a uintptr→Pointer
// conversion (which go vet's unsafeptr flags). For PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE the attribute value
// IS the HPCON passed BY VALUE in the lpValue slot (per the Windows ConPTY sample) — so we pass the handle's
// bits as the pointer, NOT its address. Handle and unsafe.Pointer are both pointer-sized.
func handleAsValue(h windows.Handle) unsafe.Pointer {
	return *(*unsafe.Pointer)(unsafe.Pointer(&h))
}

// readAllCapped reads handle h until EOF (a broken/closed pipe), capping at max bytes (truncate + return
// ErrConPTYOutputCap). A broken-pipe / handle-EOF error is a clean end-of-stream, not a failure.
func readAllCapped(h windows.Handle, max int) ([]byte, error) {
	out := make([]byte, 0, conptyReadChunk)
	chunk := make([]byte, conptyReadChunk)
	for {
		var n uint32
		rerr := windows.ReadFile(h, chunk, &n, nil)
		if n > 0 {
			if len(out)+int(n) > max {
				out = append(out, chunk[:max-len(out)]...)
				return out, ErrConPTYOutputCap
			}
			out = append(out, chunk[:n]...)
		}
		if rerr != nil {
			if errors.Is(rerr, windows.ERROR_BROKEN_PIPE) || errors.Is(rerr, windows.ERROR_HANDLE_EOF) {
				return out, nil // clean EOF
			}
			return out, rerr
		}
		if n == 0 {
			return out, nil
		}
	}
}
