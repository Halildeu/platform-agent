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
	// activeSessionOutputDrainGrace bounds the post-exit stdout/stderr pipe drain for the Session-0 service path.
	// The child receives only stdinRead + outputWrite via PROC_THREAD_ATTRIBUTE_HANDLE_LIST, so normal EOF should
	// be immediate after a short diagnostic exits. This is a final backstop against a child/descendant that keeps
	// the output handle open despite process termination/cancellation.
	activeSessionOutputDrainGrace = 2 * time.Second
)

// RunConPTY spawns exePath (commandLine = CommandLineToArgvW-compatible, NO shell), captures the merged output
// (bounded by maxConPTYOutput), waits for the process to exit, and returns the output + exit code.
//
// When called from the non-interactive services session (Session 0), it uses the same active-session token
// boundary as the VIEW_ONLY dataplane launcher but redirects stdout/stderr instead of opening a shell. This is
// the production service-mode path: the service keeps the broker-signed permit / allowlist / arg-policy gates,
// and the read-only diagnostic command runs in the logged-on user's interactive session without exposing inbound
// ports or an unrestricted shell. In a normal interactive process it keeps using ConPTY in the caller's session.
//
// The direct ConPTY path is lifecycle-safe + leak-free per the ConPTY footgun list:
//   - the output pipe is DRAINED concurrently while the child runs, so a child writing a full pipe never
//     deadlocks (which would hang the wait);
//   - the pseudo-console is closed only AFTER the child exits (its lifetime spans the child), which then
//     EOFs the reader;
//   - every handle / attribute list is released in reverse order, including on every error path;
//   - ctx cancellation terminates the child (best-effort) so a cancelled session tears the command down.
func RunConPTY(ctx context.Context, exePath, commandLine string, cols, rows int16) (output []byte, exitCode uint32, err error) {
	session, e := currentProcessSessionID()
	if e != nil {
		return nil, 0, fmt.Errorf("ptyexec: current process session: %w", e)
	}
	if session == 0 {
		return runActiveSessionCapturedCapped(ctx, exePath, commandLine, maxConPTYOutput)
	}
	return runConPTYCapped(ctx, exePath, commandLine, cols, rows, maxConPTYOutput)
}

var (
	currentProcessSessionID = func() (uint32, error) {
		var session uint32
		if err := windows.ProcessIdToSessionId(windows.GetCurrentProcessId(), &session); err != nil {
			return 0, err
		}
		return session, nil
	}
	runActiveSessionCapturedCapped = runCapturedInActiveSessionCapped
)

type activeSessionReadResult struct {
	data []byte
	err  error
}

func closeHandle(h *windows.Handle) {
	if h == nil || *h == 0 || *h == windows.InvalidHandle {
		return
	}
	_ = windows.CloseHandle(*h)
	*h = 0
}

func runCapturedInActiveSessionCapped(ctx context.Context, exePath, commandLine string, maxOutput int) (output []byte, exitCode uint32, err error) {
	if exePath == "" {
		return nil, 0, errors.New("ptyexec: empty exePath")
	}
	if commandLine == "" {
		return nil, 0, errors.New("ptyexec: empty command line")
	}
	session := windows.WTSGetActiveConsoleSessionId()
	if session == 0xFFFFFFFF || session == 0 {
		return nil, 0, errors.New("ptyexec: no active interactive Windows session")
	}

	var userTok windows.Token
	if e := windows.WTSQueryUserToken(session, &userTok); e != nil {
		return nil, 0, fmt.Errorf("ptyexec: WTSQueryUserToken: %w", e)
	}
	defer userTok.Close()

	var primaryTok windows.Token
	if e := windows.DuplicateTokenEx(userTok, windows.TOKEN_DUPLICATE|windows.TOKEN_ASSIGN_PRIMARY|
		windows.TOKEN_QUERY|windows.TOKEN_ADJUST_DEFAULT|windows.TOKEN_ADJUST_SESSIONID, nil,
		windows.SecurityImpersonation, windows.TokenPrimary, &primaryTok); e != nil {
		return nil, 0, fmt.Errorf("ptyexec: DuplicateTokenEx: %w", e)
	}
	defer primaryTok.Close()

	var envBlock *uint16
	if e := windows.CreateEnvironmentBlock(&envBlock, primaryTok, false); e != nil {
		return nil, 0, fmt.Errorf("ptyexec: CreateEnvironmentBlock: %w", e)
	}
	defer windows.DestroyEnvironmentBlock(envBlock)

	inheritSA := &windows.SecurityAttributes{
		Length:        uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		InheritHandle: 1,
	}
	var stdinRead, stdinWrite, outputRead, outputWrite windows.Handle
	if e := windows.CreatePipe(&stdinRead, &stdinWrite, inheritSA, 0); e != nil {
		return nil, 0, fmt.Errorf("ptyexec: active-session stdin pipe: %w", e)
	}
	defer closeHandle(&stdinRead)
	defer closeHandle(&stdinWrite)
	if e := windows.SetHandleInformation(stdinWrite, windows.HANDLE_FLAG_INHERIT, 0); e != nil {
		return nil, 0, fmt.Errorf("ptyexec: active-session stdin parent handle: %w", e)
	}
	if e := windows.CreatePipe(&outputRead, &outputWrite, inheritSA, 0); e != nil {
		return nil, 0, fmt.Errorf("ptyexec: active-session output pipe: %w", e)
	}
	defer closeHandle(&outputRead)
	defer closeHandle(&outputWrite)
	if e := windows.SetHandleInformation(outputRead, windows.HANDLE_FLAG_INHERIT, 0); e != nil {
		return nil, 0, fmt.Errorf("ptyexec: active-session output parent handle: %w", e)
	}

	appPtr, e := windows.UTF16PtrFromString(exePath)
	if e != nil {
		return nil, 0, fmt.Errorf("ptyexec: active-session exe path: %w", e)
	}
	cmdPtr, e := windows.UTF16PtrFromString(commandLine)
	if e != nil {
		return nil, 0, fmt.Errorf("ptyexec: active-session command line: %w", e)
	}
	deskPtr, e := windows.UTF16PtrFromString(`winsta0\default`)
	if e != nil {
		return nil, 0, fmt.Errorf("ptyexec: active-session desktop: %w", e)
	}

	al, e := windows.NewProcThreadAttributeList(1)
	if e != nil {
		return nil, 0, fmt.Errorf("ptyexec: active-session attr list: %w", e)
	}
	defer al.Delete()
	inheritHandles := []windows.Handle{stdinRead, outputWrite}
	if e := al.Update(windows.PROC_THREAD_ATTRIBUTE_HANDLE_LIST, unsafe.Pointer(&inheritHandles[0]),
		uintptr(len(inheritHandles))*unsafe.Sizeof(inheritHandles[0])); e != nil {
		return nil, 0, fmt.Errorf("ptyexec: active-session handle allowlist: %w", e)
	}

	var siEx windows.StartupInfoEx
	siEx.Cb = uint32(unsafe.Sizeof(siEx))
	siEx.Desktop = deskPtr
	siEx.Flags = windows.STARTF_USESTDHANDLES
	siEx.StdInput = stdinRead
	siEx.StdOutput = outputWrite
	siEx.StdErr = outputWrite
	siEx.ProcThreadAttributeList = al.List()
	var pi windows.ProcessInformation
	if e := windows.CreateProcessAsUser(primaryTok, appPtr, cmdPtr, nil, nil, true,
		windows.CREATE_UNICODE_ENVIRONMENT|windows.CREATE_NO_WINDOW|windows.EXTENDED_STARTUPINFO_PRESENT,
		envBlock, nil, &siEx.StartupInfo, &pi); e != nil {
		return nil, 0, fmt.Errorf("ptyexec: active-session CreateProcessAsUser: %w", e)
	}
	defer windows.CloseHandle(pi.Thread)
	defer windows.CloseHandle(pi.Process)
	closeHandle(&stdinRead)
	closeHandle(&stdinWrite)
	closeHandle(&outputWrite)

	var actual uint32
	if e := windows.ProcessIdToSessionId(pi.ProcessId, &actual); e != nil {
		_ = windows.TerminateProcess(pi.Process, 1)
		return nil, 0, fmt.Errorf("ptyexec: active-session verify process session: %w", e)
	}
	if actual != session {
		_ = windows.TerminateProcess(pi.Process, 1)
		return nil, 0, fmt.Errorf("ptyexec: active-session helper landed in session %d, expected %d", actual, session)
	}

	readCh := make(chan activeSessionReadResult, 1)
	go func() {
		data, rerr := readAllCapped(outputRead, maxOutput)
		readCh <- activeSessionReadResult{data, rerr}
	}()
	childExited := make(chan struct{})
	go func() { _, _ = windows.WaitForSingleObject(pi.Process, windows.INFINITE); close(childExited) }()

	var res activeSessionReadResult
	select {
	case <-childExited:
		res = waitActiveSessionOutput(&outputRead, readCh)
	case res = <-readCh:
		_ = windows.TerminateProcess(pi.Process, 1)
		<-childExited
	case <-ctx.Done():
		_ = windows.TerminateProcess(pi.Process, 1)
		<-childExited
		res = waitActiveSessionOutput(&outputRead, readCh)
	}

	var code uint32
	if e := windows.GetExitCodeProcess(pi.Process, &code); e != nil {
		return res.data, 0, fmt.Errorf("ptyexec: active-session GetExitCodeProcess: %w", e)
	}
	return res.data, code, res.err
}

func waitActiveSessionOutput(outputRead *windows.Handle, readCh <-chan activeSessionReadResult) activeSessionReadResult {
	select {
	case res := <-readCh:
		return res
	case <-time.After(activeSessionOutputDrainGrace):
		if outputRead != nil && *outputRead != 0 && *outputRead != windows.InvalidHandle {
			_ = windows.CancelIoEx(*outputRead, nil)
			closeHandle(outputRead)
		}
		select {
		case res := <-readCh:
			return res
		default:
			return activeSessionReadResult{err: errors.New("ptyexec: active-session output drain timed out")}
		}
	}
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
			// A zero-byte successful ReadFile is not EOF for the nonzero-sized pipe reads we issue here.
			// EOF is signalled as ERROR_BROKEN_PIPE/ERROR_HANDLE_EOF once the writer closes. Treating this
			// as EOF lets a fast diagnostic be recorded as a successful empty DATA stream and can terminate
			// the child before conhost/stdout relays the first bytes.
			time.Sleep(time.Millisecond)
			continue
		}
	}
}
