//go:build windows

// Production Windows VIEW_ONLY capture: the LocalSystem service cannot capture the
// interactive user desktop from Session 0, so it LAUNCHES this same binary as a
// short-lived helper IN the active session (over a DACL-restricted, nonce-verified
// named pipe — the proven dataplane launcher/pipe/frame-IPC, also used by the
// CONSTRAINED_PTY active-session path). The helper shows the endpoint-awareness
// banner (fail-closed), then streams active-indicator-stamped PRIMARY-monitor PNG
// frames back over the pipe until the service closes it. The service side wraps the
// pipe as a dataplane.FrameProducer the screenview.Dispatcher's Pump drains.
package screenview

import (
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"platform-agent/internal/remotebridge/dataplane"
)

const (
	helperPipeFlag  = "--rb-screenview-pipe="
	helperNonceFlag = "--rb-screenview-nonce="

	acceptTimeout      = 15 * time.Second       // bound the launch->dial handshake (Accept is ctx+timeout bounded)
	firstFrameDeadline = 12 * time.Second       // the helper must banner-verify + capture a first frame within this
	writeTimeout       = 10 * time.Second       // per-frame pipe write bound
	bannerSettle       = 700 * time.Millisecond // let the banner window create + show before self-verify
	captureInterval    = 100 * time.Millisecond // ~10 fps VIEW_ONLY pilot cadence (drop-tolerant gate downstream)
	captureMaxErr      = 3                      // consecutive capture failures trip the producer fail-closed
	indicatorBand      = 28                     // px: the in-frame "remote active" red band height (awareness)
)

// MaybeRunActiveSessionScreenViewHelper turns endpoint-agent into a short-lived
// VIEW_ONLY screen-capture helper when launched with the helper flags (the service
// passes a pipe name + launch nonce on argv). It returns (handled, exitCode);
// (false, 0) when the process was NOT invoked as the helper (normal startup).
// main() must call this before starting the service.
func MaybeRunActiveSessionScreenViewHelper(args []string) (bool, int) {
	var pipeName, nonceHex string
	for _, a := range args {
		switch {
		case strings.HasPrefix(a, helperPipeFlag):
			pipeName = strings.TrimPrefix(a, helperPipeFlag)
		case strings.HasPrefix(a, helperNonceFlag):
			nonceHex = strings.TrimPrefix(a, helperNonceFlag)
		}
	}
	if pipeName == "" && nonceHex == "" {
		return false, 0 // not a helper invocation
	}
	if pipeName == "" || nonceHex == "" {
		return true, 2 // partial flags = malformed launch
	}
	if err := runActiveSessionScreenViewHelper(pipeName, nonceHex); err != nil {
		return true, 1
	}
	return true, 0
}

// runActiveSessionScreenViewHelper runs in the ACTIVE user session: dial+handshake,
// show+self-verify the banner (fail-closed), then stream indicator-stamped
// primary-monitor frames until the service closes the pipe, then a graceful EOF.
func runActiveSessionScreenViewHelper(pipeName, nonceHex string) error {
	nonce, err := hex.DecodeString(nonceHex)
	if err != nil {
		return err
	}
	dialCtx, cancelDial := context.WithTimeout(context.Background(), acceptTimeout)
	defer cancelDial()
	conn, err := dataplane.DialAndHandshake(dialCtx, pipeName, nonce)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()

	// Endpoint awareness FIRST, fail-closed: show the "remote active" banner in the
	// active desktop and SELF-VERIFY it is present + visible before ANY frame
	// egresses. ShowActiveBanner blocks on the Win32 message pump, so it runs in a
	// goroutine; a creation failure returns early (caught), and a created-but-not-
	// visible banner is caught by BannerSelfVerify. No verified banner => no frame.
	bannerCtx, cancelBanner := context.WithCancel(context.Background())
	defer cancelBanner()
	bannerErr := make(chan error, 1)
	go func() { bannerErr <- dataplane.ShowActiveBanner(bannerCtx) }()
	select {
	case err := <-bannerErr: // returned before it could settle => window creation failed
		if err == nil {
			err = fmt.Errorf("banner exited before showing")
		}
		return fmt.Errorf("screenview helper: endpoint banner failed (fail-closed): %w", err)
	case <-time.After(bannerSettle):
	}
	if err := dataplane.BannerSelfVerify(); err != nil {
		return fmt.Errorf("screenview helper: endpoint banner not visible (fail-closed): %w", err)
	}

	// MANDATORY in-frame active-indicator on EVERY frame (red awareness band) +
	// PRIMARY-monitor capture so the captured region matches the primary-monitor
	// banner (no un-bannered secondary monitor is ever captured).
	indicator := func(fr *dataplane.RawFrame) {
		dataplane.ApplyActiveIndicator(fr, indicatorBand, 0, 0, 0xFF, 0xFF) // BGRA red
	}
	producer := dataplane.NewWindowsPrimaryScreenFrameProducer(dataplane.NewPNGEncoder(), captureInterval, captureMaxErr, indicator)
	defer producer.Close()

	// Banner LIVENESS (fail-closed): the banner is verified once above, but it could be
	// torn down mid-session (WM_CLOSE/WM_DESTROY => ShowActiveBanner returns). We have
	// NOT cancelled it yet (cancelBanner is deferred to exit), so ANY value on bannerErr
	// means the banner went down unexpectedly. Check it BEFORE producing a frame AND
	// again AFTER Next() returns (which may block one interval + capture) but BEFORE the
	// frame egresses — so a banner that closes during capture never lets that frame ship
	// ("no banner => no frame", modulo a sub-100ms TOCTOU intrinsic to async UI).
	checkBannerAlive := func() error {
		select {
		case berr := <-bannerErr:
			if berr == nil {
				berr = fmt.Errorf("banner closed mid-session")
			}
			return fmt.Errorf("screenview helper: endpoint banner went down (fail-closed): %w", berr)
		default:
			return nil
		}
	}
	for {
		if err := checkBannerAlive(); err != nil {
			return err
		}
		f, ok := producer.Next()
		if !ok {
			break // capture tripped fail-closed (consecutive errors) => end the stream
		}
		if err := checkBannerAlive(); err != nil {
			return err // banner went down during capture — do NOT egress this frame
		}
		_ = conn.SetWriteDeadline(time.Now().Add(writeTimeout))
		if err := dataplane.WriteFrame(conn, f.Payload); err != nil {
			// the service closed the pipe (session KILL / transport teardown) — a clean
			// stop, not a helper failure. The deferred banner cancel + producer close fire.
			return nil
		}
	}
	return dataplane.WriteEOF(conn)
}

// ipcFrameProducer is the service-side dataplane.FrameProducer that reads encoded
// frames from the helper over the verified pipe. The factory prefetches the first
// frame (liveness proof), so Next replays it first, then reads the rest. Close is
// idempotent and ALWAYS terminates the helper (no orphan capture survives).
type ipcFrameProducer struct {
	conn      net.Conn
	helper    *dataplane.LaunchedHelper
	listener  net.Listener
	first     []byte
	firstUsed bool
	closeOnce sync.Once
}

func (p *ipcFrameProducer) Next() (dataplane.Frame, bool) {
	if !p.firstUsed && p.first != nil {
		p.firstUsed = true
		payload := p.first
		p.first = nil
		return dataplane.Frame{Payload: payload}, true
	}
	payload, err := dataplane.ReadFrame(p.conn)
	if err != nil {
		return dataplane.Frame{}, false // EOF (helper done) or read error => exhausted
	}
	return dataplane.Frame{Payload: payload}, true
}

func (p *ipcFrameProducer) Close() error {
	p.closeOnce.Do(func() {
		if p.conn != nil {
			_ = p.conn.Close() // unblock a pending ReadFrame
		}
		if p.helper != nil {
			_ = p.helper.Terminate() // no orphan capture process survives the stream
		}
		if p.listener != nil {
			_ = p.listener.Close()
		}
	})
	return nil
}

// readFirstFrame reads the helper's first frame bounded by BOTH the deadline AND
// ctx. On ctx cancellation it closes the conn (unblocking the in-flight ReadFrame)
// and drains the read goroutine, returning ctx.Err() — so a session KILL that lands
// after accept but BEFORE the first frame aborts immediately and the factory's
// deferred cleanup terminates the helper (no orphan capture survives the deadline).
func readFirstFrame(ctx context.Context, conn net.Conn, deadline time.Duration) ([]byte, error) {
	_ = conn.SetReadDeadline(time.Now().Add(deadline))
	type result struct {
		payload []byte
		err     error
	}
	ch := make(chan result, 1)
	go func() {
		payload, err := dataplane.ReadFrame(conn)
		ch <- result{payload, err}
	}()
	select {
	case r := <-ch:
		_ = conn.SetReadDeadline(time.Time{})
		return r.payload, r.err
	case <-ctx.Done():
		_ = conn.Close() // unblock the in-flight ReadFrame
		<-ch             // drain (buffered, never blocks)
		return nil, ctx.Err()
	}
}

// NewWindowsProducerFactory builds the production VIEW_ONLY capture factory. Each
// call launches a fresh active-session helper and returns a FrameProducer fed by
// its frame stream. Fail-closed everywhere: no interactive session, a launch
// failure, a handshake failure, or a helper that never produces a first frame
// (banner/capture failed) all return an error and leave NO orphan helper.
func NewWindowsProducerFactory() ProducerFactory {
	return func(ctx context.Context, _ string) (dataplane.FrameProducer, error) {
		self, err := os.Executable()
		if err != nil {
			return nil, fmt.Errorf("screenview: resolve helper executable: %w", err)
		}
		sid, err := dataplane.ActiveSessionUserSID()
		if err != nil {
			return nil, fmt.Errorf("screenview: active session: %w", err) // no interactive session => fail-closed
		}
		name, err := dataplane.RandomPipeName()
		if err != nil {
			return nil, err
		}
		listener, err := dataplane.ListenSecurePipe(name, sid)
		if err != nil {
			return nil, err
		}
		listenerHandedOff := false
		defer func() {
			if !listenerHandedOff {
				_ = listener.Close()
			}
		}()
		nonce, err := dataplane.NewLaunchNonce()
		if err != nil {
			return nil, err
		}
		helper, err := dataplane.LaunchInActiveSession(self,
			helperPipeFlag+name, helperNonceFlag+hex.EncodeToString(nonce))
		if err != nil {
			return nil, fmt.Errorf("screenview: launch helper in active session: %w", err)
		}
		helperHandedOff := false
		defer func() {
			if !helperHandedOff {
				_ = helper.Terminate() // orphan-on-launch guard: terminate if we don't hand off
			}
		}()

		// Accept the helper's connection bounded by ctx (a KILL before the helper dials
		// aborts immediately) AND the timeout (a helper that never dials does not hang).
		conn, err := dataplane.AcceptAndVerifyContext(ctx, listener, nonce, acceptTimeout)
		if err != nil {
			return nil, fmt.Errorf("screenview: accept helper: %w", err)
		}
		connHandedOff := false
		defer func() {
			if !connHandedOff {
				_ = conn.Close()
			}
		}()

		// ANTI-SPOOF: the connected client MUST be the helper we launched. A same-session
		// process that read the launch nonce off the helper's argv and pre-empted the
		// connection has a DIFFERENT PID -> reject fail-closed. This is the unspoofable
		// check (the pipe name is already random + the nonce single-use); it closes the
		// nonce-in-argv spoof so VIEW_ONLY frames can only originate from our own helper.
		clientPID, perr := dataplane.PipeClientProcessID(conn)
		if perr != nil || clientPID != helper.Pid {
			return nil, fmt.Errorf("screenview: pipe client PID %d != launched helper PID %d (anti-spoof, fail-closed): %v", clientPID, helper.Pid, perr)
		}

		// Factory-level fail-closed (READY proof), ctx-aware: the helper emits its FIRST
		// frame ONLY after the banner self-verified and a capture succeeded, so reading a
		// first frame here proves the session is live + bannered. Bounded by BOTH
		// firstFrameDeadline AND ctx — a KILL after accept but before the first frame aborts
		// immediately (not after the deadline). A failure surfaces as this error (NOT a
		// later clean EndStream that would look like a normal end).
		firstPayload, err := readFirstFrame(ctx, conn, firstFrameDeadline)
		if err != nil {
			return nil, fmt.Errorf("screenview: helper produced no first frame (banner/capture failed or cancelled, fail-closed): %w", err)
		}

		// Success: hand conn + helper + listener to the producer (cancel the cleanup defers).
		listenerHandedOff, helperHandedOff, connHandedOff = true, true, true
		return &ipcFrameProducer{conn: conn, helper: helper, listener: listener, first: firstPayload}, nil
	}
}
