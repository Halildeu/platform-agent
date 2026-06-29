//go:build windows

package dataplane

import (
	"context"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Win32 surface for the endpoint-awareness banner. Reuses the package's
// NewLazySystemDLL/NewProc idiom (capture_windows.go). The banner is a borderless,
// topmost, non-activating popup pinned to the top of the PRIMARY monitor showing a
// red bar with white bilingual text; it never steals focus and is closed by
// cancelling the context.
// Reuses the package's existing user32/gdi32 lazy DLL handles + procGetSystemMetrics
// and procDeleteObject (declared in capture_windows.go); only banner-specific procs
// are added here.
var (
	procRegisterClassExW   = user32.NewProc("RegisterClassExW")
	procUnregisterClassW   = user32.NewProc("UnregisterClassW")
	procCreateWindowExW    = user32.NewProc("CreateWindowExW")
	procDefWindowProcW     = user32.NewProc("DefWindowProcW")
	procDestroyWindow      = user32.NewProc("DestroyWindow")
	procShowWindow         = user32.NewProc("ShowWindow")
	procUpdateWindow       = user32.NewProc("UpdateWindow")
	procIsWindowVisible    = user32.NewProc("IsWindowVisible")
	procFindWindowW        = user32.NewProc("FindWindowW")
	procGetMessageW        = user32.NewProc("GetMessageW")
	procTranslateMessage   = user32.NewProc("TranslateMessage")
	procDispatchMessageW   = user32.NewProc("DispatchMessageW")
	procPostMessageW       = user32.NewProc("PostMessageW")
	procPostQuitMessage    = user32.NewProc("PostQuitMessage")
	procLoadCursorW        = user32.NewProc("LoadCursorW")
	procSetProcessDPIAware = user32.NewProc("SetProcessDPIAware")
	procGetDpiForSystem    = user32.NewProc("GetDpiForSystem")
	procSendMessageW       = user32.NewProc("SendMessageW")

	procCreateSolidBrush = gdi32.NewProc("CreateSolidBrush")
	procSetTextColor     = gdi32.NewProc("SetTextColor")
	procSetBkColor       = gdi32.NewProc("SetBkColor")
	procCreateFontW      = gdi32.NewProc("CreateFontW")

	bKernel32            = windows.NewLazySystemDLL("kernel32.dll")
	procGetModuleHandleW = bKernel32.NewProc("GetModuleHandleW")
)

const (
	wsPopup     = 0x80000000
	wsVisible   = 0x10000000
	wsChild     = 0x40000000
	wsExTopmost = 0x00000008
	wsExToolWin = 0x00000080
	wsExNoActiv = 0x08000000

	swShowNA   = 8
	ssCenter   = 0x00000001
	ssCenterIm = 0x00000200 // SS_CENTERIMAGE (vertical center, single line)

	wmDestroy        = 0x0002
	wmClose          = 0x0010
	wmCtlColorStatic = 0x0138
	wmSetFont        = 0x0030
	idcArrow         = 32512
	smCXScreen       = 0
	smCYScreen       = 1
	fwBold           = 700
	defaultCharset   = 1
)

// systemDPI returns the system DPI, falling back to 96 (100%) if the API is
// unavailable (pre-Win10) or fails.
func systemDPI() int {
	if procGetDpiForSystem.Find() != nil {
		return dpiDefault
	}
	r, _, _ := procGetDpiForSystem.Call()
	if r == 0 {
		return dpiDefault
	}
	return int(r)
}

// wndClassExW mirrors the Win32 WNDCLASSEXW layout.
type wndClassExW struct {
	cbSize        uint32
	style         uint32
	lpfnWndProc   uintptr
	cbClsExtra    int32
	cbWndExtra    int32
	hInstance     windows.Handle
	hIcon         windows.Handle
	hCursor       windows.Handle
	hbrBackground windows.Handle
	lpszMenuName  *uint16
	lpszClassName *uint16
	hIconSm       windows.Handle
}

// msgW mirrors the Win32 MSG layout.
type msgW struct {
	hwnd    windows.Handle
	message uint32
	wParam  uintptr
	lParam  uintptr
	time    uint32
	ptX     int32
	ptY     int32
}

// BannerSelfVerify confirms the endpoint-awareness banner window exists AND is
// visible in THIS (interactive) session — FindWindowW by class + IsWindowVisible.
// The VIEW_ONLY capture helper calls it after starting ShowActiveBanner, BEFORE
// streaming any frame: no verified banner ⇒ no endpoint awareness ⇒ fail-closed
// (do not capture). It is an AWARENESS assertion, not tamper-proofing (a user can
// still kill the process; enforcement is the session gate + local-abort).
func BannerSelfVerify() error {
	classPtr, err := windows.UTF16PtrFromString(bannerClassName)
	if err != nil {
		return ErrBannerShow
	}
	hwnd, _, _ := procFindWindowW.Call(uintptr(unsafe.Pointer(classPtr)), 0)
	if hwnd == 0 {
		return ErrBannerShow
	}
	if vis, _, _ := procIsWindowVisible.Call(hwnd); vis == 0 {
		return ErrBannerShow
	}
	return nil
}

// ShowActiveBanner displays the endpoint-awareness banner and BLOCKS on the Win32
// message pump until ctx is cancelled (then it tears the window down and returns
// nil) or a fatal Win32 error occurs (returns a distinct sentinel: the caller
// MUST treat any non-nil error as fail-closed — no banner ⇒ no endpoint awareness
// ⇒ do not start the VIEW_ONLY session, mirroring the recording_ready gate).
//
// Single PRIMARY-monitor scope (MVP); a user solely on a secondary monitor may
// not see it (multi-monitor coverage is a follow-up).
func ShowActiveBanner(ctx context.Context) (retErr error) {
	// Win32 message loops MUST stay on a single OS thread for the window's life.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// Derive a cancelable ctx so the watcher goroutine unblocks on EVERY return
	// path (normal teardown, fatal Win32 error, or early failure) — no leak.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Best-effort DPI awareness so GetSystemMetrics reports physical px and the
	// bar height scales correctly on hi-DPI.
	_, _, _ = procSetProcessDPIAware.Call()
	dpi := systemDPI()
	h := scaleForDPI(bannerBaseHeight, dpi)

	scrW, _, _ := procGetSystemMetrics.Call(uintptr(int32(smCXScreen)))
	scrH, _, _ := procGetSystemMetrics.Call(uintptr(int32(smCYScreen)))
	x, y, w := bannerBounds(int(scrW), int(scrH), h)

	instR, _, _ := procGetModuleHandleW.Call(0) // NULL → current process module (never fails)
	inst := windows.Handle(instR)

	// Red background brush (also returned for the static child's WM_CTLCOLORSTATIC).
	redBrushR, _, _ := procCreateSolidBrush.Call(rgb(200, 0, 0))
	if redBrushR == 0 {
		return ErrBannerCreate
	}
	redBrush := windows.Handle(redBrushR)
	defer procDeleteObject.Call(uintptr(redBrush))

	classNamePtr, _ := windows.UTF16PtrFromString(bannerClassName)
	titlePtr, _ := windows.UTF16PtrFromString(BannerTitle)
	textPtr, _ := windows.UTF16PtrFromString(BannerText)
	staticClassPtr, _ := windows.UTF16PtrFromString("STATIC")
	cursor, _, _ := procLoadCursorW.Call(0, uintptr(idcArrow))

	// WndProc: paint-free (a STATIC child carries the text); we colour that child
	// (white-on-red) and handle teardown cleanly.
	wndProc := windows.NewCallback(func(hwnd windows.Handle, msg uint32, wparam, lparam uintptr) uintptr {
		switch msg {
		case wmCtlColorStatic:
			procSetTextColor.Call(wparam, rgb(255, 255, 255)) // white text
			procSetBkColor.Call(wparam, rgb(200, 0, 0))       // red background
			return uintptr(redBrush)
		case wmClose:
			procDestroyWindow.Call(uintptr(hwnd))
			return 0
		case wmDestroy:
			procPostQuitMessage.Call(0)
			return 0
		}
		r, _, _ := procDefWindowProcW.Call(uintptr(hwnd), uintptr(msg), wparam, lparam)
		return r
	})

	wc := wndClassExW{
		style:         0,
		lpfnWndProc:   wndProc,
		hInstance:     inst,
		hCursor:       windows.Handle(cursor),
		hbrBackground: redBrush,
		lpszClassName: classNamePtr,
	}
	wc.cbSize = uint32(unsafe.Sizeof(wc))
	atom, _, _ := procRegisterClassExW.Call(uintptr(unsafe.Pointer(&wc)))
	if atom == 0 {
		return ErrBannerClassRegister
	}
	defer procUnregisterClassW.Call(uintptr(unsafe.Pointer(classNamePtr)), uintptr(inst))

	exStyle := uintptr(wsExTopmost | wsExToolWin | wsExNoActiv)
	style := uintptr(wsPopup | wsVisible)
	hwndR, _, _ := procCreateWindowExW.Call(
		exStyle,
		uintptr(unsafe.Pointer(classNamePtr)),
		uintptr(unsafe.Pointer(titlePtr)),
		style,
		uintptr(int32(x)), uintptr(int32(y)), uintptr(int32(w)), uintptr(int32(h)),
		0, 0, uintptr(inst), 0,
	)
	if hwndR == 0 {
		return ErrBannerCreate
	}
	hwnd := windows.Handle(hwndR)
	defer procDestroyWindow.Call(uintptr(hwnd))

	// STATIC child fills the popup, single-line centered both ways.
	childStyle := uintptr(wsChild | wsVisible | ssCenter | ssCenterIm)
	childR, _, _ := procCreateWindowExW.Call(
		0,
		uintptr(unsafe.Pointer(staticClassPtr)),
		uintptr(unsafe.Pointer(textPtr)),
		childStyle,
		0, 0, uintptr(int32(w)), uintptr(int32(h)),
		uintptr(hwnd), 0, uintptr(inst), 0,
	)
	if childR == 0 {
		return ErrBannerCreate
	}
	child := windows.Handle(childR)

	// Bold legible font scaled to ~45% of the bar height.
	fontH := -(h * 45 / 100)
	facePtr, _ := windows.UTF16PtrFromString("Segoe UI")
	fontR, _, _ := procCreateFontW.Call(
		uintptr(int32(fontH)), 0, 0, 0, uintptr(fwBold),
		0, 0, 0, uintptr(defaultCharset), 0, 0, 0, 0,
		uintptr(unsafe.Pointer(facePtr)),
	)
	if fontR != 0 {
		font := windows.Handle(fontR)
		defer procDeleteObject.Call(uintptr(font))
		procSendMessageW.Call(uintptr(child), wmSetFont, fontR, 1)
	}

	// Show WITHOUT activating (no focus theft), then confirm it is actually visible.
	procShowWindow.Call(uintptr(hwnd), uintptr(swShowNA))
	procUpdateWindow.Call(uintptr(hwnd))
	if vis, _, _ := procIsWindowVisible.Call(uintptr(hwnd)); vis == 0 {
		return ErrBannerShow
	}

	// Watcher: ctx cancel → post WM_CLOSE so the pump exits cleanly.
	go func() {
		<-ctx.Done()
		procPostMessageW.Call(uintptr(hwnd), wmClose, 0, 0)
	}()

	// Message pump (GetMessageW returns 0 on WM_QUIT, -1 on error).
	var msg msgW
	for {
		r, _, _ := procGetMessageW.Call(uintptr(unsafe.Pointer(&msg)), 0, 0, 0)
		switch int32(r) {
		case 0: // WM_QUIT
			return nil
		case -1: // error
			return ErrBannerShow
		default:
			procTranslateMessage.Call(uintptr(unsafe.Pointer(&msg)))
			procDispatchMessageW.Call(uintptr(unsafe.Pointer(&msg)))
		}
	}
}
