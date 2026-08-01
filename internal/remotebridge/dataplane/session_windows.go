//go:build windows

package dataplane

import (
	"errors"
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	wtsSessionInfoEx     = 25
	wtsSessionStateLock  = 0
	wtsSessionStateOpen  = 1
	wtsSessionStateUnset = ^uint32(0)
)

var (
	wtsapi32Session                 = windows.NewLazySystemDLL("wtsapi32.dll")
	procWTSQuerySessionInformationW = wtsapi32Session.NewProc("WTSQuerySessionInformationW")

	// ErrSessionDesktopStateUnknown prevents a capture helper from choosing a
	// desktop when Windows cannot prove whether the target session is locked.
	ErrSessionDesktopStateUnknown = errors.New("dataplane: interactive session desktop state is unknown")
)

// wtsInfoExLevel1W is the level-1 payload returned for WTSSessionInfoEx. Keep
// the complete fixed layout so the SessionFlags field is read at the same ABI
// offsets as wtsapi32.h on Windows amd64.
type wtsInfoExLevel1W struct {
	SessionID               uint32
	SessionState            int32
	SessionFlags            int32
	WinStationName          [33]uint16
	UserName                [21]uint16
	DomainName              [18]uint16
	LogonTime               int64
	ConnectTime             int64
	DisconnectTime          int64
	LastInputTime           int64
	CurrentTime             int64
	IncomingBytes           uint32
	OutgoingBytes           uint32
	IncomingFrames          uint32
	OutgoingFrames          uint32
	IncomingCompressedBytes uint32
	OutgoingCompressedBytes uint32
}

type wtsInfoExW struct {
	Level uint32
	_     uint32 // WTSINFOEX_LEVEL_W is 8-byte aligned on Windows amd64.
	Data  wtsInfoExLevel1W
}

// activeInteractiveSessionState resolves one active, logged-on session and its
// lock state from the same session ID. Unknown/unsupported flags fail closed;
// callers must never guess a desktop from process names or stale UI state.
func activeInteractiveSessionState() (uint32, bool, error) {
	session, ok := activeInteractiveSessionId()
	if !ok {
		return 0, false, ErrNoInteractiveSession
	}
	locked, err := sessionLocked(session)
	if err != nil {
		return 0, false, err
	}
	return session, locked, nil
}

// sessionLocked returns the Windows lock state for a specific interactive
// session via WTSSessionInfoEx. The supported endpoint baseline is Windows 10+
// (the Windows 7/Server 2008 R2 reversed-flag defect is outside that baseline).
func sessionLocked(session uint32) (bool, error) {
	var buffer uintptr
	var bytes uint32
	r1, _, callErr := procWTSQuerySessionInformationW.Call(
		0,
		uintptr(session),
		wtsSessionInfoEx,
		uintptr(unsafe.Pointer(&buffer)),
		uintptr(unsafe.Pointer(&bytes)),
	)
	if r1 == 0 {
		return false, fmt.Errorf("%w: WTSQuerySessionInformationW: %v", ErrSessionDesktopStateUnknown, callErr)
	}
	if buffer == 0 {
		return false, fmt.Errorf("%w: empty WTSSessionInfoEx buffer", ErrSessionDesktopStateUnknown)
	}
	defer windows.WTSFreeMemory(buffer)
	if bytes < uint32(unsafe.Sizeof(wtsInfoExW{})) {
		return false, fmt.Errorf("%w: short WTSSessionInfoEx buffer: %d", ErrSessionDesktopStateUnknown, bytes)
	}
	info := (*wtsInfoExW)(unsafe.Pointer(buffer))
	return decodeWTSSessionLocked(info, session)
}

func decodeWTSSessionLocked(info *wtsInfoExW, session uint32) (bool, error) {
	if info == nil {
		return false, fmt.Errorf("%w: nil WTSSessionInfoEx", ErrSessionDesktopStateUnknown)
	}
	if info.Level != 1 || info.Data.SessionID != session {
		return false, fmt.Errorf("%w: unexpected WTSSessionInfoEx level/session", ErrSessionDesktopStateUnknown)
	}
	switch uint32(info.Data.SessionFlags) {
	case wtsSessionStateLock:
		return true, nil
	case wtsSessionStateOpen:
		return false, nil
	case wtsSessionStateUnset:
		return false, ErrSessionDesktopStateUnknown
	default:
		return false, fmt.Errorf("%w: unexpected SessionFlags=%d", ErrSessionDesktopStateUnknown, info.Data.SessionFlags)
	}
}

// VerifySessionDesktopState ensures a helper remains on the desktop whose
// warning is visible. Lock/unlock transitions terminate capture fail-closed
// instead of continuing on a now-hidden desktop.
func VerifySessionDesktopState(session uint32, wantLocked bool) error {
	locked, err := sessionLocked(session)
	if err != nil {
		return err
	}
	if locked != wantLocked {
		return fmt.Errorf("dataplane: session desktop changed (locked=%t want=%t)", locked, wantLocked)
	}
	return nil
}

// activeInteractiveSessionId returns the session id of the ACTIVE interactive
// user session, preferring a WTSActive session that has a logged-on user token.
//
// WTSGetActiveConsoleSessionId() alone is wrong for remote (RDP) admin sessions:
// when a user connects over RDP the physical CONSOLE session is disconnected and
// empty, so the console id it returns has no logged-on user. WTSQueryUserToken on
// that empty console id then fails (or yields a session with no rendered desktop),
// the capture helper launches into a blank desktop, and every VIEW_ONLY frame is
// black -> screen-view-failed. Enumerating for the WTSActive session that has a
// valid user token targets the session the operator is actually on (verified on
// SRB-AIDENETIMPC 2026-07-12: RDP `rdp-tcp#0 ... 1 Active`, console `12 Conn`
// empty; a physical-console session is likewise reported WTSActive so the
// physical path is unchanged). Falls back to WTSGetActiveConsoleSessionId when
// enumeration yields no active user session (preserves prior behavior; never a
// regression for the physical-console case).
func activeInteractiveSessionId() (uint32, bool) {
	var infosPtr *windows.WTS_SESSION_INFO
	var count uint32
	// handle 0 == WTS_CURRENT_SERVER_HANDLE; version must be 1.
	if err := windows.WTSEnumerateSessions(0, 0, 1, &infosPtr, &count); err == nil && count > 0 {
		defer windows.WTSFreeMemory(uintptr(unsafe.Pointer(infosPtr)))
		infos := unsafe.Slice(infosPtr, count)
		for i := range infos {
			if infos[i].State != windows.WTSActive {
				continue
			}
			var tok windows.Token
			if e := windows.WTSQueryUserToken(infos[i].SessionID, &tok); e == nil {
				_ = tok.Close()
				return infos[i].SessionID, true
			}
		}
	}
	// Fallback: physical console session (prior behavior, e.g. someone at the box).
	s := windows.WTSGetActiveConsoleSessionId()
	if s == 0xFFFFFFFF || s == 0 {
		return 0, false
	}
	return s, true
}
