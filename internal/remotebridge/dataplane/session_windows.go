//go:build windows

package dataplane

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

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
