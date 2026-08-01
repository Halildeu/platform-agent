//go:build windows

package dataplane

import (
	"errors"
	"testing"
	"unsafe"
)

func TestWTSInfoExLayoutAndLockState(t *testing.T) {
	if got := unsafe.Offsetof(wtsInfoExW{}.Data); got != 8 {
		t.Fatalf("WTSINFOEX data offset=%d, want 8 on windows/amd64", got)
	}
	if got := unsafe.Offsetof(wtsInfoExLevel1W{}.SessionFlags); got != 8 {
		t.Fatalf("WTSINFOEX_LEVEL1 SessionFlags offset=%d, want 8", got)
	}

	for _, tc := range []struct {
		name    string
		level   uint32
		session uint32
		flags   int32
		locked  bool
		wantErr bool
	}{
		{name: "locked", level: 1, session: 7, flags: wtsSessionStateLock, locked: true},
		{name: "unlocked", level: 1, session: 7, flags: wtsSessionStateOpen},
		{name: "unknown", level: 1, session: 7, flags: -1, wantErr: true},
		{name: "wrong-level", level: 2, session: 7, flags: wtsSessionStateLock, wantErr: true},
		{name: "wrong-session", level: 1, session: 8, flags: wtsSessionStateLock, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			info := &wtsInfoExW{Level: tc.level}
			info.Data.SessionID = tc.session
			info.Data.SessionFlags = tc.flags
			locked, err := decodeWTSSessionLocked(info, 7)
			if tc.wantErr {
				if !errors.Is(err, ErrSessionDesktopStateUnknown) {
					t.Fatalf("err=%v, want ErrSessionDesktopStateUnknown", err)
				}
				return
			}
			if err != nil || locked != tc.locked {
				t.Fatalf("locked=%t err=%v, want locked=%t", locked, err, tc.locked)
			}
		})
	}
}
