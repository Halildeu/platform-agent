//go:build windows

package users

import (
	"fmt"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// netapi32 binding for the last-administrator lockout guard. NetLocalGroupGetMembers
// is not exposed by x/sys/windows, so it is bound directly; the buffer is freed
// via the x/sys wrapper windows.NetApiBufferFree.
var procNetLocalGroupGetMembers = windows.NewLazySystemDLL("netapi32.dll").NewProc("NetLocalGroupGetMembers")

const (
	netErrMoreData    syscall.Errno = 234  // ERROR_MORE_DATA
	netErrBufTooSmall syscall.Errno = 2123 // NERR_BufTooSmall
	lockoutMaxPages   int           = 16
	// maxPreferredLength (0xffffffff, "let the API size the buffer") is already
	// declared in local_windows.go and reused here.
)

// localGroupMembersInfo0 mirrors LOCALGROUP_MEMBERS_INFO_0 (level 0): a single
// SID pointer.
type localGroupMembersInfo0 struct {
	SID *windows.SID
}

// administratorsMemberSIDStrings enumerates the built-in Administrators alias
// membership and returns the members' SIDs as SDDL strings. The string form is
// captured WHILE the netapi buffer is still valid (before NetApiBufferFree), so
// no raw SID pointer ever outlives its buffer — this deliberately sidesteps the
// SID-pointer-lifetime class of bug.
func administratorsMemberSIDStrings() (map[string]struct{}, error) {
	aliasSid, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return nil, fmt.Errorf("derive Administrators well-known SID: %w", err)
	}
	aliasName, _, _, err := aliasSid.LookupAccount("")
	if err != nil {
		return nil, fmt.Errorf("resolve Administrators alias name: %w", err)
	}
	aliasNamePtr, err := windows.UTF16PtrFromString(aliasName)
	if err != nil {
		return nil, fmt.Errorf("encode Administrators alias name: %w", err)
	}

	set := make(map[string]struct{})
	var resume uintptr
	for page := 0; page < lockoutMaxPages; page++ {
		var buf unsafe.Pointer
		var entriesRead, totalEntries uint32
		ret, _, _ := procNetLocalGroupGetMembers.Call(
			0, // servername = NULL (local)
			uintptr(unsafe.Pointer(aliasNamePtr)),
			0, // level 0
			uintptr(unsafe.Pointer(&buf)),
			maxPreferredLength,
			uintptr(unsafe.Pointer(&entriesRead)),
			uintptr(unsafe.Pointer(&totalEntries)),
			uintptr(unsafe.Pointer(&resume)),
		)
		status := syscall.Errno(ret)
		usable := (status == 0 || status == netErrMoreData || status == netErrBufTooSmall) &&
			buf != nil && entriesRead > 0

		if usable {
			entries := unsafe.Slice((*localGroupMembersInfo0)(buf), entriesRead)
			for i := range entries {
				if entries[i].SID != nil {
					// Capture as string while the SID pointer is still valid.
					set[entries[i].SID.String()] = struct{}{}
				}
			}
		}
		if buf != nil {
			_ = windows.NetApiBufferFree((*byte)(buf))
			buf = nil
		}

		switch status {
		case 0:
			return set, nil
		case netErrMoreData, netErrBufTooSmall:
			if !usable {
				return nil, fmt.Errorf("NetLocalGroupGetMembers returned no usable page (status %d)", uint32(status))
			}
			continue
		default:
			return nil, fmt.Errorf("NetLocalGroupGetMembers failed: %w", status)
		}
	}
	return set, nil
}

// gatherLockoutFacts collects the local-SAM state the lockout decision needs.
// Fail-closed: any error resolving the target or enumerating membership is
// returned so the caller refuses the command. The OtherEnabledLocalAdmins count
// skips local users whose SID cannot be resolved — undercounting is conservative
// (it can only make the guard MORE likely to refuse, never less).
func gatherLockoutFacts(targetUsername string, targetSID *windows.SID) (LockoutFacts, error) {
	flags, err := getLocalUserFlags(targetUsername)
	if err != nil {
		return LockoutFacts{}, fmt.Errorf("read target flags: %w", err)
	}
	targetEnabled := flags&ufAccountDisable == 0

	members, err := administratorsMemberSIDStrings()
	if err != nil {
		return LockoutFacts{}, err
	}

	_, targetIsAdmin := members[targetSID.String()]

	localUsers, err := ListLocal()
	if err != nil {
		return LockoutFacts{}, fmt.Errorf("list local users: %w", err)
	}
	otherEnabled := 0
	for _, u := range localUsers {
		if strings.EqualFold(u.Username, targetUsername) || u.Disabled {
			continue
		}
		sid, _, _, e := windows.LookupSID("", u.Username)
		if e != nil {
			continue // conservative undercount on resolve failure
		}
		if _, ok := members[sid.String()]; ok {
			otherEnabled++
		}
	}

	return LockoutFacts{
		TargetIsLocalAdmin:      targetIsAdmin,
		TargetEnabled:           targetEnabled,
		OtherEnabledLocalAdmins: otherEnabled,
	}, nil
}

// checkLockoutGuard refuses a LOCK_USER_LOGIN that would disable the last
// enabled local administrator. Fail-closed on any gathering error.
func checkLockoutGuard(username string) error {
	sid, _, _, err := windows.LookupSID("", username)
	if err != nil {
		return fmt.Errorf("resolve SID for lockout guard: %w", err)
	}
	facts, err := gatherLockoutFacts(username, sid)
	if err != nil {
		return err
	}
	return evaluateLockoutGuard(ActionLockUserLogin, facts)
}
