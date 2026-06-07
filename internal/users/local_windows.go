//go:build windows

package users

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	netUserEnumLevel      = 1
	filterNormalAccount   = 0x0002
	maxPreferredLength    = 0xffffffff
	ufAccountDisable      = 0x0002
	ufLockout             = 0x0010
	ufPasswordNotRequired = 0x0020
)

type userInfo1 struct {
	Name        *uint16
	Password    *uint16
	PasswordAge uint32
	Priv        uint32
	HomeDir     *uint16
	Comment     *uint16
	Flags       uint32
	ScriptPath  *uint16
}

type userInfo1003 struct {
	Password *uint16
}

type userInfo1008 struct {
	Flags uint32
}

var procNetUserSetInfo = windows.NewLazySystemDLL("netapi32.dll").NewProc("NetUserSetInfo")

func ListLocal() ([]LocalUserSnapshot, error) {
	var users []LocalUserSnapshot
	var resumeHandle uint32

	for {
		var buffer *byte
		var entriesRead uint32
		var totalEntries uint32
		err := windows.NetUserEnum(
			nil,
			netUserEnumLevel,
			filterNormalAccount,
			&buffer,
			maxPreferredLength,
			&entriesRead,
			&totalEntries,
			&resumeHandle,
		)
		if buffer != nil {
			defer windows.NetApiBufferFree(buffer)
		}
		if err != nil && !errors.Is(err, syscall.ERROR_MORE_DATA) {
			return nil, fmt.Errorf("NetUserEnum failed: %w", err)
		}
		if entriesRead > 0 && buffer != nil {
			entries := unsafe.Slice((*userInfo1)(unsafe.Pointer(buffer)), entriesRead)
			for _, entry := range entries {
				users = append(users, localUserFromNetAPI(entry))
			}
		}
		if !errors.Is(err, syscall.ERROR_MORE_DATA) {
			break
		}
	}

	sort.Slice(users, func(i, j int) bool {
		return users[i].Username < users[j].Username
	})
	return users, nil
}

func localUserFromNetAPI(info userInfo1) LocalUserSnapshot {
	return LocalUserSnapshot{
		Username:         windows.UTF16PtrToString(info.Name),
		FullName:         "",
		Comment:          windows.UTF16PtrToString(info.Comment),
		Disabled:         info.Flags&ufAccountDisable != 0,
		LockedOut:        info.Flags&ufLockout != 0,
		PasswordRequired: info.Flags&ufPasswordNotRequired == 0,
	}
}

func MutateLocal(req LocalUserMutationRequest) (LocalUserMutationResult, error) {
	username, err := normalizeLocalUsername(req.Username)
	if err != nil {
		return LocalUserMutationResult{}, err
	}

	// Identity resolution (#84): resolve the account SID ONCE, proving it is a
	// local SAM user (local-scope proof, residual #3) and yielding the RID. The
	// same identity feeds the RID guard and the lockout guard so they cannot
	// diverge. Fail closed if the SID cannot be resolved or is not a local user.
	identity, err := resolveLocalUserIdentity(username)
	if err != nil {
		return LocalUserMutationResult{}, fmt.Errorf("resolve local account for %q: %w", username, err)
	}
	// RID guard: refuse reserved well-known RIDs ({500..504}) for every action,
	// before any SAM write — catches a *renamed* or localized built-in (e.g. a
	// renamed Administrator) that the name denylist in GuardReservedUsername cannot.
	if err := GuardProtectedRID(identity.rid); err != nil {
		return LocalUserMutationResult{}, err
	}

	switch req.Action {
	case ActionLockUserLogin:
		// Lockout guard (#84 part 2): refuse to disable the last enabled local
		// administrator, which would strand the endpoint with no admin access.
		// Fail closed on any gathering error. The proven-local SID is threaded
		// through so the guard reasons over the same identity.
		if err := checkLockoutGuard(username, identity.sid); err != nil {
			return LocalUserMutationResult{}, err
		}
		return setLocalUserDisabled(username, true)
	case ActionUnlockUserLogin:
		return setLocalUserDisabled(username, false)
	case ActionChangeLocalPassword:
		if req.NewPassword == "" {
			return LocalUserMutationResult{}, errors.New("new password is required")
		}
		return setLocalUserPassword(username, req.NewPassword)
	default:
		return LocalUserMutationResult{}, fmt.Errorf("unsupported local user action %q", req.Action)
	}
}

// localUserRID resolves username to a proven-local SAM account SID and returns
// its relative identifier (the last sub-authority). The RID guard uses it to
// refuse reserved built-in identifiers ({500..504}) even when the account has
// been renamed. Routing through localAccountSID also enforces the local-scope
// proof (#84 residual #3): a bare name that resolves to a domain principal, or a
// non-user SID, is refused before any RID is read.
func localUserRID(username string) (uint32, error) {
	id, err := resolveLocalUserIdentity(username)
	if err != nil {
		return 0, err
	}
	return id.rid, nil
}

func normalizeLocalUsername(raw string) (string, error) {
	username := strings.TrimSpace(raw)
	if username == "" {
		return "", errors.New("username is required")
	}
	if len(username) > 128 {
		return "", errors.New("username exceeds 128 characters")
	}
	for _, r := range username {
		if r < 0x20 || strings.ContainsRune(`"\/[]:;|=,+*?<>@`, r) {
			return "", fmt.Errorf("username %q is not a local SAM account name", username)
		}
	}
	return username, nil
}

func setLocalUserDisabled(username string, disabled bool) (LocalUserMutationResult, error) {
	flags, err := getLocalUserFlags(username)
	if err != nil {
		return LocalUserMutationResult{}, err
	}
	if disabled {
		flags |= ufAccountDisable
	} else {
		flags &^= ufAccountDisable
		flags &^= ufLockout
	}
	info := userInfo1008{Flags: flags}
	if err := netUserSetInfo(username, 1008, unsafe.Pointer(&info)); err != nil {
		return LocalUserMutationResult{}, fmt.Errorf("NetUserSetInfo flags failed for %q: %w", username, err)
	}
	lockedOut := flags&ufLockout != 0
	return LocalUserMutationResult{
		Username:  username,
		Action:    string(mapDisabledAction(disabled)),
		Disabled:  &disabled,
		LockedOut: &lockedOut,
	}, nil
}

func setLocalUserPassword(username, password string) (LocalUserMutationResult, error) {
	if len(password) < 8 {
		return LocalUserMutationResult{}, errors.New("new password must be at least 8 characters")
	}
	if len(password) > 256 {
		return LocalUserMutationResult{}, errors.New("new password exceeds 256 characters")
	}
	passwordPtr, err := windows.UTF16PtrFromString(password)
	if err != nil {
		return LocalUserMutationResult{}, fmt.Errorf("encode new password: %w", err)
	}
	info := userInfo1003{Password: passwordPtr}
	if err := netUserSetInfo(username, 1003, unsafe.Pointer(&info)); err != nil {
		return LocalUserMutationResult{}, fmt.Errorf("NetUserSetInfo password failed for %q: %w", username, err)
	}
	return LocalUserMutationResult{
		Username:        username,
		Action:          string(ActionChangeLocalPassword),
		PasswordChanged: true,
	}, nil
}

func getLocalUserFlags(username string) (uint32, error) {
	usernamePtr, err := windows.UTF16PtrFromString(username)
	if err != nil {
		return 0, fmt.Errorf("encode username: %w", err)
	}
	var buffer *byte
	if err := windows.NetUserGetInfo(nil, usernamePtr, netUserEnumLevel, &buffer); err != nil {
		return 0, fmt.Errorf("NetUserGetInfo failed for %q: %w", username, err)
	}
	if buffer == nil {
		return 0, fmt.Errorf("NetUserGetInfo returned empty buffer for %q", username)
	}
	defer windows.NetApiBufferFree(buffer)
	info := (*userInfo1)(unsafe.Pointer(buffer))
	return info.Flags, nil
}

func netUserSetInfo(username string, level uint32, buf unsafe.Pointer) error {
	usernamePtr, err := windows.UTF16PtrFromString(username)
	if err != nil {
		return fmt.Errorf("encode username: %w", err)
	}
	var parmErr uint32
	r0, _, _ := syscall.SyscallN(
		procNetUserSetInfo.Addr(),
		0,
		uintptr(unsafe.Pointer(usernamePtr)),
		uintptr(level),
		uintptr(buf),
		uintptr(unsafe.Pointer(&parmErr)),
	)
	if r0 != 0 {
		if parmErr != 0 {
			return fmt.Errorf("net error %d (parmErr=%d)", r0, parmErr)
		}
		return syscall.Errno(r0)
	}
	return nil
}

func mapDisabledAction(disabled bool) LocalUserMutationAction {
	if disabled {
		return ActionLockUserLogin
	}
	return ActionUnlockUserLogin
}
