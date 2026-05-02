//go:build windows

package users

import (
	"errors"
	"fmt"
	"sort"
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
