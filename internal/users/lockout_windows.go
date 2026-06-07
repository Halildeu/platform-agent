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
	// Safety bounds for the recursive Administrators-membership expansion.
	maxAdminExpansionDepth  = 16
	maxAdminExpansionGroups = 256
	// maxPreferredLength (0xffffffff, "let the API size the buffer") is already
	// declared in local_windows.go and reused here.
)

// localGroupMembersInfo0 mirrors LOCALGROUP_MEMBERS_INFO_0 (level 0): a single
// SID pointer.
type localGroupMembersInfo0 struct {
	SID *windows.SID
}

// enumerateLocalGroupMembers returns deep-copied SIDs of the DIRECT members of a
// local group. Level 0 is used (just the SID) and each member is classified by a
// separate LookupAccount, which avoids the larger LOCALGROUP_MEMBERS_INFO_1 ABI
// surface in favour of reviewability. The enumeration is complete-or-error: the
// pagination loop refuses to treat a partial set as authoritative (a missing
// member would otherwise be read as "not an admin"), and any non-terminal status
// returns an error.
func enumerateLocalGroupMembers(groupName string) ([]*windows.SID, error) {
	namePtr, err := windows.UTF16PtrFromString(groupName)
	if err != nil {
		return nil, fmt.Errorf("encode group name %q: %w", groupName, err)
	}

	var out []*windows.SID
	var resume uintptr
	for page := 0; page < lockoutMaxPages; page++ {
		var buf unsafe.Pointer
		var entriesRead, totalEntries uint32
		ret, _, _ := procNetLocalGroupGetMembers.Call(
			0, // servername = NULL (local)
			uintptr(unsafe.Pointer(namePtr)),
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

		var copyErr error
		if usable {
			entries := unsafe.Slice((*localGroupMembersInfo0)(buf), entriesRead)
			for i := range entries {
				if entries[i].SID == nil {
					continue
				}
				// Deep-copy WHILE the buffer is still valid so no raw pointer
				// outlives the netapi buffer (SID-pointer-lifetime class of bug).
				c, e := entries[i].SID.Copy()
				if e != nil {
					copyErr = fmt.Errorf("copy member SID of %q: %w", groupName, e)
					break
				}
				out = append(out, c)
			}
		}
		if buf != nil {
			_ = windows.NetApiBufferFree((*byte)(buf))
		}
		if copyErr != nil {
			return nil, copyErr
		}

		switch status {
		case 0:
			return out, nil
		case netErrMoreData, netErrBufTooSmall:
			if !usable {
				return nil, fmt.Errorf("NetLocalGroupGetMembers(%q) returned no usable page (status %d)", groupName, uint32(status))
			}
			continue
		default:
			return nil, fmt.Errorf("NetLocalGroupGetMembers(%q) failed: %w", groupName, status)
		}
	}
	return nil, fmt.Errorf("NetLocalGroupGetMembers(%q) exceeded the %d-page safety bound; refusing to use a partial membership set", groupName, lockoutMaxPages)
}

// isLocalGroupSID reports whether sid is a LOCAL group/alias that can be
// recursively expanded: a built-in alias (S-1-5-32-*) or a machine-local group
// (directly under the machine account-domain SID). Domain groups are not.
func isLocalGroupSID(sid, machineSid *windows.SID) bool {
	if strings.HasPrefix(sid.String(), "S-1-5-32-") {
		return true
	}
	return localUnderMachineDomain(sid, machineSid)
}

// adminLocalUserSIDStrings returns the set of LOCAL-USER SID strings that are
// effective members of the built-in Administrators alias — flattening nested
// LOCAL groups (a user that is an admin only via a nested local group, which
// NetUserGetLocalGroups(LG_INCLUDE_INDIRECT) does NOT surface on a workgroup
// host — proven by live test; Codex 019ea1a2 A+). This is the single
// authoritative source for both the target check and the other-admins count, so
// they cannot diverge.
//
// Classification per member (via LookupAccount):
//   - local user (SidTypeUser under the machine domain) -> add to the set;
//   - domain user -> skipped (the guard counts LOCAL admins);
//   - local group / built-in alias -> recursed (cycle-guarded);
//   - domain / non-local group -> skipped;
//   - an unresolvable member SID (orphaned/deleted account) -> skipped (it cannot
//     be an enabled effective admin).
//
// Fail-closed: enumeration errors, copy failures, or hitting a safety bound
// return an error so the caller refuses the command rather than acting on a
// partial admin set.
func adminLocalUserSIDStrings() (map[string]struct{}, error) {
	machineSid, err := resolveMachineDomainSid()
	if err != nil {
		return nil, err
	}
	adminsSid, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return nil, fmt.Errorf("derive Administrators well-known SID: %w", err)
	}
	adminsName, err := administratorsAliasName()
	if err != nil {
		return nil, err
	}

	userSet := make(map[string]struct{})
	visited := map[string]struct{}{adminsSid.String(): {}}
	groupsExpanded := 0

	var expand func(groupName string, depth int) error
	expand = func(groupName string, depth int) error {
		if depth > maxAdminExpansionDepth {
			return fmt.Errorf("Administrators expansion exceeded depth %d", maxAdminExpansionDepth)
		}
		groupsExpanded++
		if groupsExpanded > maxAdminExpansionGroups {
			return fmt.Errorf("Administrators expansion exceeded %d groups", maxAdminExpansionGroups)
		}

		members, err := enumerateLocalGroupMembers(groupName)
		if err != nil {
			return err
		}
		for _, m := range members {
			ms := m.String()
			name, _, use, lookupErr := m.LookupAccount("")
			if lookupErr != nil {
				// Orphaned / unresolvable member SID = a deleted account; it
				// cannot be an enabled effective admin, so skipping is safe.
				continue
			}
			switch use {
			case windows.SidTypeUser:
				if localUnderMachineDomain(m, machineSid) {
					userSet[ms] = struct{}{}
				}
			case windows.SidTypeAlias, windows.SidTypeGroup, windows.SidTypeWellKnownGroup:
				if isLocalGroupSID(m, machineSid) {
					if _, seen := visited[ms]; seen {
						continue
					}
					visited[ms] = struct{}{}
					if err := expand(name, depth+1); err != nil {
						return err
					}
				}
			default:
				// Computer accounts, label SIDs, etc. are not local admin users.
			}
		}
		return nil
	}

	if err := expand(adminsName, 0); err != nil {
		return nil, err
	}
	return userSet, nil
}

// administratorsMemberSIDStrings returns the DIRECT member SID strings of the
// built-in Administrators alias. It is no longer the authoritative lockout signal
// (adminLocalUserSIDStrings flattens nested local groups); it is retained as an
// independent cross-check for the live integration test.
func administratorsMemberSIDStrings() (map[string]struct{}, error) {
	adminsName, err := administratorsAliasName()
	if err != nil {
		return nil, err
	}
	members, err := enumerateLocalGroupMembers(adminsName)
	if err != nil {
		return nil, err
	}
	set := make(map[string]struct{}, len(members))
	for _, m := range members {
		set[m.String()] = struct{}{}
	}
	return set, nil
}

// gatherLockoutFacts collects the local-SAM state the lockout decision needs.
// The set of effective local administrators is computed ONCE
// (adminLocalUserSIDStrings, which flattens nested local groups) and used for
// both the target check and the other-admins count, so they share one truth.
//
// Two OPPOSITE safety directions are enforced:
//   - target admin status: a gathering error is fail-closed (returned), because a
//     false "not an admin" would let the guard wave a last-admin lock through;
//   - OtherEnabledLocalAdmins: a per-user local-SID resolution failure is skipped
//     (undercount), because undercounting other admins can only make the guard
//     MORE likely to refuse, never less.
func gatherLockoutFacts(targetUsername string, targetSID *windows.SID) (LockoutFacts, error) {
	flags, err := getLocalUserFlags(targetUsername)
	if err != nil {
		return LockoutFacts{}, fmt.Errorf("read target flags: %w", err)
	}
	targetEnabled := flags&ufAccountDisable == 0

	adminUsers, err := adminLocalUserSIDStrings()
	if err != nil {
		return LockoutFacts{}, err
	}

	_, targetIsAdmin := adminUsers[targetSID.String()]

	localUsers, err := ListLocal()
	if err != nil {
		return LockoutFacts{}, fmt.Errorf("list local users: %w", err)
	}
	otherEnabled := 0
	for _, u := range localUsers {
		if strings.EqualFold(u.Username, targetUsername) || u.Disabled {
			continue
		}
		sid, e := localAccountSID(u.Username)
		if e != nil {
			continue // conservative undercount on resolve/proof failure
		}
		if _, ok := adminUsers[sid.String()]; ok {
			otherEnabled++
		}
	}

	return LockoutFacts{
		TargetIsLocalAdmin:      targetIsAdmin,
		TargetEnabled:           targetEnabled,
		OtherEnabledLocalAdmins: otherEnabled,
	}, nil
}

// checkLockoutGuard refuses a LOCK_USER_LOGIN that would disable the last enabled
// local administrator. Fail-closed on any gathering error. The target's
// local-scope + RID are already proven by resolveLocalUserIdentity in
// MutateLocal; the proven SID is threaded through here so no bare LookupSID is
// repeated.
func checkLockoutGuard(username string, targetSID *windows.SID) error {
	facts, err := gatherLockoutFacts(username, targetSID)
	if err != nil {
		return err
	}
	return evaluateLockoutGuard(ActionLockUserLogin, facts)
}
