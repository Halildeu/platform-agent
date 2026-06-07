//go:build windows

package users

import (
	"errors"
	"fmt"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Windows identity helpers for the local-user mutation guards (#84 residual #3,
// local-scope proof). NetUserModalsGet is not exposed by x/sys/windows, so it is
// bound directly; its buffer is freed via the x/sys wrapper NetApiBufferFree.
// The machine account-domain SID resolution mirrors the proven scope proof in
// internal/inventory/local_admin_group_windows.go (Codex 019e74d7 MF-1/MF-5);
// it is re-implemented here to keep the guard package self-contained.
var (
	guardNetapi32        = windows.NewLazySystemDLL("netapi32.dll")
	procNetUserModalsGet = guardNetapi32.NewProc("NetUserModalsGet")
)

// userModalsInfo2 mirrors USER_MODALS_INFO_2: the account-domain name + SID.
// Only DomainID is read; DomainName is left untouched and freed with the buffer.
type userModalsInfo2 struct {
	DomainName *uint16
	DomainID   *windows.SID
}

// localUserIdentity is a single, proven-local SAM identity: its SID (and SDDL
// string form) plus RID. Resolved once per command so the RID guard and the
// lockout guard reason over the SAME identity instead of repeating bare lookups.
type localUserIdentity struct {
	sid       *windows.SID
	sidString string
	rid       uint32
}

// resolveMachineDomainSid returns the local SAM / account-domain SID via
// NetUserModalsGet level 2. On a workgroup host this is the machine's own SAM
// domain SID; every local account SID is this SID plus one RID. Fail-closed.
func resolveMachineDomainSid() (*windows.SID, error) {
	var buf unsafe.Pointer
	ret, _, _ := procNetUserModalsGet.Call(
		0, // servername = NULL (local)
		2, // level 2
		uintptr(unsafe.Pointer(&buf)),
	)
	if status := syscall.Errno(ret); status != 0 || buf == nil {
		return nil, fmt.Errorf("NetUserModalsGet level 2 failed: status %d", ret)
	}
	defer windows.NetApiBufferFree((*byte)(buf))

	info := (*userModalsInfo2)(buf)
	if info.DomainID == nil {
		return nil, errors.New("NetUserModalsGet returned a null account-domain SID")
	}
	// Deep-copy into caller-owned memory before the API buffer is freed.
	sid, err := info.DomainID.Copy()
	if err != nil {
		return nil, fmt.Errorf("copy machine account-domain SID: %w", err)
	}
	return sid, nil
}

// localUnderMachineDomain reports whether sid is the machine account-domain SID
// plus exactly one extra sub-authority (the RID) and shares its full prefix —
// i.e. sid names a LOCAL SAM principal, not a domain one. Uses the canonical
// SDDL string form so the comparison cannot be fooled by sub-authority aliasing.
func localUnderMachineDomain(sid, machineSid *windows.SID) bool {
	if sid == nil || machineSid == nil {
		return false
	}
	if int(sid.SubAuthorityCount()) != int(machineSid.SubAuthorityCount())+1 {
		return false
	}
	return strings.HasPrefix(sid.String(), machineSid.String()+"-")
}

// localAccountSID resolves username to its SID and PROVES it is a local SAM user
// account (#84 residual #3): SID_NAME_USE must be SidTypeUser AND the SID must
// sit directly under the machine account-domain SID. A bare username on a
// domain-joined host can otherwise resolve to a domain principal, which would
// make the RID and lockout guards reason over the wrong identity while the
// mutation itself targets the local SAM. Fail-closed on any failure.
func localAccountSID(username string) (*windows.SID, error) {
	sid, _, use, err := windows.LookupSID("", username)
	if err != nil {
		return nil, fmt.Errorf("LookupSID failed for %q: %w", username, err)
	}
	if use != windows.SidTypeUser {
		return nil, fmt.Errorf("account %q is not a user principal (SID_NAME_USE=%d)", username, use)
	}
	machineSid, err := resolveMachineDomainSid()
	if err != nil {
		return nil, fmt.Errorf("resolve machine account-domain SID: %w", err)
	}
	if !localUnderMachineDomain(sid, machineSid) {
		return nil, fmt.Errorf("account %q (SID %s) is not a local SAM account under machine domain %s",
			username, sid.String(), machineSid.String())
	}
	return sid, nil
}

// resolveLocalUserIdentity proves username is a local SAM user and returns its
// SID + RID as one value, so callers do not repeat bare LookupSID calls that
// could diverge.
func resolveLocalUserIdentity(username string) (localUserIdentity, error) {
	sid, err := localAccountSID(username)
	if err != nil {
		return localUserIdentity{}, err
	}
	rid, err := ridFromSID(sid)
	if err != nil {
		return localUserIdentity{}, err
	}
	return localUserIdentity{sid: sid, sidString: sid.String(), rid: rid}, nil
}

// ridFromSID returns the relative identifier (last sub-authority) of sid.
func ridFromSID(sid *windows.SID) (uint32, error) {
	count := sid.SubAuthorityCount()
	if count == 0 {
		return 0, errors.New("SID has no sub-authorities")
	}
	return sid.SubAuthority(uint32(count) - 1), nil
}

// administratorsAliasName resolves the localized display name of the built-in
// Administrators alias (e.g. "Administrators", "Administratoren"), used to seed
// the recursive Administrators-membership expansion.
func administratorsAliasName() (string, error) {
	aliasSid, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return "", fmt.Errorf("derive Administrators well-known SID: %w", err)
	}
	name, _, _, err := aliasSid.LookupAccount("")
	if err != nil {
		return "", fmt.Errorf("resolve Administrators alias name: %w", err)
	}
	return name, nil
}
