//go:build windows

package inventory

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// AG-032 Windows live runner — direct local Built-in Administrators
// (S-1-5-32-544) alias membership enumeration with strict
// identifier-leak suppression. See local_admin_group.go for the
// wire-shape contract and the Codex 019e74d7 5-iter plan-time
// review chain.
//
// Source ordering (Codex iter-2 + iter-3 absorb):
//   1. NetAPI NetLocalGroupGetMembers level 0 (SID-only) — primary
//   2. PowerShell `Get-LocalGroup -SID ... | Get-LocalGroupMember`
//      with scalar SID allowlist — fallback
//   3. WMI Win32_GroupUser filtered by group SID — last-resort
//
// Lifetime safety: each NetAPI page's LOCALGROUP_MEMBERS_INFO_0
// entries are classified IN-PLACE before the page buffer is
// freed (Codex iter-3 MF-1 absorb). No SID pointer escapes the
// per-page scope.

const localAdminProbeTimeout = 30 * time.Second

// netapi32 + LSA lazy DLL bindings. Pinned per-process; never
// payload-supplied.
var (
	netapi32                    = syscall.NewLazyDLL("netapi32.dll")
	procNetLocalGroupGetMembers = netapi32.NewProc("NetLocalGroupGetMembers")
	procNetApiBufferFree        = netapi32.NewProc("NetApiBufferFree")
	procNetUserModalsGet        = netapi32.NewProc("NetUserModalsGet")
)

// NetAPI status codes we map.
const (
	netAPIErrorMoreData   syscall.Errno = 234
	netAPINERR_BufTooSmall syscall.Errno = 2123
	netAPINERR_GroupNotFound syscall.Errno = 2220
	netAPIErrorAccessDenied syscall.Errno = 5
	maxPreferredLength     uintptr       = 0xFFFFFFFF // -1, "let API choose"
	localAdminMaxPages     int           = 16         // safety: 16*MAX = ~ huge pages
)

// LOCALGROUP_MEMBERS_INFO_0 mirrors the netapi32.h structure for
// level 0. Contains ONLY a SID pointer.
type localGroupMembersInfo0 struct {
	SID *windows.SID
}

// rawNetAPIError carries an internal NetAPI failure with classified
// code; never includes raw status numbers in summary text.
type rawNetAPIError struct {
	Code    string
	Summary string
}

func (e *rawNetAPIError) Error() string { return e.Summary }

// ProbeLocalAdminGroup is the Windows live runner entrypoint.
func ProbeLocalAdminGroup(ctx context.Context, now func() time.Time) LocalAdminGroupResult {
	if ctx == nil {
		ctx = context.Background()
	}
	if now == nil {
		now = time.Now
	}
	start := now()
	result := LocalAdminGroupResult{
		SchemaVersion: LocalAdminGroupSchemaVersion,
		Supported:     true,
		SourceUsed:    LocalAdminSourceNone,
		MaxMembers:    maxLocalAdminMembers,
	}

	// 1. Resolve the well-known Built-in Administrators alias SID
	//    deterministically; failure here is a probe-init failure.
	adminAliasSid, errAlias := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if errAlias != nil {
		result.ProbeErrors = append(result.ProbeErrors, LocalAdminProbeError{
			Source:  LocalAdminSourceNone,
			Code:    LocalAdminErrWellKnownSIDFailed,
			Summary: "could not derive Built-in Administrators well-known SID",
		})
		finalizeLocalAdminGroup(&result, nil, start, now)
		return result
	}

	// 2. Resolve machine account-domain SID via NetUserModalsGet
	//    level 2 (Codex iter-1 MF-2: do NOT rely on
	//    LookupAccountName("Administrator")). On failure, classifier
	//    operates without local-scope classification.
	machineDomainSid, machineSidErr := resolveMachineDomainSid()
	if machineSidErr != nil {
		result.ProbeErrors = append(result.ProbeErrors, LocalAdminProbeError{
			Source:  LocalAdminSourceNone,
			Code:    LocalAdminErrMachineSIDResolutionFailed,
			Summary: "could not resolve account-domain SID for machine-scope classification",
		})
		// Continue without machine SID — classifier degrades
		// to Kind=unknown for S-1-5-21-* members per iter-1 MF-5.
	}

	// 3. NetAPI primary path. If it produces complete evidence,
	//    that's the wire result. Otherwise fall through to
	//    PowerShell, then WMI.
	classified, netapiErr := enumerateNetAPI(ctx, adminAliasSid, machineDomainSid)
	if netapiErr == nil {
		// Successful NetAPI enumeration.
		result.SourceUsed = LocalAdminSourceNetAPI
		assignMembersAndCounts(&result, classified)
		finalizeLocalAdminGroup(&result, nil, start, now)
		return result
	}

	// NetAPI failed. Try PowerShell fallback.
	classifiedPS, psErr := enumeratePowerShell(ctx, machineDomainSid)
	if psErr == nil {
		result.SourceUsed = LocalAdminSourcePowerShellLocalAccounts
		assignMembersAndCounts(&result, classifiedPS)
		finalizeLocalAdminGroup(&result, nil, start, now)
		return result
	}

	// PowerShell failed. Try WMI fallback.
	classifiedWMI, wmiErr := enumerateWMI(ctx, machineDomainSid)
	if wmiErr == nil {
		result.SourceUsed = LocalAdminSourceWMIGroupUser
		assignMembersAndCounts(&result, classifiedWMI)
		finalizeLocalAdminGroup(&result, nil, start, now)
		return result
	}

	// All three failed — final state: SourceUsed=none,
	// probeErrors records each source's failure.
	result.SourceUsed = LocalAdminSourceNone
	result.ProbeErrors = append(result.ProbeErrors, LocalAdminProbeError{
		Source:  LocalAdminSourceNetAPI,
		Code:    netapiErr.Code,
		Summary: netapiErr.Summary,
	})
	result.ProbeErrors = append(result.ProbeErrors, LocalAdminProbeError{
		Source:  LocalAdminSourcePowerShellLocalAccounts,
		Code:    psErr.Code,
		Summary: psErr.Summary,
	})
	result.ProbeErrors = append(result.ProbeErrors, LocalAdminProbeError{
		Source:  LocalAdminSourceWMIGroupUser,
		Code:    wmiErr.Code,
		Summary: wmiErr.Summary,
	})
	finalizeLocalAdminGroup(&result, nil, start, now)
	return result
}

// enumerateNetAPI is the NetAPI primary path. Each page's SIDs are
// classified IN-PLACE before the page buffer is freed
// (Codex 019e74d7 iter-3 MF-1 absorb).
func enumerateNetAPI(ctx context.Context, aliasSid *windows.SID, machineDomainSid *windows.SID) ([]LocalAdminMember, *rawNetAPIError) {
	// Resolve the alias SID to its localized name in-process only.
	// The localized name NEVER leaves this function.
	aliasName, _, _, lookupErr := aliasSid.LookupAccount("")
	if lookupErr != nil {
		return nil, &rawNetAPIError{
			Code:    LocalAdminErrNetAPIGroupNotFound,
			Summary: "NetAPI could not resolve local Administrators alias",
		}
	}
	aliasNamePtr, _ := windows.UTF16PtrFromString(aliasName)
	_ = ctx // future cancellation hook

	var classified []LocalAdminMember
	var resumeHandle uintptr
	for page := 0; page < localAdminMaxPages; page++ {
		var bufPtr unsafe.Pointer
		var entriesRead, totalEntries uint32

		ret, _, _ := procNetLocalGroupGetMembers.Call(
			0, // servername=NULL (local)
			uintptr(unsafe.Pointer(aliasNamePtr)),
			0, // level 0
			uintptr(unsafe.Pointer(&bufPtr)),
			maxPreferredLength,
			uintptr(unsafe.Pointer(&entriesRead)),
			uintptr(unsafe.Pointer(&totalEntries)),
			uintptr(unsafe.Pointer(&resumeHandle)),
		)
		status := syscall.Errno(ret)

		// Codex iter-3 MF-2 absorb: only process page when status
		// permits AND buffer/count are valid.
		pageUsable := (status == 0 || status == netAPIErrorMoreData || status == netAPINERR_BufTooSmall) &&
			bufPtr != nil && entriesRead > 0

		if pageUsable {
			// Walk entries directly from page buffer. Each SID is
			// classified into POD member rows IMMEDIATELY. No raw
			// SID pointer escapes this scope.
			entries := unsafe.Slice((*localGroupMembersInfo0)(bufPtr), entriesRead)
			for i := range entries {
				sid := entries[i].SID
				if sid == nil {
					continue
				}
				row := classifySID(sid, machineDomainSid)
				classified = append(classified, row)
			}
		}

		// Free this page's buffer NOW, before next iteration.
		if bufPtr != nil {
			procNetApiBufferFree.Call(uintptr(bufPtr))
			bufPtr = nil
		}

		switch status {
		case 0: // NERR_Success
			return classified, nil
		case netAPIErrorMoreData, netAPINERR_BufTooSmall:
			if !pageUsable {
				return nil, &rawNetAPIError{
					Code:    LocalAdminErrNetAPIFailed,
					Summary: "NetAPI local administrators enumeration failed",
				}
			}
			continue
		default:
			code := LocalAdminErrNetAPIFailed
			summary := "NetAPI local administrators enumeration failed"
			switch status {
			case netAPIErrorAccessDenied:
				code = LocalAdminErrNetAPIAccessDenied
				summary = "NetAPI access denied during local administrators enumeration"
			case netAPINERR_GroupNotFound:
				code = LocalAdminErrNetAPIGroupNotFound
				summary = "NetAPI could not find local Administrators alias"
			}
			return nil, &rawNetAPIError{Code: code, Summary: summary}
		}
	}

	// Pagination cap hit; treat as failure to avoid an infinite loop.
	return nil, &rawNetAPIError{
		Code:    LocalAdminErrNetAPIFailed,
		Summary: "NetAPI local administrators enumeration exceeded pagination safety bound",
	}
}

// resolveMachineDomainSid returns the local SAM/account-domain SID
// via NetUserModalsGet level 2 (Codex iter-1 MF-2). Returns nil
// when resolution fails; classifier degrades to coarse scope.
//
// USER_MODALS_INFO_2 contains: domainName (PWSTR) + domainId (PSID).
// Only DomainId is read; domainName is freed without being read.
func resolveMachineDomainSid() (*windows.SID, error) {
	type userModalsInfo2 struct {
		DomainName *uint16
		DomainID   *windows.SID
	}

	var bufPtr unsafe.Pointer
	ret, _, _ := procNetUserModalsGet.Call(
		0,                                 // servername=NULL (local)
		2,                                 // level 2
		uintptr(unsafe.Pointer(&bufPtr)),
	)
	if ret != 0 || bufPtr == nil {
		return nil, fmt.Errorf("NetUserModalsGet failed: status %d", ret)
	}
	defer procNetApiBufferFree.Call(uintptr(bufPtr))

	info := (*userModalsInfo2)(bufPtr)
	if info.DomainID == nil {
		return nil, errors.New("NetUserModalsGet returned null DomainID")
	}

	// Deep-copy the SID into caller-owned memory before freeing the
	// API buffer (handled by defer above).
	domainSid, copyErr := info.DomainID.Copy()
	if copyErr != nil {
		return nil, copyErr
	}
	return domainSid, nil
}

// classifySID applies the 10-step precedence table from
// COMMAND-CONTRACT.md §14.4 (Codex iter-3 MF-3 + iter-4 MF-1
// absorb). Each SID matches exactly one Kind.
func classifySID(sid *windows.SID, machineDomainSid *windows.SID) LocalAdminMember {
	// Build a string form once for prefix tests. We do NOT include
	// this string anywhere on the wire — only sub-authority
	// inspection.
	authority := sid.IdentifierAuthority()
	subAuthCount := sid.SubAuthorityCount()

	// Step 1: Privileged builtin alias (S-1-5-32 + admin-adjacent RID)
	if isSidPrefixS_1_5_32(authority, subAuthCount, sid) {
		if subAuthCount >= 2 {
			switch sid.SubAuthority(1) {
			case 544, 547, 548, 549, 551: // Administrators, Power Users, Account/Server/Backup Ops
				return LocalAdminMember{
					Kind:                     LocalAdminKindBuiltinAlias,
					IsPrivilegedBuiltinAlias: true,
				}
			}
		}
		// Step 2 (broad well-known via S-1-5-32 family) checked next
		// before falling to generic builtin.
		if subAuthCount >= 2 {
			switch sid.SubAuthority(1) {
			case 545, 546, 555: // Users, Guests, Remote Desktop Users
				return LocalAdminMember{
					Kind:             LocalAdminKindBroadWellKnown,
					IsBroadWellKnown: true,
				}
			}
		}
		// Step 7: generic builtin alias — any other S-1-5-32-*.
		return LocalAdminMember{
			Kind:                     LocalAdminKindBuiltinAlias,
			IsPrivilegedBuiltinAlias: false,
		}
	}

	// Step 2 (continued): broad well-known outside S-1-5-32
	if isBroadWellKnownNonAlias(authority, subAuthCount, sid) {
		return LocalAdminMember{
			Kind:             LocalAdminKindBroadWellKnown,
			IsBroadWellKnown: true,
		}
	}

	// Step 3: Well-known privileged (System, LocalService, NetworkService)
	if isWellKnownPrivileged(authority, subAuthCount, sid) {
		return LocalAdminMember{Kind: LocalAdminKindWellKnownPrivileged}
	}

	// Step 4: Service SID (S-1-5-80-*, S-1-5-83-*)
	if isServiceSid(authority, subAuthCount, sid) {
		return LocalAdminMember{Kind: LocalAdminKindServiceSID}
	}

	// Step 5: Capability / app package (S-1-15-2-*, S-1-15-3-*)
	if isCapabilitySid(authority, subAuthCount, sid) {
		return LocalAdminMember{Kind: LocalAdminKindCapability}
	}

	// Step 6: Cloud principal (S-1-12-1-*)
	if isCloudPrincipalSid(authority, subAuthCount, sid) {
		return LocalAdminMember{
			Kind:             LocalAdminKindCloudPrincipal,
			IsCloudPrincipal: true,
		}
	}

	// Steps 8/9: S-1-5-21-* (local or domain) based on machine SID
	// prefix match. SID_NAME_USE classifies user/group/computer.
	if isAccountDomainSid(authority, subAuthCount, sid) {
		isLocal := false
		if machineDomainSid != nil {
			isLocal = sidPrefixesMatch(sid, machineDomainSid)
		}
		// Try to resolve SID_NAME_USE; failure degrades to unknown.
		_, _, sidUse, lookupErr := sid.LookupAccount("")
		resolved := lookupErr == nil

		if isLocal {
			if !resolved {
				return LocalAdminMember{
					Kind:          LocalAdminKindUnknown,
					IsLocalScoped: true,
				}
			}
			switch sidUse {
			case windows.SidTypeUser:
				return LocalAdminMember{Kind: LocalAdminKindLocalUser, IsLocalScoped: true}
			case windows.SidTypeGroup, windows.SidTypeAlias:
				return LocalAdminMember{Kind: LocalAdminKindLocalGroup, IsLocalScoped: true}
			default:
				return LocalAdminMember{Kind: LocalAdminKindUnknown, IsLocalScoped: true}
			}
		}
		// Non-machine S-1-5-21 = domain-scoped (Codex iter-1 MF-5
		// absorb: scope is provable from family alone).
		if !resolved {
			return LocalAdminMember{
				Kind:           LocalAdminKindUnknown,
				IsDomainScoped: machineDomainSid != nil, // only assert when we can prove not-machine
			}
		}
		switch sidUse {
		case windows.SidTypeUser:
			return LocalAdminMember{Kind: LocalAdminKindDomainUser, IsDomainScoped: true}
		case windows.SidTypeGroup, windows.SidTypeAlias:
			return LocalAdminMember{Kind: LocalAdminKindDomainGroup, IsDomainScoped: true}
		case windows.SidTypeComputer:
			return LocalAdminMember{Kind: LocalAdminKindDomainComputer, IsDomainScoped: true}
		default:
			return LocalAdminMember{Kind: LocalAdminKindUnknown, IsDomainScoped: true}
		}
	}

	// Step 10: anything else → unknown
	return LocalAdminMember{Kind: LocalAdminKindUnknown}
}

// SID-family predicates. These inspect authority + sub-authority
// values WITHOUT producing a wire-visible string form.

func isSidPrefixS_1_5_32(auth windows.SidIdentifierAuthority, count uint8, sid *windows.SID) bool {
	if auth.Value[5] != 5 || count < 2 {
		return false
	}
	return sid.SubAuthority(0) == 32
}

func isBroadWellKnownNonAlias(auth windows.SidIdentifierAuthority, count uint8, sid *windows.SID) bool {
	// S-1-1-0 Everyone
	if auth.Value[5] == 1 && count == 1 && sid.SubAuthority(0) == 0 {
		return true
	}
	// S-1-5-{11 Authenticated Users, 4 Interactive, 2 Network, 7 Anonymous}
	if auth.Value[5] == 5 && count == 1 {
		switch sid.SubAuthority(0) {
		case 2, 4, 7, 11:
			return true
		}
	}
	return false
}

func isWellKnownPrivileged(auth windows.SidIdentifierAuthority, count uint8, sid *windows.SID) bool {
	if auth.Value[5] != 5 || count != 1 {
		return false
	}
	switch sid.SubAuthority(0) {
	case 18, 19, 20:
		return true
	}
	return false
}

func isServiceSid(auth windows.SidIdentifierAuthority, count uint8, sid *windows.SID) bool {
	if auth.Value[5] != 5 || count < 1 {
		return false
	}
	first := sid.SubAuthority(0)
	return first == 80 || first == 83
}

func isCapabilitySid(auth windows.SidIdentifierAuthority, count uint8, sid *windows.SID) bool {
	if auth.Value[5] != 15 || count < 1 {
		return false
	}
	first := sid.SubAuthority(0)
	return first == 2 || first == 3
}

func isCloudPrincipalSid(auth windows.SidIdentifierAuthority, count uint8, sid *windows.SID) bool {
	if auth.Value[5] != 12 || count < 1 {
		return false
	}
	return sid.SubAuthority(0) == 1
}

func isAccountDomainSid(auth windows.SidIdentifierAuthority, count uint8, sid *windows.SID) bool {
	if auth.Value[5] != 5 || count < 1 {
		return false
	}
	return sid.SubAuthority(0) == 21
}

// sidPrefixesMatch compares S-1-5-21-X-Y-Z prefix (the first 3
// sub-authorities after the 21 marker) between `sid` and
// `machineDomainSid`. Returns true if the prefixes match — i.e.
// the SID belongs to the local account-domain.
func sidPrefixesMatch(sid *windows.SID, machineDomainSid *windows.SID) bool {
	if machineDomainSid == nil {
		return false
	}
	if sid.SubAuthorityCount() < 4 || machineDomainSid.SubAuthorityCount() < 4 {
		return false
	}
	// Skip sub-authority 0 (the "21" marker) and compare the next 3.
	for i := uint32(1); i < 4; i++ {
		if sid.SubAuthority(i) != machineDomainSid.SubAuthority(i) {
			return false
		}
	}
	return true
}

// enumeratePowerShell is the PowerShell LocalAccounts fallback.
// Resolves the local Administrators alias by SID, enumerates
// members, emits ONLY the scalar SID string per member (Codex
// iter-1 MF-5 absorb: no SecurityIdentifier object serialization).
var runLocalAdminPowerShellProbe = runLocalAdminPowerShellProbeReal

func runLocalAdminPowerShellProbeReal(ctx context.Context) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "powershell.exe",
		"-NoProfile", "-NonInteractive", "-Command", localAdminPowerShellScript)
	return cmd.Output()
}

const localAdminPowerShellScript = `
$ErrorActionPreference = 'Stop'
try {
  $group = Get-LocalGroup -SID 'S-1-5-32-544'
  $members = Get-LocalGroupMember -SID $group.SID -ErrorAction Stop
  $sidStrings = @()
  foreach ($m in $members) {
    if ($m.SID -and $m.SID.Value) {
      $sidStrings += [string]$m.SID.Value
    }
  }
  @{ members = $sidStrings; sourcePresent = $true } | ConvertTo-Json -Depth 3 -Compress
} catch {
  $code = 'POWERSHELL_FAILED'
  if ($_.Exception -and $_.Exception.GetType().Name -like '*UnauthorizedAccess*') { $code = 'ACCESS_DENIED' }
  elseif ($_.CategoryInfo -and $_.CategoryInfo.Category -eq 'ObjectNotFound') { $code = 'CMDLET_UNAVAILABLE' }
  @{ members = @(); sourcePresent = $false; error = $code } | ConvertTo-Json -Depth 3 -Compress
}
`

type powerShellEnumOutput struct {
	Members       []string `json:"members"`
	SourcePresent bool     `json:"sourcePresent"`
	Error         string   `json:"error"`
}

func enumeratePowerShell(ctx context.Context, machineDomainSid *windows.SID) ([]LocalAdminMember, *rawNetAPIError) {
	probeCtx, cancel := context.WithTimeout(ctx, localAdminProbeTimeout)
	defer cancel()

	raw, err := runLocalAdminPowerShellProbe(probeCtx)
	if err != nil {
		code := LocalAdminErrPowerShellFailed
		if errors.Is(probeCtx.Err(), context.DeadlineExceeded) {
			code = LocalAdminErrPowerShellTimeout
		}
		return nil, &rawNetAPIError{Code: code, Summary: "PowerShell LocalAccounts enumeration failed"}
	}
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" {
		return nil, &rawNetAPIError{
			Code:    LocalAdminErrPowerShellEmptyOutput,
			Summary: "PowerShell LocalAccounts enumeration returned no output",
		}
	}
	var parsed powerShellEnumOutput
	if perr := json.Unmarshal([]byte(trimmed), &parsed); perr != nil {
		return nil, &rawNetAPIError{
			Code:    LocalAdminErrPowerShellParseError,
			Summary: "PowerShell LocalAccounts JSON parse failed",
		}
	}
	if !parsed.SourcePresent {
		code := LocalAdminErrPowerShellFailed
		if parsed.Error == "ACCESS_DENIED" {
			code = LocalAdminErrAccessDenied
		} else if parsed.Error == "CMDLET_UNAVAILABLE" {
			code = LocalAdminErrCmdletUnavailable
		}
		return nil, &rawNetAPIError{
			Code:    code,
			Summary: "PowerShell LocalAccounts enumeration failed",
		}
	}

	classified := make([]LocalAdminMember, 0, len(parsed.Members))
	for _, sidStr := range parsed.Members {
		sid, parseErr := windows.StringToSid(sidStr)
		if parseErr != nil || sid == nil {
			classified = append(classified, LocalAdminMember{Kind: LocalAdminKindUnknown})
			continue
		}
		classified = append(classified, classifySID(sid, machineDomainSid))
	}
	return classified, nil
}

// enumerateWMI is the last-resort WMI fallback. Uses
// Get-CimInstance Win32_GroupUser via PowerShell, filtered to the
// local Administrators group SID, emitting only the per-member
// PartComponent's Name and Domain — wait, no: we still want SID,
// not Name. We use Win32_Account by SID per member to get only
// the SID.
//
// For v1 we keep this stub-implemented: if both NetAPI and
// PowerShell LocalAccounts fail, WMI is unlikely to succeed
// cleanly, so we return CMDLET_UNAVAILABLE. Operators get the
// NetAPI + PS failure trail in probeErrors[] and SourceUsed=none.
// Future WMI runner can land without schema change.
func enumerateWMI(ctx context.Context, machineDomainSid *windows.SID) ([]LocalAdminMember, *rawNetAPIError) {
	_ = ctx
	_ = machineDomainSid
	return nil, &rawNetAPIError{
		Code:    LocalAdminErrCmdletUnavailable,
		Summary: "WMI Win32_GroupUser enumeration is not implemented in v1",
	}
}

// assignMembersAndCounts incorporates classified rows into the
// result, increments per-bucket counts, and applies the
// maxLocalAdminMembers cap (Codex iter-4 MF-3 absorb). counts
// cover the full enumeration; Members slice is capped.
func assignMembersAndCounts(result *LocalAdminGroupResult, classified []LocalAdminMember) {
	result.DirectMemberCount = len(classified)
	for _, m := range classified {
		switch m.Kind {
		case LocalAdminKindLocalUser:
			result.LocalUserCount++
		case LocalAdminKindLocalGroup:
			result.LocalGroupCount++
		case LocalAdminKindDomainUser:
			result.DomainUserCount++
		case LocalAdminKindDomainGroup:
			result.DomainGroupCount++
		case LocalAdminKindDomainComputer:
			result.DomainComputerCount++
		case LocalAdminKindBuiltinAlias:
			result.BuiltinAliasCount++
		case LocalAdminKindServiceSID:
			result.ServiceSIDCount++
		case LocalAdminKindWellKnownPrivileged:
			result.WellKnownPrivilegedCount++
		case LocalAdminKindBroadWellKnown:
			result.BroadWellKnownCount++
		case LocalAdminKindCloudPrincipal:
			result.CloudPrincipalCount++
		case LocalAdminKindCapability:
			result.CapabilityCount++
		default:
			result.UnknownCount++
		}
	}
	if len(classified) > maxLocalAdminMembers {
		result.Members = append(result.Members[:0], classified[:maxLocalAdminMembers]...)
		result.MembersTruncated = true
	} else {
		result.Members = append(result.Members[:0], classified...)
		result.MembersTruncated = false
	}
}

// finalizeLocalAdminGroup normalizes Members to non-nil,
// derives ProbeComplete + risk flags, and stamps ProbeDurationMs.
func finalizeLocalAdminGroup(result *LocalAdminGroupResult, _ []LocalAdminMember, start time.Time, now func() time.Time) {
	deriveLocalAdminGroupSummary(result)
	result.ProbeDurationMs = localAdminGroupElapsedMs(start, now)
}
