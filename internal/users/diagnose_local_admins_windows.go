//go:build windows

package users

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"golang.org/x/sys/windows"
)

// DiagnoseLocalAdmins builds a READ-ONLY Gate-0 snapshot (see LocalAdminDiagnostic).
// It NEVER mutates the SAM: it resolves the machine account-domain SID, enumerates
// the DIRECT members of the built-in Administrators alias, classifies each via the
// SAME localUnderMachineDomain / isLocalGroupSID discriminator the lockout guard
// uses, and also reports the flattened effective LOCAL-admin user set
// (adminLocalUserSIDStrings) the guard actually reasons over.
//
// Unlike the guard, per-member lookup failures are surfaced (as "unresolved" +
// an Errors entry) rather than fail-closed — the diagnostic's job is to SHOW the
// discriminator, not to make a security decision.
func DiagnoseLocalAdmins() (LocalAdminDiagnostic, error) {
	machineSid, err := resolveMachineDomainSid()
	if err != nil {
		return LocalAdminDiagnostic{}, fmt.Errorf("resolve machine account-domain SID: %w", err)
	}
	diag := LocalAdminDiagnostic{MachineDomainSID: machineSid.String()}

	aliasName, err := administratorsAliasName()
	if err != nil {
		return LocalAdminDiagnostic{}, fmt.Errorf("resolve Administrators alias name: %w", err)
	}
	diag.AdministratorsAliasName = aliasName

	members, err := enumerateLocalGroupMembers(aliasName)
	if err != nil {
		return LocalAdminDiagnostic{}, fmt.Errorf("enumerate Administrators members: %w", err)
	}
	for _, m := range members {
		entry := LocalAdminMember{
			SID:                     m.String(),
			LocalUnderMachineDomain: localUnderMachineDomain(m, machineSid),
		}
		name, _, use, lookupErr := m.LookupAccount("")
		if lookupErr != nil {
			if errors.Is(lookupErr, windows.ERROR_NONE_MAPPED) {
				entry.Classification = "orphaned-skipped"
			} else {
				entry.Classification = "unresolved"
				diag.Errors = append(diag.Errors, fmt.Sprintf("lookup member %s: %v", entry.SID, lookupErr))
			}
			diag.DirectMembers = append(diag.DirectMembers, entry)
			continue
		}
		entry.Name = name
		entry.AccountType = sidTypeName(use)
		switch use {
		case windows.SidTypeUser:
			if entry.LocalUnderMachineDomain {
				entry.Classification = "local-user-counted"
			} else {
				entry.Classification = "domain-user-skipped"
			}
		case windows.SidTypeAlias, windows.SidTypeGroup, windows.SidTypeWellKnownGroup:
			// The guard recurses iff isLocalGroupSID (built-in alias OR machine-local
			// group); everything else is skipped. "Skipped" is NOT synonymous with
			// "domain group" (Codex 019ea719): Everyone / Authenticated Users / other
			// well-known or non-local aliases also land here. Split the label by the
			// S-1-5-21- (issuing-authority) prefix so the operator can tell a real
			// AD domain group from a well-known/non-local one — both still skipped.
			switch {
			case isLocalGroupSID(m, machineSid):
				entry.Classification = "local-group-recursed"
			case strings.HasPrefix(entry.SID, "S-1-5-21-"):
				entry.Classification = "domain-group-skipped"
			default:
				entry.Classification = "well-known-or-nonlocal-group-skipped"
			}
		default:
			entry.Classification = "other-skipped"
		}
		diag.DirectMembers = append(diag.DirectMembers, entry)
	}

	// The flattened effective LOCAL-admin user set the guard reasons over
	// (adminLocalUserSIDStrings recurses nested local groups). Surfaced so the
	// EffectiveLocalAdminUserCount can be eyeballed against the directMembers
	// breakdown (e.g. a nested-only local admin appears here but not as a direct
	// user member).
	if set, setErr := adminLocalUserSIDStrings(); setErr != nil {
		diag.Errors = append(diag.Errors, fmt.Sprintf("flatten effective local-admin set: %v", setErr))
	} else {
		sids := make([]string, 0, len(set))
		for s := range set {
			sids = append(sids, s)
		}
		sort.Strings(sids)
		diag.EffectiveLocalAdminUserSIDs = sids
		diag.EffectiveLocalAdminUserCount = len(sids)
	}
	return diag, nil
}

// sidTypeName renders a SID_NAME_USE constant as a short label for the diagnostic.
func sidTypeName(use uint32) string {
	switch use {
	case windows.SidTypeUser:
		return "user"
	case windows.SidTypeGroup:
		return "group"
	case windows.SidTypeAlias:
		return "alias"
	case windows.SidTypeWellKnownGroup:
		return "well-known-group"
	case windows.SidTypeDomain:
		return "domain"
	case windows.SidTypeComputer:
		return "computer"
	case windows.SidTypeDeletedAccount:
		return "deleted"
	default:
		return fmt.Sprintf("type-%d", use)
	}
}
