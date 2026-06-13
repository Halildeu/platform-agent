package dataprotection

import (
	"path/filepath"
	"strings"
)

// DC-EA-RED class identifiers (contract §3). These are the ONLY strings that
// may appear in Aggregate.DeniedClasses. They are agent-hardcoded and cannot
// be loosened by policy (backend mirror re-validates server-side).
const (
	classCredentialStore    = "credential_store"
	classBrowserProfile     = "browser_profile"
	classMailboxCache       = "mailbox_cache"
	classPrivateKeyMaterial = "private_key_material"
	classCloudCLITokenStore = "cloud_cli_token_store"
	classPasswordManager    = "password_manager_vault"
	classDPAPIStore         = "dpapi_store"
	classRegistryHive       = "registry_hive"
	classAppTokenStore      = "app_token_store"
	classArchiveContainer   = "archive_container"
)

// archiveExts are the DC-EA-RED archive/container extensions. They are
// denied-aggregate (never an entry); RED data can hide inside them and
// recursive classification is a separately-gated later step (contract §3 +
// Codex 019ec28a). pst/ost intentionally appear here AND under mailbox_cache
// (dual-match dedup handled by classifyDenied + recordDenied).
var archiveExts = map[string]bool{
	".zip": true, ".7z": true, ".rar": true,
	".vhd": true, ".vhdx": true,
	".pst": true, ".ost": true,
}

// privateKeyExts are private-key / secret-material extensions.
var privateKeyExts = map[string]bool{
	".kdbx": true, ".pem": true, ".key": true,
	".pfx": true, ".ppk": true, ".ovpn": true,
}

// classifyDenied applies the hardcoded DC-EA-RED class matcher to a canonical
// path. It returns the primary class, whether the object is denied, and
// whether the archive-container predicate is additionally true (for
// container_count + the pst/ost dual-match). Matching is class-based over
// canonical path segments + basename/extension — the contract's example paths
// are illustrative, not exhaustive, and a rename-based escape (id_rsa →
// notes.txt) is an accepted, documented residual: this is managed-root
// metadata + hardcoded path-class deny, NOT content-based DLP.
func classifyDenied(canonPath, name string) (class string, denied bool, archive bool) {
	lowerName := strings.ToLower(name)
	ext := strings.ToLower(filepath.Ext(name))
	segs := lowerSegments(canonPath)
	archive = archiveExts[ext]

	switch {
	case isCredentialStore(lowerName, segs):
		return classCredentialStore, true, archive
	case isPrivateKeyMaterial(lowerName, ext, segs):
		return classPrivateKeyMaterial, true, archive
	case isMailboxCache(ext, segs):
		// pst/ost land here as PRIMARY mailbox_cache; archive flag stays true
		// so recordDenied also bumps container_count + archive_container.
		return classMailboxCache, true, archive
	case isBrowserProfile(lowerName, segs):
		return classBrowserProfile, true, archive
	case isCloudCLITokenStore(segs):
		return classCloudCLITokenStore, true, archive
	case isPasswordManagerVault(segs):
		return classPasswordManager, true, archive
	case isDPAPIStore(segs):
		return classDPAPIStore, true, archive
	case isRegistryHive(lowerName):
		return classRegistryHive, true, archive
	case isAppTokenStore(lowerName, segs):
		return classAppTokenStore, true, archive
	case archive:
		// Pure archive/container not caught by a more-specific class.
		return classArchiveContainer, true, true
	default:
		return "", false, false
	}
}

func isCredentialStore(lowerName string, segs []string) bool {
	switch lowerName {
	case ".git-credentials", ".npmrc":
		return true
	}
	if lowerName == "config.json" && hasSegment(segs, ".docker") {
		return true
	}
	if lowerName == "credentials" && hasSegment(segs, ".git") {
		return true
	}
	return false
}

func isPrivateKeyMaterial(lowerName, ext string, segs []string) bool {
	if privateKeyExts[ext] {
		return true
	}
	if strings.HasPrefix(lowerName, "id_rsa") ||
		strings.HasPrefix(lowerName, "id_dsa") ||
		strings.HasPrefix(lowerName, "id_ecdsa") ||
		strings.HasPrefix(lowerName, "id_ed25519") {
		return true
	}
	switch lowerName {
	case "known_hosts", "authorized_keys":
		return true
	}
	return hasSegment(segs, ".ssh")
}

func isMailboxCache(ext string, segs []string) bool {
	if ext == ".ost" || ext == ".pst" {
		return true
	}
	if hasSegment(segs, "thunderbird") {
		return true
	}
	if hasSegment(segs, "outlook") && hasSegment(segs, "microsoft") {
		return true
	}
	return false
}

func isBrowserProfile(lowerName string, segs []string) bool {
	if lowerName == "webcachev01.dat" {
		return true
	}
	if hasSegment(segs, "user data") {
		return true
	}
	// cookies / local-storage / session-storage within a known browser tree
	if (hasSegment(segs, "cookies") || hasSegment(segs, "local storage") || hasSegment(segs, "session storage")) &&
		(hasSegment(segs, "chrome") || hasSegment(segs, "edge") || hasSegment(segs, "mozilla")) {
		return true
	}
	return false
}

func isCloudCLITokenStore(segs []string) bool {
	if hasSegment(segs, ".aws") || hasSegment(segs, ".azure") || hasSegment(segs, ".kube") {
		return true
	}
	if hasSegment(segs, ".config") && hasSegment(segs, "gcloud") {
		return true
	}
	return false
}

func isPasswordManagerVault(segs []string) bool {
	for _, s := range segs {
		switch s {
		case "keepass", "1password", "bitwarden", "lastpass", "keepassxc":
			return true
		}
	}
	return false
}

func isDPAPIStore(segs []string) bool {
	return hasSegment(segs, "microsoft") && hasSegment(segs, "protect")
}

func isRegistryHive(lowerName string) bool {
	switch lowerName {
	case "ntuser.dat", "usrclass.dat":
		return true
	}
	return false
}

func isAppTokenStore(lowerName string, segs []string) bool {
	if lowerName == "state.vscdb" {
		return true
	}
	if hasSegment(segs, "jetbrains") && strings.Contains(lowerName, "token") {
		return true
	}
	if hasSegment(segs, "globalstorage") &&
		(hasSegment(segs, "code") || hasSegment(segs, "vscode")) {
		return true
	}
	return false
}

// hasADSName reports whether a child file NAME carries an NTFS alternate data
// stream designator. A plain filename never legitimately contains ':', so any
// occurrence is treated as a RED-hiding vector (fail-closed).
func hasADSName(name string) bool {
	return strings.Contains(name, ":")
}

// lowerSegments splits a path into lowercased segments on BOTH separators so
// the matcher is correct regardless of which canonical form (Windows '\' or
// POSIX '/') the canonicalizer produced.
func lowerSegments(p string) []string {
	return strings.FieldsFunc(strings.ToLower(p), func(r rune) bool {
		return r == '/' || r == '\\'
	})
}

// hasSegment is a segment-boundary match (".ssh" does not match ".sshfoo").
func hasSegment(segs []string, want string) bool {
	for _, s := range segs {
		if s == want {
			return true
		}
	}
	return false
}
