//go:build windows

package winget

import (
	"context"
	"errors"
	"fmt"
	"strings"

	winreg "golang.org/x/sys/windows/registry"
)

// arpEnumCap bounds ARP enumeration (reuse of the inventory cap
// discipline — Codex 019e7d82). Hitting the cap is an ERROR, not a partial
// result: an AUTHORITATIVE detector must not treat a truncated inventory as
// a complete one (a match / second distinct match could lie beyond it).
const arpEnumCap = 5000

// arpUninstallRoots are the machine-scope ARP hives. Index 0 is the
// PRIMARY 64-bit hive; index 1 is WOW6432Node (32-bit registrations on
// 64-bit Windows), which is simply absent on 32-bit OS. HKCU is
// intentionally NOT read: the agent runs as SYSTEM (Session-0) and only
// machine-scope installs are in scope.
var arpUninstallRoots = []string{
	`SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`,
	`SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall`,
}

// windowsArpReader enumerates HKLM ARP entries via read-only registry
// APIs (no shell). Raw UninstallString is never read/surfaced.
type windowsArpReader struct{}

func defaultArpReader() ArpReader { return windowsArpReader{} }

func (windowsArpReader) Enumerate(ctx context.Context) ([]ArpEntry, error) {
	out := make([]ArpEntry, 0, 256)
	for i, path := range arpUninstallRoots {
		if err := ctx.Err(); err != nil {
			return out, err
		}
		root, err := winreg.OpenKey(winreg.LOCAL_MACHINE, path, winreg.ENUMERATE_SUB_KEYS)
		if err != nil {
			// A genuinely-absent WOW6432Node hive (32-bit OS) is fine; ANY
			// other open failure — including access-denied — on either hive
			// is a hard error. An authoritative detector must not treat a
			// failed read as a clean miss (Codex 019e7d82).
			if i > 0 && errors.Is(err, winreg.ErrNotExist) {
				continue
			}
			return out, fmt.Errorf("AG-027 registry open %q: %w", path, err)
		}
		names, err := root.ReadSubKeyNames(-1)
		root.Close()
		if err != nil {
			return out, fmt.Errorf("AG-027 registry enumerate %q: %w", path, err)
		}
		for _, name := range names {
			if len(out) >= arpEnumCap {
				return out, ErrArpEnumTruncated
			}
			if err := ctx.Err(); err != nil {
				return out, err
			}
			if e, ok := readArpEntry(path, name); ok {
				out = append(out, e)
			}
		}
	}
	return out, nil
}

func (windowsArpReader) Lookup(ctx context.Context, keyName string) (ArpEntry, bool, error) {
	if err := ctx.Err(); err != nil {
		return ArpEntry{}, false, err
	}
	for _, path := range arpUninstallRoots {
		e, ok, err := lookupArpEntry(path, keyName)
		if err != nil {
			return ArpEntry{}, false, err
		}
		if ok {
			return e, true, nil
		}
	}
	return ArpEntry{}, false, nil
}

// readArpEntry opens <path>\<name> for enumeration. ok=false if the subkey
// cannot be opened or has no DisplayName (system components / updates are
// not user-facing installed software).
func readArpEntry(path, name string) (ArpEntry, bool) {
	sub, err := winreg.OpenKey(winreg.LOCAL_MACHINE, path+`\`+name, winreg.QUERY_VALUE)
	if err != nil {
		return ArpEntry{}, false
	}
	defer sub.Close()
	dn, _, _ := sub.GetStringValue("DisplayName")
	dn = sanitizeArp(dn)
	if dn == "" {
		return ArpEntry{}, false
	}
	dv, _, _ := sub.GetStringValue("DisplayVersion")
	pub, _, _ := sub.GetStringValue("Publisher")
	return ArpEntry{
		KeyName:        sanitizeArp(name),
		DisplayName:    dn,
		DisplayVersion: sanitizeArp(dv),
		Publisher:      sanitizeArp(pub),
	}, true
}

// lookupArpEntry opens the EXACT subkey for a productCode lookup:
// (entry,true,nil) if present, (_,false,nil) if genuinely absent,
// (_,false,err) on any other read failure. Unlike enumeration it does NOT
// DisplayName-skip — a productCode key that exists is a match.
func lookupArpEntry(path, name string) (ArpEntry, bool, error) {
	sub, err := winreg.OpenKey(winreg.LOCAL_MACHINE, path+`\`+name, winreg.QUERY_VALUE)
	if err != nil {
		if errors.Is(err, winreg.ErrNotExist) {
			return ArpEntry{}, false, nil
		}
		return ArpEntry{}, false, fmt.Errorf("AG-027 registry lookup %q\\%q: %w", path, name, err)
	}
	defer sub.Close()
	dn, _, _ := sub.GetStringValue("DisplayName")
	dv, _, _ := sub.GetStringValue("DisplayVersion")
	pub, _, _ := sub.GetStringValue("Publisher")
	return ArpEntry{
		KeyName:        sanitizeArp(name),
		DisplayName:    sanitizeArp(dn),
		DisplayVersion: sanitizeArp(dv),
		Publisher:      sanitizeArp(pub),
	}, true, nil
}

// sanitizeArp trims, strips control characters, and length-caps a raw
// registry string before it can reach the wire (Codex 019e7d82).
func sanitizeArp(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 {
			return -1
		}
		return r
	}, s)
	s = strings.TrimSpace(s)
	if len(s) > 256 {
		s = s[:256]
	}
	return s
}
