//go:build windows

package registry

import (
	"strings"

	winreg "golang.org/x/sys/windows/registry"
)

// ReadInt returns the DWORD value at key\value, or def on any failure.
// Errors are deliberately swallowed: the registry contract is "best
// effort" — missing values fall back to the agent default. Operators who
// need stricter behaviour can verify the registry layout via MSI install
// and the deployment runbook.
func (reader) ReadInt(keyPath, value string, def int) int {
	rootKey, sub, ok := splitRoot(keyPath)
	if !ok {
		return def
	}
	k, err := winreg.OpenKey(rootKey, sub, winreg.QUERY_VALUE)
	if err != nil {
		return def
	}
	defer k.Close()
	raw, _, err := k.GetIntegerValue(value)
	if err != nil {
		return def
	}
	return int(raw)
}

// ReadString returns the REG_SZ value at key\value, or def on any failure.
func (reader) ReadString(keyPath, value, def string) string {
	rootKey, sub, ok := splitRoot(keyPath)
	if !ok {
		return def
	}
	k, err := winreg.OpenKey(rootKey, sub, winreg.QUERY_VALUE)
	if err != nil {
		return def
	}
	defer k.Close()
	raw, _, err := k.GetStringValue(value)
	if err != nil {
		return def
	}
	return raw
}

// splitRoot maps a "HKLM:\path\..." or "HKLM\path\..." string onto the
// matching root key handle and the sub-path. The leading backslash is
// trimmed so caller paths can mirror PowerShell syntax (HKLM:\SOFTWARE\X)
// without surprises.
func splitRoot(keyPath string) (winreg.Key, string, bool) {
	p := strings.TrimSpace(keyPath)
	for _, sep := range []string{`:\`, `:`, `\`} {
		if idx := strings.Index(p, sep); idx > 0 {
			head := strings.ToUpper(p[:idx])
			rest := strings.TrimLeft(p[idx+len(sep):], `\`)
			root, ok := rootMap[head]
			if ok {
				return root, rest, true
			}
		}
	}
	return 0, "", false
}

var rootMap = map[string]winreg.Key{
	"HKLM":               winreg.LOCAL_MACHINE,
	"HKEY_LOCAL_MACHINE": winreg.LOCAL_MACHINE,
	"HKCU":               winreg.CURRENT_USER,
	"HKEY_CURRENT_USER":  winreg.CURRENT_USER,
}
