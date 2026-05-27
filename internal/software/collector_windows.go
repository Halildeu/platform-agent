//go:build windows

package software

import (
	"time"

	winreg "golang.org/x/sys/windows/registry"
)

// uninstallKeyPath is the canonical Uninstall hive shared by both the
// 64-bit and 32-bit (WOW6432Node) registry views. The leading
// "SOFTWARE\\" prefix is part of the path; the Wow6432Node variant
// substitutes a different sub-path entirely (see hkdm32Path).
const (
	hklm64Path = `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`
	hklm32Path = `SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall`
)

// Collect enumerates HKLM (64-bit view) and HKLM\WOW6432Node (32-bit
// view) Uninstall hives and runs the data through Normalize. HKCU is
// intentionally NOT read: under LocalSystem (which is where the
// service runs) HKCU resolves to the S-1-5-18 hive, which is the
// service account's profile and does not represent a human user
// (HIGH 1 in the package doc).
func Collect(now time.Time, opts CollectOptions) SoftwareSnapshot {
	sources := []RegistrySource{
		readSource(winreg.LOCAL_MACHINE, hklm64Path, SourceHKLM64, "x64"),
		readSource(winreg.LOCAL_MACHINE, hklm32Path, SourceHKLM32, "x86"),
	}
	return Normalize(sources, now, opts)
}

// readSource opens one Uninstall hive (64-bit or WOW6432Node view) and
// flattens its subkeys into a RegistrySource that Normalize can
// process. Each subkey error is recorded against that subkey only —
// individual unreadable entries must not poison the whole snapshot.
func readSource(root winreg.Key, path, label, architecture string) RegistrySource {
	source := RegistrySource{Label: label, Architecture: architecture}
	root32, err := winreg.OpenKey(root, path, winreg.ENUMERATE_SUB_KEYS|winreg.QUERY_VALUE)
	if err != nil {
		source.ReadErr = err
		return source
	}
	defer root32.Close()

	subkeyNames, err := root32.ReadSubKeyNames(-1)
	if err != nil {
		source.ReadErr = err
		return source
	}
	for _, name := range subkeyNames {
		subkey := readSubkey(root, path, name)
		source.Subkeys = append(source.Subkeys, subkey)
	}
	return source
}

func readSubkey(root winreg.Key, parentPath, name string) RegistrySubkey {
	subkey := RegistrySubkey{Name: name}
	k, err := winreg.OpenKey(root, parentPath+`\`+name, winreg.QUERY_VALUE)
	if err != nil {
		return subkey
	}
	defer k.Close()
	subkey.DisplayName = readString(k, "DisplayName")
	subkey.DisplayVersion = readString(k, "DisplayVersion")
	subkey.Publisher = readString(k, "Publisher")
	subkey.InstallDate = readString(k, "InstallDate")
	subkey.EstimatedSize = readDWORD(k, "EstimatedSize")
	subkey.UninstallString = readString(k, "UninstallString")
	subkey.QuietUninstallString = readString(k, "QuietUninstallString")
	subkey.SystemComponent = readDWORD(k, "SystemComponent")
	subkey.ParentKeyName = readString(k, "ParentKeyName")
	subkey.ReleaseType = readString(k, "ReleaseType")
	return subkey
}

func readString(k winreg.Key, value string) string {
	raw, _, err := k.GetStringValue(value)
	if err != nil {
		return ""
	}
	return raw
}

func readDWORD(k winreg.Key, value string) int {
	raw, _, err := k.GetIntegerValue(value)
	if err != nil {
		return 0
	}
	return int(raw)
}
