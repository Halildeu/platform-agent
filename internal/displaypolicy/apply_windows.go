//go:build windows

package displaypolicy

import (
	"context"
	"errors"
	"fmt"
	"strconv"

	"golang.org/x/sys/windows/registry"
)

// Policy registry key paths, relative to each HKU\<SID> hive. Screensaver +
// wallpaper policy are User-class (Codex 019ea9c5): there is no machine-wide
// HKLM surface, so they are written under every loaded interactive user hive.
const (
	keyScreensaver   = `Software\Policies\Microsoft\Windows\Control Panel\Desktop`
	keyWallpaper     = `Software\Microsoft\Windows\CurrentVersion\Policies\System`
	keyActiveDesktop = `Software\Microsoft\Windows\CurrentVersion\Policies\ActiveDesktop`
)

var screensaverValues = []string{"ScreenSaveActive", "ScreenSaverIsSecure", "ScreenSaveTimeOut", "SCRNSAVE.EXE"}

// Apply writes (ENFORCE) or deletes (CLEAR) the managed screensaver + wallpaper
// policy values under every loaded interactive user hive. It is fail-loud:
// ENFORCE with no loaded user hive is FAILED_NO_TARGET_USER_HIVE (cannot
// honestly claim enforced); partial per-hive failure is PARTIAL.
func Apply(_ context.Context, cmd Command) Result {
	res := Result{
		Operation:      cmd.Operation,
		TargetModel:    targetModel,
		TargetedSIDs:   []string{},
		WrittenValues:  []string{},
		DeletedValues:  []string{},
		EffectiveState: effectiveNote,
		Limitations: []string{
			"v1 targets currently loaded user hives only; unloaded profiles are not applied",
			"no wallpaper asset download in v1 (assetRef must be an existing local path)",
			"a registry write does not prove the interactive desktop visibly changed",
		},
	}

	sids, err := loadedTargetSIDs()
	if err != nil {
		res.FinalStatus = StatusFailedRegistry
		res.Errors = append(res.Errors, fmt.Sprintf("enumerate HKEY_USERS: %v", err))
		res.Summary = "SET_DISPLAY_POLICY failed to enumerate user hives"
		return res
	}
	if len(sids) == 0 {
		res.Skipped = append(res.Skipped, Skipped{Scope: "no-loaded-user-hive", Reason: "no loaded interactive user SID hive"})
		if cmd.Operation == OperationClear {
			res.FinalStatus = StatusSucceeded
			res.Summary = "SET_DISPLAY_POLICY CLEAR: no loaded user hive to clear (no-op)"
			return res
		}
		res.FinalStatus = StatusFailedNoTargetHive
		res.Summary = "SET_DISPLAY_POLICY ENFORCE: no loaded interactive user hive to target"
		return res
	}

	successes, failures := 0, 0
	for _, sid := range sids {
		res.TargetedSIDs = append(res.TargetedSIDs, sid)
		var sidErr bool
		if cmd.Operation == OperationEnforce {
			sidErr = applyEnforceForSID(sid, cmd, &res)
		} else {
			applyClearForSID(sid, &res)
		}
		if sidErr {
			failures++
		} else {
			successes++
		}
	}

	switch {
	case failures == 0:
		res.FinalStatus = StatusSucceeded
	case successes == 0:
		res.FinalStatus = StatusFailedRegistry
	default:
		res.FinalStatus = StatusPartial
	}
	res.Summary = fmt.Sprintf("SET_DISPLAY_POLICY %s: %d/%d loaded user hives applied", cmd.Operation, successes, len(sids))
	return res
}

// loadedTargetSIDs enumerates HKEY_USERS and returns only loaded real
// interactive user SID hives (IsTargetUserSID).
func loadedTargetSIDs() ([]string, error) {
	k, err := registry.OpenKey(registry.USERS, "", registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return nil, err
	}
	defer k.Close()
	names, err := k.ReadSubKeyNames(-1)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(names))
	for _, n := range names {
		if IsTargetUserSID(n) {
			out = append(out, n)
		}
	}
	return out, nil
}

func applyEnforceForSID(sid string, cmd Command, res *Result) bool {
	hadErr := false
	if s := cmd.Screensaver; s != nil {
		spath := sid + `\` + keyScreensaver
		if s.Enabled {
			pairs := [][2]string{
				{"ScreenSaveActive", "1"},
				{"ScreenSaverIsSecure", boolToReg(s.SecureOnResume)},
				{"ScreenSaveTimeOut", strconv.Itoa(s.TimeoutSeconds)},
				{"SCRNSAVE.EXE", s.ScrPath},
			}
			for _, p := range pairs {
				if setString(spath, p[0], p[1], res) {
					hadErr = true
				}
			}
		} else {
			for _, name := range screensaverValues {
				deleteValue(spath, name, res)
			}
		}
	}
	if w := cmd.Wallpaper; w != nil {
		wpath := sid + `\` + keyWallpaper
		apath := sid + `\` + keyActiveDesktop
		if w.Enabled {
			styleVal, _ := StyleToRegistryValue(w.Style)
			if setString(wpath, "Wallpaper", w.AssetRef, res) {
				hadErr = true
			}
			if setString(wpath, "WallpaperStyle", styleVal, res) {
				hadErr = true
			}
			if w.UserCannotChange {
				if setDWord(apath, "NoChangingWallPaper", 1, res) {
					hadErr = true
				}
			} else {
				deleteValue(apath, "NoChangingWallPaper", res)
			}
		} else {
			deleteValue(wpath, "Wallpaper", res)
			deleteValue(wpath, "WallpaperStyle", res)
			deleteValue(apath, "NoChangingWallPaper", res)
		}
	}
	return hadErr
}

// applyClearForSID deletes every managed value; a missing value is not a
// failure (CLEAR = revert to user control).
func applyClearForSID(sid string, res *Result) {
	spath := sid + `\` + keyScreensaver
	wpath := sid + `\` + keyWallpaper
	apath := sid + `\` + keyActiveDesktop
	for _, name := range screensaverValues {
		deleteValue(spath, name, res)
	}
	deleteValue(wpath, "Wallpaper", res)
	deleteValue(wpath, "WallpaperStyle", res)
	deleteValue(apath, "NoChangingWallPaper", res)
}

func boolToReg(b bool) string {
	if b {
		return "1"
	}
	return "0"
}

func openOrCreate(path string) (registry.Key, error) {
	k, _, err := registry.CreateKey(registry.USERS, path,
		registry.SET_VALUE|registry.CREATE_SUB_KEY|registry.QUERY_VALUE)
	return k, err
}

func setString(path, name, val string, res *Result) bool {
	k, err := openOrCreate(path)
	if err != nil {
		res.Errors = append(res.Errors, fmt.Sprintf("open %q: %v", path, err))
		return true
	}
	defer k.Close()
	if err := k.SetStringValue(name, val); err != nil {
		res.Errors = append(res.Errors, fmt.Sprintf("set %s\\%s: %v", path, name, err))
		return true
	}
	res.WrittenValues = append(res.WrittenValues, `HKU\`+path+`\`+name)
	return false
}

func setDWord(path, name string, val uint32, res *Result) bool {
	k, err := openOrCreate(path)
	if err != nil {
		res.Errors = append(res.Errors, fmt.Sprintf("open %q: %v", path, err))
		return true
	}
	defer k.Close()
	if err := k.SetDWordValue(name, val); err != nil {
		res.Errors = append(res.Errors, fmt.Sprintf("set %s\\%s: %v", path, name, err))
		return true
	}
	res.WrittenValues = append(res.WrittenValues, `HKU\`+path+`\`+name)
	return false
}

func deleteValue(path, name string, res *Result) {
	k, err := registry.OpenKey(registry.USERS, path, registry.SET_VALUE)
	if err != nil {
		// Key absent → the managed value is already absent; nothing to do.
		return
	}
	defer k.Close()
	if err := k.DeleteValue(name); err != nil {
		if errors.Is(err, registry.ErrNotExist) {
			return
		}
		res.Errors = append(res.Errors, fmt.Sprintf("delete %s\\%s: %v", path, name, err))
		return
	}
	res.DeletedValues = append(res.DeletedValues, `HKU\`+path+`\`+name)
}
