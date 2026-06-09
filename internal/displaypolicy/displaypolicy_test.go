package displaypolicy

import (
	"context"
	"runtime"
	"testing"
)

func enforceCmd() Command {
	return Command{
		Operation:  OperationEnforce,
		RevisionID: "rev-1",
		DeviceID:   "dev-1",
		PolicyHash: "h",
		Screensaver: &Screensaver{
			Enabled:        true,
			TimeoutSeconds: 600,
			SecureOnResume: true,
			ScrPath:        `C:\Windows\System32\scrnsave.scr`,
		},
	}
}

func TestValidate_OK(t *testing.T) {
	if err := Validate(enforceCmd()); err != nil {
		t.Fatalf("valid ENFORCE rejected: %v", err)
	}
	if err := Validate(Command{Operation: OperationClear}); err != nil {
		t.Fatalf("valid CLEAR rejected: %v", err)
	}
}

func TestValidate_UnknownOperation(t *testing.T) {
	if err := Validate(Command{Operation: "WIPE"}); err == nil {
		t.Fatal("unknown operation accepted")
	}
}

func TestValidate_EnforceNeedsAtLeastOneBlock(t *testing.T) {
	if err := Validate(Command{Operation: OperationEnforce}); err == nil {
		t.Fatal("ENFORCE with no screensaver/wallpaper accepted")
	}
}

func TestValidate_TimeoutRange(t *testing.T) {
	for _, to := range []int{0, 59, 86401, -1} {
		c := enforceCmd()
		c.Screensaver.TimeoutSeconds = to
		if err := Validate(c); err == nil {
			t.Fatalf("out-of-range timeout %d accepted", to)
		}
	}
	for _, to := range []int{60, 600, 86400} {
		c := enforceCmd()
		c.Screensaver.TimeoutSeconds = to
		if err := Validate(c); err != nil {
			t.Fatalf("in-range timeout %d rejected: %v", to, err)
		}
	}
}

func TestValidate_ScrPathAllowlist(t *testing.T) {
	bad := []string{
		`C:\Windows\System32\evil.scr`,
		`C:\Windows\System32\..\evil.scr`,
		`scrnsave.scr`,
		`%SystemRoot%\System32\scrnsave.scr`,
		`D:\scrnsave.scr`,
	}
	for _, p := range bad {
		c := enforceCmd()
		c.Screensaver.ScrPath = p
		if err := Validate(c); err == nil {
			t.Fatalf("non-allowlisted scrPath %q accepted", p)
		}
	}
	// case-insensitive accept of every allowlisted path
	good := []string{
		`C:\Windows\System32\scrnsave.scr`,
		`c:\windows\system32\MYSTIFY.scr`,
		`C:\WINDOWS\SYSTEM32\Ribbons.scr`,
		`C:\Windows\System32\bubbles.scr`,
		`C:\Windows\System32\PhotoScreensaver.scr`,
		`C:\Windows\System32\ssText3d.scr`,
	}
	for _, p := range good {
		c := enforceCmd()
		c.Screensaver.ScrPath = p
		if err := Validate(c); err != nil {
			t.Fatalf("allowlisted scrPath %q rejected: %v", p, err)
		}
	}
}

func TestValidate_WallpaperNeedsPathAndStyle(t *testing.T) {
	base := Command{Operation: OperationEnforce, Wallpaper: &Wallpaper{Enabled: true, Style: "FILL", AssetRef: `C:\w.jpg`}}
	if err := Validate(base); err != nil {
		t.Fatalf("valid wallpaper rejected: %v", err)
	}
	noPath := base
	w := *base.Wallpaper
	w.AssetRef = "   "
	noPath.Wallpaper = &w
	if err := Validate(noPath); err == nil {
		t.Fatal("wallpaper enabled without a usable path accepted")
	}
	badStyle := base
	w2 := *base.Wallpaper
	w2.Style = "MOSAIC"
	badStyle.Wallpaper = &w2
	if err := Validate(badStyle); err == nil {
		t.Fatal("unknown wallpaper style accepted")
	}
}

func TestIsUsableLocalWallpaperPath(t *testing.T) {
	good := []string{`C:\wall.jpg`, `c:\Windows\Web\Wallpaper\img.jpg`, `D:/pics/x.png`}
	for _, p := range good {
		if !IsUsableLocalWallpaperPath(p) {
			t.Fatalf("usable local path %q rejected", p)
		}
	}
	bad := []string{
		``, `   `, `wall.jpg`, // relative
		`\\server\share\wall.jpg`,   // UNC
		`C:\dir\..\wall.jpg`,        // traversal
		`%SystemRoot%\Web\wall.jpg`, // env var
		`1:\wall.jpg`,               // not a drive letter
		`C:wall.jpg`,                // drive-relative (no separator)
		`/etc/wall.jpg`,             // posix absolute
	}
	for _, p := range bad {
		if IsUsableLocalWallpaperPath(p) {
			t.Fatalf("non-usable path %q accepted", p)
		}
	}
	// Validate must reject an enabled wallpaper whose path is UNC/relative.
	for _, p := range []string{`\\srv\s\w.jpg`, `w.jpg`, `C:\a\..\w.jpg`} {
		c := Command{Operation: OperationEnforce, Wallpaper: &Wallpaper{Enabled: true, Style: "FILL", AssetRef: p}}
		if err := Validate(c); err == nil {
			t.Fatalf("Validate accepted wallpaper with bad path %q", p)
		}
	}
}

func TestStyleToRegistryValue(t *testing.T) {
	want := map[string]string{"CENTER": "0", "STRETCH": "2", "FIT": "6", "FILL": "10", "SPAN": "22"}
	for style, exp := range want {
		got, ok := StyleToRegistryValue(style)
		if !ok || got != exp {
			t.Fatalf("style %s → %q,%v want %q", style, got, ok, exp)
		}
	}
	if _, ok := StyleToRegistryValue("TILE"); ok {
		t.Fatal("unknown style accepted")
	}
	if got, _ := StyleToRegistryValue(" fill "); got != "10" {
		t.Fatalf("case/space-insensitive mapping failed: %q", got)
	}
}

func TestIsTargetUserSID(t *testing.T) {
	target := []string{"S-1-5-21-1111-2222-3333-1001", "S-1-5-21-9-8-7-500"}
	for _, s := range target {
		if !IsTargetUserSID(s) {
			t.Fatalf("real interactive SID %q rejected", s)
		}
	}
	skip := []string{
		".DEFAULT",
		"S-1-5-18",
		"S-1-5-19",
		"S-1-5-20",
		"S-1-5-21-1111-2222-3333-1001_Classes",
		"S-1-5-21-1111-2222-3333-1001_CLASSES",
		"",
		"garbage",
	}
	for _, s := range skip {
		if IsTargetUserSID(s) {
			t.Fatalf("non-target hive %q targeted", s)
		}
	}
}

// TestApply_StubOnNonWindows asserts the build-tagged stub fail-loud path. On
// Windows this build uses apply_windows.go (VM-smoke acceptance, not unit).
func TestApply_StubOnNonWindows(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("windows uses the real registry applier (VM smoke)")
	}
	res := Apply(context.Background(), enforceCmd())
	if res.FinalStatus != StatusFailedUnsupportedOS {
		t.Fatalf("non-windows Apply status = %s, want %s", res.FinalStatus, StatusFailedUnsupportedOS)
	}
}
