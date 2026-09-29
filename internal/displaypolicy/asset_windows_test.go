//go:build windows

package displaypolicy

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

// A test does not run as SYSTEM, so it cannot make SYSTEM the owner; these
// descriptors keep everything else the production ones enforce and let the
// test's own identity (OW) clean up.
const (
	testDirSDDL  = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;OW)(A;OICI;0x1200a9;;;BU)"
	testFileSDDL = "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;OW)(A;;0x1200a9;;;BU)"
)

func testStore(t *testing.T) WindowsAssetStore {
	t.Helper()
	return WindowsAssetStore{
		Root:     filepath.Join(t.TempDir(), "wallpaper"),
		DirSDDL:  testDirSDDL,
		FileSDDL: testFileSDDL,
	}
}

func daclString(t *testing.T, path string) string {
	t.Helper()
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatalf("read security of %s: %v", path, err)
	}
	return sd.String()
}

func TestWindowsAssetStore_CommitWritesAReadOnlyForUsersFileAndReplaces(t *testing.T) {
	s := testStore(t)
	name := strings.Repeat("d", 64) + ".png"

	first := pngBytes(512)
	path, err := s.Commit(name, first)
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if path != filepath.Join(s.Root, name) {
		t.Fatalf("path = %q", path)
	}
	if got, _ := os.ReadFile(path); !bytes.Equal(got, first) {
		t.Fatal("stored content differs")
	}
	dacl := daclString(t, path)
	if !strings.Contains(dacl, "D:P") || !strings.Contains(dacl, "(A;;0x1200a9;;;BU)") {
		t.Fatalf("file DACL %q is not protected read-only for Users", dacl)
	}
	if strings.Contains(dacl, ";;FA;;;BU)") || strings.Contains(dacl, ";;FW;;;BU)") {
		t.Fatalf("file DACL %q lets Users write", dacl)
	}

	second := pngBytes(700)
	if _, err := s.Commit(name, second); err != nil {
		t.Fatalf("second Commit: %v", err)
	}
	if got, _ := os.ReadFile(path); !bytes.Equal(got, second) {
		t.Fatal("second commit did not replace the file")
	}
}

func TestWindowsAssetStore_RefusesADirectoryPlantedAtTheTargetName(t *testing.T) {
	s := testStore(t)
	name := strings.Repeat("e", 64) + ".png"
	if err := os.MkdirAll(filepath.Join(s.Root, name), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Commit(name, pngBytes(64)); err == nil {
		t.Fatal("committed over a planted directory")
	}
	entries, _ := os.ReadDir(s.Root)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".wallpaper-") {
			t.Fatalf("temp file %s left behind", e.Name())
		}
	}
}

func TestWindowsAssetStore_RefusesAJunctionPlantedAsTheStoreRoot(t *testing.T) {
	base := t.TempDir()
	elsewhere := filepath.Join(base, "elsewhere")
	if err := os.MkdirAll(elsewhere, 0o755); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(base, "wallpaper")
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", root, elsewhere).CombinedOutput(); err != nil {
		t.Skipf("cannot create a junction here: %v %s", err, out)
	}
	s := WindowsAssetStore{Root: root, DirSDDL: testDirSDDL, FileSDDL: testFileSDDL}

	if _, err := s.Commit(strings.Repeat("f", 64)+".png", pngBytes(64)); err == nil {
		t.Fatal("wrote through a junction planted as the store root")
	}
	if entries, _ := os.ReadDir(elsewhere); len(entries) != 0 {
		t.Fatalf("junction target received %d entries", len(entries))
	}
}

func TestWindowsAssetStore_RejectsNamesThatCarryAPath(t *testing.T) {
	s := testStore(t)
	for _, name := range []string{"", `..\x.png`, `sub\x.png`} {
		if _, err := s.Commit(name, pngBytes(64)); err == nil {
			t.Fatalf("accepted name %q", name)
		}
	}
}

func TestProductionWallpaperDescriptorsGiveUsersReadOnly(t *testing.T) {
	for _, sddl := range []string{wallpaperDirSDDL, wallpaperFileSDDL} {
		if !strings.HasPrefix(sddl, "O:SY") || !strings.Contains(sddl, "D:P") {
			t.Fatalf("%q must set SYSTEM as owner and protect the DACL", sddl)
		}
		if !strings.Contains(sddl, "0x1200a9;;;BU)") {
			t.Fatalf("%q must grant Users read so the desktop can render it", sddl)
		}
		if strings.Contains(sddl, "FA;;;BU)") || strings.Contains(sddl, "OW)") {
			t.Fatalf("%q grants more than read to a non-admin identity", sddl)
		}
		if _, err := windows.SecurityDescriptorFromString(sddl); err != nil {
			t.Fatalf("%q does not parse: %v", sddl, err)
		}
	}
}
