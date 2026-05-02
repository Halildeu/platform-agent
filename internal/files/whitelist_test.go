package files

import (
	"errors"
	"testing"
)

func TestNormalizeRelativePathRejectsTraversal(t *testing.T) {
	_, err := NormalizeRelativePath("../AppData")
	if !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("err = %v, want ErrUnsafePath", err)
	}
}

func TestNormalizeRelativePathRejectsDriveOverride(t *testing.T) {
	_, err := NormalizeRelativePath("C:\\Windows")
	if !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("err = %v, want ErrUnsafePath", err)
	}
}

func TestNormalizeRelativePathCleansSafePath(t *testing.T) {
	got, err := NormalizeRelativePath("Desktop/./reports")
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if got != "Desktop/reports" {
		t.Fatalf("path = %q, want Desktop/reports", got)
	}
}

func TestValidateResolvedPathAllowsChild(t *testing.T) {
	err := ValidateResolvedPath("C:\\Users\\alice\\Desktop", "C:\\Users\\Alice\\Desktop\\report.txt", true)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
}

func TestValidateResolvedPathRejectsSiblingPrefix(t *testing.T) {
	err := ValidateResolvedPath("/Users/alice/Desktop", "/Users/alice/DesktopArchive/report.txt", false)
	if !errors.Is(err, ErrPathOutOfScope) {
		t.Fatalf("err = %v, want ErrPathOutOfScope", err)
	}
}
