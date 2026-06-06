package selfupdate

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestFileHighWaterStore_ReadMaxSeen(t *testing.T) {
	ctx := context.Background()

	t.Run("absent file is first-install", func(t *testing.T) {
		s := FileHighWaterStore{Path: filepath.Join(t.TempDir(), "nope.txt")}
		v, err := s.ReadMaxSeen(ctx)
		if err != nil || v != "" {
			t.Fatalf("absent => (%q,%v), want (\"\",nil)", v, err)
		}
	})

	t.Run("present value is read + trimmed", func(t *testing.T) {
		p := filepath.Join(t.TempDir(), "hw.txt")
		if err := os.WriteFile(p, []byte("  2.3.4\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		v, err := FileHighWaterStore{Path: p}.ReadMaxSeen(ctx)
		if err != nil || v != "2.3.4" {
			t.Fatalf("present => (%q,%v), want (\"2.3.4\",nil)", v, err)
		}
	})

	t.Run("present but empty is corrupt => error", func(t *testing.T) {
		p := filepath.Join(t.TempDir(), "empty.txt")
		if err := os.WriteFile(p, []byte("   \n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := (FileHighWaterStore{Path: p}).ReadMaxSeen(ctx); err == nil {
			t.Fatal("empty high-water file must be treated as corrupt (error)")
		}
	})

	t.Run("empty path => error", func(t *testing.T) {
		if _, err := (FileHighWaterStore{}).ReadMaxSeen(ctx); err == nil {
			t.Fatal("empty path must error")
		}
	})
}

func TestFileHighWaterStore_WriteMaxSeen(t *testing.T) {
	ctx := context.Background()

	t.Run("roundtrip", func(t *testing.T) {
		p := filepath.Join(t.TempDir(), "hw.txt")
		s := FileHighWaterStore{Path: p}
		if err := s.WriteMaxSeen(ctx, "1.4.2"); err != nil {
			t.Fatal(err)
		}
		v, err := s.ReadMaxSeen(ctx)
		if err != nil || v != "1.4.2" {
			t.Fatalf("roundtrip => (%q,%v), want (\"1.4.2\",nil)", v, err)
		}
	})

	t.Run("refuses unparseable version", func(t *testing.T) {
		p := filepath.Join(t.TempDir(), "hw.txt")
		if err := (FileHighWaterStore{Path: p}).WriteMaxSeen(ctx, "garbage"); err == nil {
			t.Fatal("writing an unparseable version must be refused")
		}
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Fatal("no file should be written on a refused version")
		}
	})

	t.Run("overwrite is atomic", func(t *testing.T) {
		p := filepath.Join(t.TempDir(), "hw.txt")
		s := FileHighWaterStore{Path: p}
		_ = s.WriteMaxSeen(ctx, "1.0.0")
		if err := s.WriteMaxSeen(ctx, "2.0.0"); err != nil {
			t.Fatal(err)
		}
		v, _ := s.ReadMaxSeen(ctx)
		if v != "2.0.0" {
			t.Fatalf("after overwrite => %q, want 2.0.0", v)
		}
		// no leftover temp files
		entries, _ := os.ReadDir(filepath.Dir(p))
		if len(entries) != 1 {
			t.Fatalf("expected exactly the high-water file, got %d entries", len(entries))
		}
	})
}
