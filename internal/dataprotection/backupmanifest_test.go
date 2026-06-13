package dataprotection

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// writeFile creates a file with one byte of content (the generator must never
// read it; we only need it to exist with metadata).
func writeFile(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte("x"), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func genOverTree(t *testing.T, build func(root string)) Manifest {
	t.Helper()
	root := filepath.Join(t.TempDir(), "managed")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatalf("mkdir root: %v", err)
	}
	build(root)
	m, err := Generate(Options{
		DeviceID:           "dev-1",
		TenantID:           "ten-1",
		AllowlistProfileID: "prof-1",
		Now:                time.Now(),
		Canon:              NewCanonicalizer(),
		Roots: []ManagedRoot{{
			RootRef:        "managed_root:11111111-1111-1111-1111-111111111111",
			LocalPath:      root,
			PathClass:      "managed/it-folder",
			CompanyManaged: true,
		}},
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	return m
}

func TestGenerate_EmitsEligibleEntries(t *testing.T) {
	m := genOverTree(t, func(root string) {
		writeFile(t, filepath.Join(root, "docs", "report.docx"))
		writeFile(t, filepath.Join(root, "sheets", "data.csv"))
		writeFile(t, filepath.Join(root, "scan.pdf"))
		writeFile(t, filepath.Join(root, "photo.png"))
		writeFile(t, filepath.Join(root, "blob.bin"))
	})

	if m.ManifestVersion != "1" || m.DCEATier != "DC-EA-1" {
		t.Fatalf("header drift: %+v", m)
	}
	got := map[string]string{} // ext_type by a stable key (count-based check)
	counts := map[string]int{}
	for _, e := range m.Entries {
		counts[e.ExtensionType]++
		got[e.ExtensionType] = e.OwnerScopeMarker
		if e.RootRef != "managed_root:11111111-1111-1111-1111-111111111111" {
			t.Errorf("entry root_ref drift: %q", e.RootRef)
		}
		if e.OwnerScopeMarker != ownerCompany {
			t.Errorf("expected company owner_scope, got %q", e.OwnerScopeMarker)
		}
		if e.FileCount != 1 {
			t.Errorf("expected file_count 1, got %d", e.FileCount)
		}
	}
	for _, want := range []string{extDoc, extSheet, extPDF, extImage, extOther} {
		if counts[want] != 1 {
			t.Errorf("expected exactly 1 %s entry, got %d (entries=%+v)", want, counts[want], m.Entries)
		}
	}
	if m.Aggregate.TotalEligibleCount != 5 {
		t.Errorf("expected 5 eligible, got %d", m.Aggregate.TotalEligibleCount)
	}
	if m.Aggregate.DeniedCount != 0 {
		t.Errorf("expected 0 denied, got %d", m.Aggregate.DeniedCount)
	}
}

func TestGenerate_DeniesRedClasses(t *testing.T) {
	m := genOverTree(t, func(root string) {
		writeFile(t, filepath.Join(root, "report.docx")) // 1 eligible anchor
		writeFile(t, filepath.Join(root, "secrets", "server.pem"))
		writeFile(t, filepath.Join(root, "NTUSER.DAT"))
		writeFile(t, filepath.Join(root, ".git-credentials"))
		writeFile(t, filepath.Join(root, "Microsoft", "Protect", "masterkey"))
	})

	if m.Aggregate.TotalEligibleCount != 1 {
		t.Errorf("expected 1 eligible (report.docx), got %d (entries=%+v)", m.Aggregate.TotalEligibleCount, m.Entries)
	}
	classes := strings.Join(m.Aggregate.DeniedClasses, ",")
	for _, want := range []string{classPrivateKeyMaterial, classRegistryHive, classCredentialStore, classDPAPIStore} {
		if !strings.Contains(classes, want) {
			t.Errorf("expected denied class %q in {%s}", want, classes)
		}
	}
	// No RED path should ever appear as an entry.
	for _, e := range m.Entries {
		if e.ExtensionType != extDoc {
			t.Errorf("unexpected non-doc entry leaked: %+v", e)
		}
	}
}

func TestGenerate_ArchiveDeniedAggregate(t *testing.T) {
	m := genOverTree(t, func(root string) {
		writeFile(t, filepath.Join(root, "report.docx"))
		writeFile(t, filepath.Join(root, "backup.zip"))
		writeFile(t, filepath.Join(root, "disk.vhdx"))
	})

	if m.Aggregate.TotalEligibleCount != 1 {
		t.Errorf("expected 1 eligible, got %d", m.Aggregate.TotalEligibleCount)
	}
	// 2 archives → denied_count 2, container_count 2, archive_container class.
	if m.Aggregate.DeniedCount != 2 {
		t.Errorf("expected denied_count 2, got %d", m.Aggregate.DeniedCount)
	}
	if m.Aggregate.ContainerCount != 2 {
		t.Errorf("expected container_count 2, got %d", m.Aggregate.ContainerCount)
	}
	if !contains(m.Aggregate.DeniedClasses, classArchiveContainer) {
		t.Errorf("expected archive_container in denied_classes %v", m.Aggregate.DeniedClasses)
	}
	// CONTRACT INVARIANT: an archive must never be an entry.
	for _, e := range m.Entries {
		if e.ExtensionType == "archive" {
			t.Fatalf("archive leaked as an entry: %+v", e)
		}
	}
}

func TestGenerate_PstOstDualMatchDedup(t *testing.T) {
	m := genOverTree(t, func(root string) {
		writeFile(t, filepath.Join(root, "mailbox.pst"))
	})

	// Codex 019ec28a: a .pst is BOTH mailbox_cache and archive_container, but
	// counts ONCE in denied_count; container_count bumps; both classes appear.
	if m.Aggregate.DeniedCount != 1 {
		t.Errorf("pst dual-match must count denied_count ONCE, got %d", m.Aggregate.DeniedCount)
	}
	if m.Aggregate.ContainerCount != 1 {
		t.Errorf("pst must bump container_count to 1, got %d", m.Aggregate.ContainerCount)
	}
	if !contains(m.Aggregate.DeniedClasses, classMailboxCache) {
		t.Errorf("expected mailbox_cache in %v", m.Aggregate.DeniedClasses)
	}
	if !contains(m.Aggregate.DeniedClasses, classArchiveContainer) {
		t.Errorf("expected archive_container in %v", m.Aggregate.DeniedClasses)
	}
	if len(m.Entries) != 0 {
		t.Errorf("pst must not be an entry, got %+v", m.Entries)
	}
}

func TestGenerate_DeniedDirNotDescended(t *testing.T) {
	m := genOverTree(t, func(root string) {
		// .ssh is a private_key_material class DIRECTORY; its contents must
		// never be walked or counted as eligible.
		writeFile(t, filepath.Join(root, ".ssh", "id_rsa"))
		writeFile(t, filepath.Join(root, ".ssh", "config"))
		writeFile(t, filepath.Join(root, "ok.txt"))
	})

	if m.Aggregate.TotalEligibleCount != 1 {
		t.Errorf("only ok.txt is eligible; got %d (entries=%+v)", m.Aggregate.TotalEligibleCount, m.Entries)
	}
	// The .ssh directory is denied once; its children are never reached.
	if m.Aggregate.DeniedCount != 1 {
		t.Errorf("expected the .ssh dir denied exactly once (no descent), got %d", m.Aggregate.DeniedCount)
	}
	if !contains(m.Aggregate.DeniedClasses, classPrivateKeyMaterial) {
		t.Errorf("expected private_key_material, got %v", m.Aggregate.DeniedClasses)
	}
}

func TestGenerate_SymlinkEscapeDropped(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink-escape exercised via the non-Windows canonicalizer")
	}
	outside := filepath.Join(t.TempDir(), "outside")
	writeFile(t, filepath.Join(outside, "secret.txt"))

	m := genOverTree(t, func(root string) {
		writeFile(t, filepath.Join(root, "ok.txt"))
		// A symlink that escapes the managed root must be dropped (its
		// canonical target is outside the root), not followed.
		if err := os.Symlink(outside, filepath.Join(root, "escape")); err != nil {
			t.Fatalf("symlink: %v", err)
		}
	})

	for _, e := range m.Entries {
		// secret.txt lives outside the root; it must never be emitted.
		if e.ExtensionType == extDoc && e.RelativeDepth > 1 {
			t.Errorf("possible escape leak: %+v", e)
		}
	}
	if m.Aggregate.TotalEligibleCount != 1 {
		t.Errorf("only ok.txt eligible (escape dropped), got %d (entries=%+v)", m.Aggregate.TotalEligibleCount, m.Entries)
	}
	if m.Aggregate.UnresolvedPathCount < 1 {
		t.Errorf("escaping symlink should increment unresolved_path_count, got %d", m.Aggregate.UnresolvedPathCount)
	}
}

func TestGenerate_NoRawPathInManifest(t *testing.T) {
	var rootPath string
	m := genOverTree(t, func(root string) {
		rootPath = root
		writeFile(t, filepath.Join(root, "deep", "nested", "report.docx"))
		writeFile(t, filepath.Join(root, "secrets", "id_rsa"))
	})
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	// INVARIANT #4: no raw filesystem path may appear in the manifest JSON.
	for _, needle := range []string{rootPath, "report.docx", "id_rsa", "secrets", "nested", "Users"} {
		if needle != "" && strings.Contains(string(raw), needle) {
			t.Errorf("raw path fragment %q leaked into manifest JSON", needle)
		}
	}
}

func TestGenerate_OwnerScopeUnknownForBYOD(t *testing.T) {
	root := filepath.Join(t.TempDir(), "byod")
	writeFile(t, filepath.Join(root, "report.docx"))
	m, err := Generate(Options{
		DeviceID: "dev", TenantID: "ten", AllowlistProfileID: "p",
		BYOD: true, Now: time.Now(), Canon: NewCanonicalizer(),
		Roots: []ManagedRoot{{
			RootRef: "managed_root:22222222-2222-2222-2222-222222222222",
			LocalPath: root, PathClass: "managed/onedrive-business",
			CompanyManaged: false,
		}},
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	for _, e := range m.Entries {
		if e.OwnerScopeMarker != ownerUnknown {
			t.Errorf("non-company-managed root must yield owner_scope unknown, got %q", e.OwnerScopeMarker)
		}
	}
	if !m.Scope.BYOD {
		t.Error("scope.byod should be true")
	}
}

func TestGenerate_FailClosed(t *testing.T) {
	if _, err := Generate(Options{Roots: []ManagedRoot{{LocalPath: "/x"}}}); err != ErrNoCanonicalizer {
		t.Errorf("nil canonicalizer must fail closed, got %v", err)
	}
	if _, err := Generate(Options{Canon: NewCanonicalizer()}); err != ErrNoManagedRoots {
		t.Errorf("no roots must fail closed, got %v", err)
	}
}

func TestGenerate_RootResolvingToRedIsRefused(t *testing.T) {
	// Defense-in-depth: a backend-supplied root that itself is a RED class
	// (e.g. someone allowlisted "...\.ssh") is refused, not walked.
	base := t.TempDir()
	sshRoot := filepath.Join(base, ".ssh")
	writeFile(t, filepath.Join(sshRoot, "id_rsa"))
	m, err := Generate(Options{
		DeviceID: "d", TenantID: "t", AllowlistProfileID: "p",
		Now: time.Now(), Canon: NewCanonicalizer(),
		Roots: []ManagedRoot{{
			RootRef: "managed_root:33333333-3333-3333-3333-333333333333",
			LocalPath: sshRoot, PathClass: "managed/it-folder", CompanyManaged: true,
		}},
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if m.Aggregate.TotalEligibleCount != 0 {
		t.Errorf("a RED root must yield 0 eligible, got %d", m.Aggregate.TotalEligibleCount)
	}
	if m.Aggregate.DeniedCount != 1 || !contains(m.Aggregate.DeniedClasses, classPrivateKeyMaterial) {
		t.Errorf("RED root must be denied (private_key_material), got count=%d classes=%v", m.Aggregate.DeniedCount, m.Aggregate.DeniedClasses)
	}
}

func TestGenerate_BroadArchiveFamilyDenied(t *testing.T) {
	// Codex 019ec2bb P2: the archive family is broader than the contract's
	// examples — .tar/.gz/.iso/.vmdk must NOT become eligible "other" entries.
	m := genOverTree(t, func(root string) {
		writeFile(t, filepath.Join(root, "ok.docx"))
		writeFile(t, filepath.Join(root, "logs.tar"))
		writeFile(t, filepath.Join(root, "dump.gz"))
		writeFile(t, filepath.Join(root, "image.iso"))
		writeFile(t, filepath.Join(root, "vm.vmdk"))
	})
	if m.Aggregate.TotalEligibleCount != 1 {
		t.Errorf("only ok.docx eligible; tar/gz/iso/vmdk must be denied, got %d (entries=%+v)", m.Aggregate.TotalEligibleCount, m.Entries)
	}
	if m.Aggregate.DeniedCount != 4 || m.Aggregate.ContainerCount != 4 {
		t.Errorf("expected 4 archives denied+containers, got denied=%d container=%d", m.Aggregate.DeniedCount, m.Aggregate.ContainerCount)
	}
	if !contains(m.Aggregate.DeniedClasses, classArchiveContainer) {
		t.Errorf("expected archive_container class, got %v", m.Aggregate.DeniedClasses)
	}
	for _, e := range m.Entries {
		if e.ExtensionType != extDoc {
			t.Errorf("archive leaked as entry: %+v", e)
		}
	}
}

func TestGenerate_InvalidRootRefOrClassDropped(t *testing.T) {
	// Codex 019ec2bb P1: a path-shaped root_ref or out-of-enum path_class must
	// be dropped fail-closed (never canonicalized/walked, never echoed).
	base := t.TempDir()
	good := filepath.Join(base, "good")
	bad := filepath.Join(base, "bad")
	writeFile(t, filepath.Join(good, "a.docx"))
	writeFile(t, filepath.Join(bad, "b.docx"))

	m, err := Generate(Options{
		DeviceID: "d", TenantID: "t", AllowlistProfileID: "p",
		Now: time.Now(), Canon: NewCanonicalizer(),
		Roots: []ManagedRoot{
			{RootRef: `managed_root:C:\Users\Alice\Secret`, LocalPath: bad, PathClass: "managed/it-folder", CompanyManaged: true}, // path-shaped ref
			{RootRef: "managed_root:99999999-9999-9999-9999-999999999999", LocalPath: bad, PathClass: "totally-bogus-class", CompanyManaged: true},  // bad class
			{RootRef: "managed_root:88888888-8888-8888-8888-888888888888", LocalPath: good, PathClass: "managed/it-folder", CompanyManaged: true},   // valid
		},
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	// Only the valid root is echoed + walked.
	if len(m.Scope.ManagedDataRoots) != 1 || m.Scope.ManagedDataRoots[0] != "managed_root:88888888-8888-8888-8888-888888888888" {
		t.Errorf("only the valid root should be echoed, got %v", m.Scope.ManagedDataRoots)
	}
	if m.Aggregate.TotalEligibleCount != 1 {
		t.Errorf("only good/a.docx eligible (2 bad roots dropped), got %d", m.Aggregate.TotalEligibleCount)
	}
	if m.Aggregate.UnresolvedPathCount < 2 {
		t.Errorf("two invalid roots should be counted unresolved, got %d", m.Aggregate.UnresolvedPathCount)
	}
	// The path-shaped ref must NOT appear anywhere in the manifest JSON.
	raw, _ := json.Marshal(m)
	for _, needle := range []string{`C:\Users\Alice`, "Alice", "Secret", "totally-bogus-class"} {
		if strings.Contains(string(raw), needle) {
			t.Errorf("invalid root field %q leaked into manifest", needle)
		}
	}
}

func contains(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}
