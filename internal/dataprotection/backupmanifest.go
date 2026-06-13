// Package dataprotection implements the Faz 22.8A endpoint backup dry-run
// manifest generator (gitops docs/faz-22-8a-backup-manifest-contract-v1.md,
// Codex 019ea961 AGREE + 019ec28a P0 amendment).
//
// CONTRACT INVARIANTS (machine-enforced by backupmanifest_guard_test.go):
//
//   1. METADATA-ONLY. This package MUST NOT read file content and MUST NOT
//      compute any content hash. It uses directory listing (os.ReadDir) and
//      file metadata (fs.DirEntry.Info → size/mtime/mode) ONLY. The guard
//      test forbids importing crypto/*, hash/*, io, bufio and forbids
//      os.Open/os.ReadFile/os.OpenFile/io.ReadAll. The Windows canonicalizer
//      opens a metadata handle with FILE_READ_ATTRIBUTES only (no read
//      access), also asserted by the guard test.
//
//   2. DC-EA-RED → denied-aggregate, NEVER an entry. credential / browser
//      profile / mailbox cache / private-key / cloud-cli token / password
//      manager / DPAPI / registry hive / app-token / archive-container are
//      counted in Aggregate (denied_count + denied_classes [+ container_count
//      for archives]) and their paths are never listed.
//
//   3. CANONICALIZE → CONTAIN → DENY *before* descent. Each child is
//      canonicalized (symlink/junction/reparse/UNC/ADS resolved), checked for
//      segment-boundary containment in the managed root, and classified
//      against the hardcoded denylist BEFORE the walker decides to descend.
//      Reparse-point directories are never descended in 22.8A.1.
//
//   4. PATH-FREE diagnostics. No raw filesystem path is ever placed in the
//      manifest, in returned errors, or in any structured result. Failures are
//      reported as path-free counters (unresolved_path_count) or path-free
//      error codes.
//
//   5. DISABLED-BY-DEFAULT. The COLLECT_BACKUP_DRYRUN capability is opt-in
//      (RuntimeCapabilityOptions.EnableBackupDryRun) and advertised only on a
//      policy-ready Windows build (AG-013 coherence).
package dataprotection

import (
	"errors"
	"io/fs"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// ManifestVersion / DCEATier are pinned by the contract.
const (
	ManifestVersion = "1"
	DCEATier        = "DC-EA-1"
)

// Path-free error codes (invariant #4 — never embed a raw path).
var (
	// ErrNoCanonicalizer is returned when Generate is called without a
	// platform canonicalizer wired (fail-closed; we never fall back to a
	// raw, un-canonicalized walk).
	ErrNoCanonicalizer = errors.New("BACKUP_DRYRUN_NO_CANONICALIZER")
	// ErrNoManagedRoots is returned when no allowlisted managed root is
	// supplied. A dry run over the whole filesystem is forbidden.
	ErrNoManagedRoots = errors.New("BACKUP_DRYRUN_NO_MANAGED_ROOTS")
	// ErrManifestFailed is the generic path-free failure wrapper.
	ErrManifestFailed = errors.New("BACKUP_DRYRUN_MANIFEST_FAILED")
)

// Canonicalizer resolves a local path to its canonical form and reports the
// two bypass vectors the walker must fail-closed on. Implementations live in
// backupmanifest_windows.go (GetFinalPathNameByHandleW, metadata handle only)
// and backupmanifest_other.go (EvalSymlinks fallback for dev/test).
//
// Implementations MUST NOT open the file for reading — metadata/attribute
// access only (invariant #1).
type Canonicalizer interface {
	// Canonicalize returns the canonical absolute path of localPath.
	// isReparse is true when localPath is itself a reparse point
	// (symlink/junction/mount) — the walker never descends these in
	// 22.8A.1. hasADS is true when the resolved name carries an NTFS
	// alternate data stream (':' beyond the drive designator) — a RED-
	// hiding vector that is failed-closed. err is path-free.
	Canonicalize(localPath string) (canonical string, isReparse bool, hasADS bool, err error)
}

// ManagedRoot is one allowlisted, company-managed data root. The agent only
// ever walks inside these. RootRef is the opaque registry id surfaced in the
// manifest; the raw LocalPath is never emitted.
type ManagedRoot struct {
	// RootRef is the opaque "managed_root:<uuid>" reference (contract §2).
	RootRef string
	// LocalPath is the on-disk root (canonicalized internally before use).
	LocalPath string
	// PathClass is the normalized class (managed/onedrive-business, ...).
	PathClass string
	// CompanyManaged true → owner_scope_marker "company"; false → "unknown".
	CompanyManaged bool
}

// Options configures one dry-run manifest generation.
type Options struct {
	DeviceID           string
	TenantID           string
	AllowlistProfileID string
	BYOD               bool
	Roots              []ManagedRoot
	// Now is the generation clock (injectable for deterministic tests).
	Now time.Time
	// Canon is the platform canonicalizer (required, fail-closed).
	Canon Canonicalizer
	// MaxDepth bounds recursion defensively (0 → DefaultMaxDepth).
	MaxDepth int
}

// DefaultMaxDepth bounds the walk if Options.MaxDepth is unset.
const DefaultMaxDepth = 64

// Manifest is the contract v1 metadata-only dry-run artifact.
type Manifest struct {
	ManifestVersion    string    `json:"manifest_version"`
	DCEATier           string    `json:"dc_ea_tier"`
	DeviceID           string    `json:"device_id"`
	TenantID           string    `json:"tenant_id"`
	GeneratedAt        string    `json:"generated_at"`
	AllowlistProfileID string    `json:"allowlist_profile_id"`
	Scope              Scope     `json:"scope"`
	Entries            []Entry   `json:"entries"`
	Aggregate          Aggregate `json:"aggregate"`
}

// Scope is the manifest scope block — opaque root refs only.
type Scope struct {
	ManagedDataRoots []string `json:"managed_data_roots"`
	BYOD             bool     `json:"byod"`
}

// Entry is one eligible (non-denied) file. Metadata only — no raw path.
type Entry struct {
	PathClass        string `json:"path_class"`
	RootRef          string `json:"root_ref"`
	RelativeDepth    int    `json:"relative_depth"`
	ExtensionType    string `json:"extension_type"`
	SizeBytes        int64  `json:"size_bytes"`
	MtimeBucket      string `json:"mtime_bucket"`
	OwnerScopeMarker string `json:"owner_scope_marker"`
	FileCount        int    `json:"file_count"`
}

// Aggregate carries the denied-only counts (DC-EA-RED never appears as an
// entry — invariant #2).
type Aggregate struct {
	TotalEligibleCount     int      `json:"total_eligible_count"`
	TotalEligibleSizeBytes int64    `json:"total_eligible_size_bytes"`
	DeniedCount            int      `json:"denied_count"`
	DeniedClasses          []string `json:"denied_classes"`
	ContainerCount         int      `json:"container_count"`
	UnresolvedPathCount    int      `json:"unresolved_path_count"`
}

// owner_scope_marker values (contract §2).
const (
	ownerCompany = "company"
	ownerUnknown = "unknown"
)

// mtime buckets (contract §2 — coarse, no exact timestamp).
const (
	bucketP7D   = "P7D"
	bucketP30D  = "P30D"
	bucketP90D  = "P90D"
	bucketOlder = "older"
)

// extension_type enum (contract §2 — archive intentionally ABSENT; archives
// are DC-EA-RED denied-aggregate, never an entry).
const (
	extDoc   = "doc"
	extSheet = "sheet"
	extPDF   = "pdf"
	extImage = "image"
	extOther = "other"
)

// generator holds mutable walk state.
type generator struct {
	opts      Options
	entries   []Entry
	agg       Aggregate
	deniedSet map[string]bool
}

// Generate produces the metadata-only dry-run manifest. It never reads file
// content and never emits a raw path (invariants #1, #4). It is the caller's
// responsibility to have gated this behind the disabled-by-default capability.
func Generate(opts Options) (Manifest, error) {
	if opts.Canon == nil {
		return Manifest{}, ErrNoCanonicalizer
	}
	if len(opts.Roots) == 0 {
		return Manifest{}, ErrNoManagedRoots
	}
	if opts.MaxDepth <= 0 {
		opts.MaxDepth = DefaultMaxDepth
	}

	g := &generator{opts: opts, deniedSet: map[string]bool{}}

	rootRefs := make([]string, 0, len(opts.Roots))
	for _, root := range opts.Roots {
		rootRefs = append(rootRefs, root.RootRef)
		// Canonicalize the root itself; if it cannot be resolved or is a
		// reparse point, we fail-closed (count, do not walk).
		canonRoot, isReparse, hasADS, err := opts.Canon.Canonicalize(root.LocalPath)
		if err != nil || hasADS || isReparse {
			g.agg.UnresolvedPathCount++
			continue
		}
		// Defense-in-depth (Codex 019ec28a — do not raw-trust the backend
		// root payload): a supplied root that canonically resolves to a
		// DC-EA-RED class (e.g. someone allowlisted "...\.ssh") is refused
		// and counted as denied, never walked.
		if class, denied, archive := classifyDenied(canonRoot, filepath.Base(canonRoot)); denied {
			g.recordDenied(class, archive)
			continue
		}
		g.walk(canonRoot, canonRoot, root, 0)
	}

	g.agg.DeniedClasses = sortedKeys(g.deniedSet)

	m := Manifest{
		ManifestVersion:    ManifestVersion,
		DCEATier:           DCEATier,
		DeviceID:           opts.DeviceID,
		TenantID:           opts.TenantID,
		GeneratedAt:        opts.Now.UTC().Format(time.RFC3339),
		AllowlistProfileID: opts.AllowlistProfileID,
		Scope:              Scope{ManagedDataRoots: rootRefs, BYOD: opts.BYOD},
		Entries:            g.entries,
		Aggregate:          g.agg,
	}
	if m.Entries == nil {
		m.Entries = []Entry{}
	}
	if m.Aggregate.DeniedClasses == nil {
		m.Aggregate.DeniedClasses = []string{}
	}
	return m, nil
}

// walk recurses with canonicalize→contain→deny BEFORE descent. localCanon is
// the canonical path of the current directory; rootCanon is the canonical
// managed-root path used for segment-boundary containment.
func (g *generator) walk(localCanon, rootCanon string, root ManagedRoot, depth int) {
	if depth > g.opts.MaxDepth {
		g.agg.UnresolvedPathCount++
		return
	}
	children, err := readDirNames(localCanon)
	if err != nil {
		// Path-free: a directory we cannot list is counted, not surfaced.
		g.agg.UnresolvedPathCount++
		return
	}
	for _, name := range children {
		child := filepath.Join(localCanon, name)
		canon, isReparse, hasADS, cerr := g.opts.Canon.Canonicalize(child)
		if cerr != nil {
			g.agg.UnresolvedPathCount++
			continue
		}
		// ADS is a RED-hiding vector — fail-closed (count, never descend/emit).
		if hasADS || hasADSName(name) {
			g.agg.UnresolvedPathCount++
			continue
		}
		// Segment-boundary containment: a canonical target that escaped the
		// managed root (junction/symlink to elsewhere) is dropped.
		if !withinRoot(canon, rootCanon) {
			g.agg.UnresolvedPathCount++
			continue
		}

		info, ierr := lstatInfo(canon)
		if ierr != nil {
			g.agg.UnresolvedPathCount++
			continue
		}

		// DENY decision happens BEFORE any descent (invariant #3).
		class, denied, archive := classifyDenied(canon, name)
		if denied {
			g.recordDenied(class, archive)
			continue // never descend a denied dir; never emit a denied file
		}

		if info.IsDir() {
			if isReparse {
				// Do not descend reparse points in 22.8A.1.
				g.agg.UnresolvedPathCount++
				continue
			}
			g.walk(canon, rootCanon, root, depth+1)
			continue
		}

		// Eligible file → metadata-only entry (no content access).
		g.entries = append(g.entries, Entry{
			PathClass:        root.PathClass,
			RootRef:          root.RootRef,
			RelativeDepth:    depth + 1,
			ExtensionType:    classifyExtension(name),
			SizeBytes:        info.Size(),
			MtimeBucket:      mtimeBucket(g.opts.Now, info.ModTime()),
			OwnerScopeMarker: ownerScope(root),
			FileCount:        1,
		})
		g.agg.TotalEligibleCount++
		g.agg.TotalEligibleSizeBytes += info.Size()
	}
}

// recordDenied books a DC-EA-RED hit. denied_count increments exactly once per
// object; archive predicate additionally bumps container_count and adds the
// archive_container class (the pst/ost dual-match dedup — contract §3 + Codex
// 019ec28a).
func (g *generator) recordDenied(class string, archive bool) {
	g.agg.DeniedCount++
	if class != "" {
		g.deniedSet[class] = true
	}
	if archive {
		g.agg.ContainerCount++
		g.deniedSet[classArchiveContainer] = true
	}
}

func ownerScope(root ManagedRoot) string {
	if root.CompanyManaged {
		return ownerCompany
	}
	return ownerUnknown
}

// withinRoot is segment-boundary aware so C:\Managed does not match
// C:\Managed2 (Codex prefix-trap guard). Comparison is case-insensitive
// because the Windows canonicalizer returns a canonical-cased VOLUME_NAME_DOS
// path and we normalize both sides.
func withinRoot(canon, root string) bool {
	c := normalizeForCompare(canon)
	r := normalizeForCompare(root)
	if c == r {
		return true
	}
	sep := string(filepath.Separator)
	if !strings.HasSuffix(r, sep) {
		r += sep
	}
	return strings.HasPrefix(c, r)
}

func normalizeForCompare(p string) string {
	return strings.ToLower(filepath.Clean(p))
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// mtimeBucket maps a mod time to a coarse age bucket (no exact timestamp).
func mtimeBucket(now, mod time.Time) string {
	age := now.Sub(mod)
	switch {
	case age <= 7*24*time.Hour:
		return bucketP7D
	case age <= 30*24*time.Hour:
		return bucketP30D
	case age <= 90*24*time.Hour:
		return bucketP90D
	default:
		return bucketOlder
	}
}

// classifyExtension maps a filename to the coarse extension_type enum. Archive
// extensions never reach this function (they are denied upstream); if one
// somehow does, it maps to extOther (defensive — still not "archive").
func classifyExtension(name string) string {
	switch strings.ToLower(filepath.Ext(name)) {
	case ".doc", ".docx", ".odt", ".rtf", ".txt", ".md":
		return extDoc
	case ".xls", ".xlsx", ".ods", ".csv", ".tsv":
		return extSheet
	case ".pdf":
		return extPDF
	case ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tif", ".tiff", ".heic", ".webp":
		return extImage
	default:
		return extOther
	}
}

// fileInfo is the minimal metadata surface the walker needs. It is satisfied
// by fs.FileInfo. Declaring it locally keeps the content-read guard test's
// import allowlist tight.
type fileInfo interface {
	IsDir() bool
	Size() int64
	ModTime() time.Time
	Mode() fs.FileMode
}
