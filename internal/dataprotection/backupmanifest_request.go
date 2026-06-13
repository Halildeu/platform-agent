package dataprotection

import "time"

// Request is the COLLECT_BACKUP_DRYRUN command payload (wire shape). The
// backend supplies a BOUNDED allowlist of company-managed roots (contract §4);
// the agent re-verifies every path (canonicalize → contain → deny) and never
// trusts the payload blindly.
type Request struct {
	DeviceID           string     `json:"device_id"`
	TenantID           string     `json:"tenant_id"`
	AllowlistProfileID string     `json:"allowlist_profile_id"`
	BYOD               bool       `json:"byod"`
	Roots              []RootSpec `json:"roots"`
}

// RootSpec is one allowlisted managed root in the request payload.
type RootSpec struct {
	// RootRef is the opaque "managed_root:<uuid>" registry reference echoed
	// into the manifest (raw LocalPath is never emitted).
	RootRef string `json:"root_ref"`
	// LocalPath is the on-disk root the agent canonicalizes + walks.
	LocalPath string `json:"local_path"`
	// PathClass is the normalized class for emitted entries.
	PathClass string `json:"path_class"`
	// CompanyManaged drives owner_scope_marker (company vs unknown).
	CompanyManaged bool `json:"company_managed"`
}

// GenerateFromRequest maps a wire Request to Options and produces the manifest.
// now is the generation clock; canon is the platform canonicalizer.
func GenerateFromRequest(req Request, now time.Time, canon Canonicalizer) (Manifest, error) {
	roots := make([]ManagedRoot, 0, len(req.Roots))
	for _, r := range req.Roots {
		roots = append(roots, ManagedRoot{
			RootRef:        r.RootRef,
			LocalPath:      r.LocalPath,
			PathClass:      r.PathClass,
			CompanyManaged: r.CompanyManaged,
		})
	}
	return Generate(Options{
		DeviceID:           req.DeviceID,
		TenantID:           req.TenantID,
		AllowlistProfileID: req.AllowlistProfileID,
		BYOD:               req.BYOD,
		Roots:              roots,
		Now:                now,
		Canon:              canon,
	})
}
