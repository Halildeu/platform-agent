//go:build windows

package inventory

import (
	"errors"
	"testing"

	"golang.org/x/sys/windows"
)

// AG-039 fix regression guards. The cross-platform services_test.go covers
// the pure projection (sort / ProbeComplete / wire shape); these
// windows-tagged tests cover the Win32 access-right surface that the bug
// lived in. They run on the CI windows-latest runner via `go test ./...`
// (Job 3 windows-go-test in ci-build-test.yml).

// TestServicesQueryAccessMaskIsMinimal pins the per-service SCM access mask
// as exactly the two read-only query rights. A regression back to
// mgr.Mgr.OpenService (which hard-codes SERVICE_ALL_ACCESS) — or anyone
// widening the mask to include a write/control right — re-breaks
// WinDefend/MpsSvc on their protected-service DACLs. This test is fully
// deterministic (no SCM dependency) so it is the authoritative guard.
func TestServicesQueryAccessMaskIsMinimal(t *testing.T) {
	const want = windows.SERVICE_QUERY_STATUS | windows.SERVICE_QUERY_CONFIG
	if servicesQueryAccess != want {
		t.Fatalf("servicesQueryAccess = %#x; want %#x (SERVICE_QUERY_STATUS|SERVICE_QUERY_CONFIG)",
			servicesQueryAccess, want)
	}
	if servicesQueryAccess == windows.SERVICE_ALL_ACCESS {
		t.Fatal("servicesQueryAccess collapsed into SERVICE_ALL_ACCESS — AG-039 regression")
	}

	// No write/control bit may be present — these are the rights a hardened
	// service DACL denies and which the probe never needs.
	writeControl := uint32(windows.SERVICE_CHANGE_CONFIG |
		windows.SERVICE_STOP |
		windows.SERVICE_START |
		windows.SERVICE_PAUSE_CONTINUE |
		windows.DELETE |
		windows.WRITE_DAC |
		windows.WRITE_OWNER)
	if leaked := uint32(servicesQueryAccess) & writeControl; leaked != 0 {
		t.Errorf("servicesQueryAccess %#x contains forbidden write/control bits %#x",
			servicesQueryAccess, leaked)
	}

	// Both read bits the probe depends on must be present.
	if servicesQueryAccess&windows.SERVICE_QUERY_STATUS == 0 {
		t.Error("servicesQueryAccess missing SERVICE_QUERY_STATUS — run-state unreadable")
	}
	if servicesQueryAccess&windows.SERVICE_QUERY_CONFIG == 0 {
		t.Error("servicesQueryAccess missing SERVICE_QUERY_CONFIG — DISABLED startup-mode unreadable")
	}
}

// TestScmConnectAccessIsLeastPrivilege pins the SCM-manager handle to the
// minimal SC_MANAGER_CONNECT (mgr.Connect would request SC_MANAGER_ALL_ACCESS).
func TestScmConnectAccessIsLeastPrivilege(t *testing.T) {
	if scmConnectAccess != windows.SC_MANAGER_CONNECT {
		t.Fatalf("scmConnectAccess = %#x; want SC_MANAGER_CONNECT %#x",
			scmConnectAccess, windows.SC_MANAGER_CONNECT)
	}
	if scmConnectAccess == windows.SC_MANAGER_ALL_ACCESS {
		t.Fatal("scmConnectAccess collapsed into SC_MANAGER_ALL_ACCESS — least-privilege regression")
	}
}

// TestProbeOneServiceProtectedServicesQueryable is the live-SCM evidence
// test. WinDefend (Defender) and MpsSvc (Firewall) carry hardened DACLs that
// deny the write/control rights in SERVICE_ALL_ACCESS even to an elevated
// token; with the query-only mask they must open AND complete Config()+Query()
// without a per-service probe error.
//
// It drives the full probeOneService path (open + Config + Query) rather than
// a bare OpenService, so the extra QueryServiceConfig2 calls inside
// service.Config() are exercised too (Codex 019e950c iter-1 #6 absorb).
//
// Environment tolerance (no CI flake; the authoritative regression guard is
// the deterministic mask test above): a service that is genuinely absent from
// the SCM, or an ACCESS_DENIED that reflects a non-elevated/locked-down runner
// token rather than the bug, is a SKIP — never a FAIL. The real protected-DACL
// acceptance happens on the live Windows 11 VM (Codex 019e950c iter-1 #7:
// windows-latest server-runner behavior is not a substitute for VM smoke).
func TestProbeOneServiceProtectedServicesQueryable(t *testing.T) {
	scm, err := connectSCMReadOnly()
	if err != nil {
		t.Skipf("SC_MANAGER_CONNECT failed (runner not elevated?): %v", err)
	}
	defer scm.Disconnect()

	for _, name := range []string{"WinDefend", "MpsSvc"} {
		t.Run(name, func(t *testing.T) {
			// Existence/permission pre-check so absent or env-denied is a skip.
			h, openErr := openServiceQueryOnly(scm, name)
			if openErr != nil {
				switch {
				case isServiceNotFound(openErr):
					t.Skipf("%s not installed on this runner — skipping", name)
				case errors.Is(openErr, windows.ERROR_ACCESS_DENIED):
					t.Skipf("%s open ACCESS_DENIED on this runner (env token, not the mask) — "+
						"live VM smoke is the protected-DACL acceptance: %v", name, openErr)
				default:
					t.Fatalf("%s open failed unexpectedly: %v", name, openErr)
				}
				return
			}
			h.Close()

			// Open succeeded → the full read path MUST complete with no
			// per-service error. A failure here means the query-only mask is
			// insufficient for Config()/Query() (a real fix defect), which is
			// deterministic given the open succeeded. perErr==nil already
			// proves BOTH service.Query() and service.Config() returned
			// without error (probeOneService only emits on a Config/Query
			// failure), so it is the authoritative success signal.
			entry, perErr := probeOneService(scm, name)
			if perErr != nil {
				t.Fatalf("%s probeOneService emitted %s (%q) despite a successful open — "+
					"query-only mask insufficient for Config()/Query()",
					name, perErr.Code, perErr.Summary)
			}
			if !entry.Present {
				t.Errorf("%s expected Present=true after successful open", name)
			}
			// State/StartupMode concrete values are logged, NOT asserted: a
			// service caught mid paused/pending transition maps to UNKNOWN
			// run-state, and an unusual StartType (boot/system) maps to
			// UNKNOWN startup-mode, even though Query()/Config() succeeded.
			// Asserting concrete values here would add an environment-timing
			// flake with no extra proof of the fix (Codex 019e950c iter-2
			// non-blocking note absorb).
			t.Logf("%s queried OK with query-only mask: state=%s startupMode=%s",
				name, entry.State, entry.StartupMode)
		})
	}
}
