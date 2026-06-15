package dataplane

import (
	"strings"
	"testing"
)

func TestRandomPipeNameFormatAndUnique(t *testing.T) {
	a, err := RandomPipeName()
	if err != nil {
		t.Fatalf("pipe name: %v", err)
	}
	if !strings.HasPrefix(a, `\\.\pipe\dpcap-`) {
		t.Fatalf("pipe name %q missing expected prefix", a)
	}
	if len(strings.TrimPrefix(a, `\\.\pipe\dpcap-`)) != 32 { // 16 bytes hex
		t.Fatalf("pipe name %q has unexpected random length", a)
	}
	b, _ := RandomPipeName()
	if a == b {
		t.Fatal("two pipe names identical — not random")
	}
}

func TestPipeSDDLRestrictsToSystemAndUser(t *testing.T) {
	sd := pipeSDDL("S-1-5-21-1-2-3-1105")
	// protected DACL, SYSTEM + the user, no world/Everyone (WD) ACE.
	if !strings.HasPrefix(sd, "D:P") {
		t.Fatalf("SDDL %q must be a protected DACL (D:P...)", sd)
	}
	if !strings.Contains(sd, "(A;;GA;;;SY)") {
		t.Fatalf("SDDL %q must grant SYSTEM", sd)
	}
	if !strings.Contains(sd, "(A;;GA;;;S-1-5-21-1-2-3-1105)") {
		t.Fatalf("SDDL %q must grant the target user SID", sd)
	}
	if strings.Contains(sd, ";WD)") || strings.Contains(sd, ";AU)") {
		t.Fatalf("SDDL %q must NOT grant Everyone/AuthenticatedUsers", sd)
	}
}
