package screenview

import (
	"errors"
	"strings"
	"testing"

	"platform-agent/internal/remotebridge/dataplane"
	"platform-agent/internal/security"
)

func TestAcceptanceModeEnabledIsExactAndDefaultOff(t *testing.T) {
	for _, tc := range []struct {
		value string
		want  bool
	}{
		{"", false}, {"true", false}, {"production", false}, {"TEST", false}, {" test", false}, {"test ", false}, {"test", true},
	} {
		t.Run(tc.value, func(t *testing.T) {
			t.Setenv(AcceptanceModeEnv, tc.value)
			if got := AcceptanceModeEnabled(); got != tc.want {
				t.Fatalf("AcceptanceModeEnabled() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestAcceptanceWindowBindingIsSessionBoundAndOpaque(t *testing.T) {
	a, err := AcceptanceWindowBinding("sess-1")
	if err != nil {
		t.Fatal(err)
	}
	b, err := AcceptanceWindowBinding("sess-2")
	if err != nil {
		t.Fatal(err)
	}
	if a == b || len(a) != 64 || strings.Contains(a, "sess") {
		t.Fatalf("bindings must be distinct opaque SHA-256 values: a=%q b=%q", a, b)
	}
}

func TestAcceptanceWindowBindingRejectsUnsafeOrStaleInput(t *testing.T) {
	for _, sessionID := range []string{"", " sess-1", "sess-1 ", "sess/1", "sess\n1", "oturum-\xff", strings.Repeat("a", 257)} {
		if _, err := AcceptanceWindowBinding(sessionID); !errors.Is(err, ErrAcceptanceSessionID) {
			t.Fatalf("session %q: err=%v, want ErrAcceptanceSessionID", sessionID, err)
		}
	}
}

func TestAcceptanceWindowBindingMatchesBackendWireIDAlphabet(t *testing.T) {
	if _, err := AcceptanceWindowBinding("session.user@example+pilot=test:1"); err != nil {
		t.Fatalf("backend-valid wire id was rejected: %v", err)
	}
}

func TestValidAcceptanceWindowBindingRejectsNonCanonicalValues(t *testing.T) {
	binding, err := AcceptanceWindowBinding("sess-1")
	if err != nil {
		t.Fatal(err)
	}
	if !validAcceptanceWindowBinding(binding) {
		t.Fatal("canonical binding was rejected")
	}
	for _, value := range []string{"", binding[:63], strings.ToUpper(binding), strings.Repeat("z", 64)} {
		if validAcceptanceWindowBinding(value) {
			t.Fatalf("non-canonical binding accepted: %q", value)
		}
	}
}

func TestIndicatorLossAcceptanceGuardsAndExactBinding(t *testing.T) {
	const sessionID = "sess-acceptance-1"
	const token = "test-maintenance-token"
	hash := security.MaintenanceTokenHash(token)

	t.Setenv(AcceptanceModeEnv, "")
	if err := triggerIndicatorLossAcceptance(sessionID, token, hash, acceptanceModeTest, acceptanceTriggerDeps{}); !errors.Is(err, ErrAcceptanceModeDisabled) {
		t.Fatalf("default-off err=%v", err)
	}

	t.Setenv(AcceptanceModeEnv, acceptanceModeTest)
	if err := triggerIndicatorLossAcceptance(sessionID, token, hash, "", acceptanceTriggerDeps{}); !errors.Is(err, ErrAcceptanceProtectedMode) {
		t.Fatalf("missing protected test mode err=%v", err)
	}
	authorizedHost := acceptanceTriggerDeps{isElevated: func() bool { return true }}
	if err := triggerIndicatorLossAcceptance(sessionID, token, "", acceptanceModeTest, authorizedHost); !errors.Is(err, security.ErrMaintenanceTokenRequired) {
		t.Fatalf("unconfigured token hash err=%v", err)
	}
	if err := triggerIndicatorLossAcceptance(sessionID, "wrong", hash, acceptanceModeTest, authorizedHost); !errors.Is(err, security.ErrMaintenanceTokenRequired) {
		t.Fatalf("wrong token err=%v", err)
	}
	if err := triggerIndicatorLossAcceptance(sessionID, token, hash, acceptanceModeTest, acceptanceTriggerDeps{
		isElevated: func() bool { return false },
	}); !errors.Is(err, ErrAcceptanceAdminRequired) {
		t.Fatalf("non-admin err=%v", err)
	}

	wantBinding, _ := AcceptanceWindowBinding(sessionID)
	var gotBinding string
	err := triggerIndicatorLossAcceptance(sessionID, token, hash, acceptanceModeTest, acceptanceTriggerDeps{
		isElevated: func() bool { return true },
		trigger: func(binding string) error {
			gotBinding = binding
			return nil
		},
	})
	if err != nil || gotBinding != wantBinding {
		t.Fatalf("authorized trigger err=%v binding=%q want=%q", err, gotBinding, wantBinding)
	}
}

func TestIndicatorLossAcceptanceErrorsNeverEchoMaintenanceToken(t *testing.T) {
	const recognizableToken = "DO-NOT-LOG-THIS-TEST-TOKEN"
	t.Setenv(AcceptanceModeEnv, acceptanceModeTest)
	hash := security.MaintenanceTokenHash("different-token")
	err := triggerIndicatorLossAcceptance("sess-1", recognizableToken, hash, acceptanceModeTest, acceptanceTriggerDeps{
		isElevated: func() bool { return true },
	})
	if err == nil || strings.Contains(err.Error(), recognizableToken) {
		t.Fatalf("error must refuse without echoing token: %v", err)
	}
}

func TestIndicatorLossAcceptanceWrongSessionAndNoBannerFailClosed(t *testing.T) {
	const token = "test-maintenance-token"
	hash := security.MaintenanceTokenHash(token)
	t.Setenv(AcceptanceModeEnv, acceptanceModeTest)
	deps := acceptanceTriggerDeps{
		isElevated: func() bool { return true },
		trigger:    func(string) error { return dataplane.ErrBannerNotFound },
	}
	if err := triggerIndicatorLossAcceptance("wrong/session", token, hash, acceptanceModeTest, deps); !errors.Is(err, ErrAcceptanceSessionID) {
		t.Fatalf("wrong-session syntax err=%v", err)
	}
	if err := triggerIndicatorLossAcceptance("stale-session", token, hash, acceptanceModeTest, deps); !errors.Is(err, dataplane.ErrBannerNotFound) {
		t.Fatalf("no-banner err=%v", err)
	}
	triggerFailure := acceptanceTriggerDeps{
		isElevated: func() bool { return true },
		trigger:    func(string) error { return dataplane.ErrBannerTrigger },
	}
	err := triggerIndicatorLossAcceptance("sess-private", token, hash, acceptanceModeTest, triggerFailure)
	if !errors.Is(err, dataplane.ErrBannerTrigger) || strings.Contains(err.Error(), "sess-private") {
		t.Fatalf("trigger failure must stay typed and omit raw session id: %v", err)
	}
}
