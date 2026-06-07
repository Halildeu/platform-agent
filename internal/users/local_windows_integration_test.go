//go:build windows

package users

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestMutateLocalWindowsIntegration(t *testing.T) {
	if os.Getenv("ENDPOINT_AGENT_LOCAL_USER_MUTATION_TEST") != "1" {
		t.Skip("set ENDPOINT_AGENT_LOCAL_USER_MUTATION_TEST=1 on a disposable Windows lab account")
	}
	username := strings.TrimSpace(os.Getenv("ENDPOINT_AGENT_LOCAL_USER_TEST_NAME"))
	newPassword := os.Getenv("ENDPOINT_AGENT_LOCAL_USER_TEST_PASSWORD")
	if username == "" || newPassword == "" {
		t.Fatal("ENDPOINT_AGENT_LOCAL_USER_TEST_NAME and ENDPOINT_AGENT_LOCAL_USER_TEST_PASSWORD are required")
	}
	if !strings.HasPrefix(strings.ToLower(username), "ea-") &&
		!strings.HasPrefix(strings.ToLower(username), "endpointagenttest") {
		t.Fatalf("refusing to mutate non-lab local account %q; use ea-* or EndpointAgentTest* prefix", username)
	}

	before := findLocalUserForTest(t, username)
	if before.Disabled {
		t.Fatalf("lab account %q must start enabled so the test can restore enabled state", username)
	}

	locked, err := MutateLocal(LocalUserMutationRequest{
		Action:   ActionLockUserLogin,
		Username: username,
	})
	if err != nil {
		t.Fatalf("lock local user: %v", err)
	}
	if locked.Disabled == nil || !*locked.Disabled {
		t.Fatalf("lock result Disabled=%v, want true", locked.Disabled)
	}
	afterLock := findLocalUserForTest(t, username)
	if !afterLock.Disabled {
		t.Fatalf("account %q is not disabled after lock action", username)
	}

	unlocked, err := MutateLocal(LocalUserMutationRequest{
		Action:   ActionUnlockUserLogin,
		Username: username,
	})
	if err != nil {
		t.Fatalf("unlock local user: %v", err)
	}
	if unlocked.Disabled == nil || *unlocked.Disabled {
		t.Fatalf("unlock result Disabled=%v, want false", unlocked.Disabled)
	}
	afterUnlock := findLocalUserForTest(t, username)
	if afterUnlock.Disabled {
		t.Fatalf("account %q is still disabled after unlock action", username)
	}

	changed, err := MutateLocal(LocalUserMutationRequest{
		Action:      ActionChangeLocalPassword,
		Username:    username,
		NewPassword: newPassword,
	})
	if err != nil {
		t.Fatalf("change local password: %v", err)
	}
	if !changed.PasswordChanged {
		t.Fatal("password result PasswordChanged=false, want true")
	}
	wire, err := json.Marshal(changed)
	if err != nil {
		t.Fatalf("marshal password result: %v", err)
	}
	if strings.Contains(string(wire), newPassword) {
		t.Fatal("password result leaked the new password")
	}
}

func findLocalUserForTest(t *testing.T, username string) LocalUserSnapshot {
	t.Helper()
	users, err := ListLocal()
	if err != nil {
		t.Fatalf("list local users: %v", err)
	}
	for _, user := range users {
		if strings.EqualFold(user.Username, username) {
			return user
		}
	}
	t.Fatalf("local lab account %q not found", username)
	return LocalUserSnapshot{}
}
