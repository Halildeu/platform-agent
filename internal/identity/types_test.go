package identity

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestClassifyWorkgroupLocal(t *testing.T) {
	got := Classify(JoinSignals{
		PartOfDomain:    false,
		Workgroup:       "WORKGROUP",
		AzureAdJoined:   "NO",
		DomainJoined:    "NO",
		WorkplaceJoined: "NO",
	})
	if got != ClassificationLocal {
		t.Fatalf("classification = %s, want %s", got, ClassificationLocal)
	}
}

func TestClassifyDomainTakesPrecedence(t *testing.T) {
	got := Classify(JoinSignals{
		PartOfDomain:    true,
		Domain:          "acik.local",
		AzureAdJoined:   "YES",
		DomainJoined:    "YES",
		WorkplaceJoined: "NO",
	})
	if got != ClassificationDomain {
		t.Fatalf("classification = %s, want %s", got, ClassificationDomain)
	}
}

func TestClassifyEntraAndWorkplace(t *testing.T) {
	if got := Classify(JoinSignals{AzureAdJoined: "YES"}); got != ClassificationEntra {
		t.Fatalf("entra classification = %s, want %s", got, ClassificationEntra)
	}
	if got := Classify(JoinSignals{WorkplaceJoined: "YES"}); got != ClassificationWorkplace {
		t.Fatalf("workplace classification = %s, want %s", got, ClassificationWorkplace)
	}
}

func TestLoggedInIdentitySanitizesRawIdentifiers(t *testing.T) {
	identity := BuildLoggedInIdentity(`ACIK\halil.kocoglu`, "halil.kocoglu@example.com", "S-1-5-21-1111111111-2222222222-3333333333-1001")
	payload, err := json.Marshal(identity)
	if err != nil {
		t.Fatal(err)
	}
	body := string(payload)
	for _, forbidden := range []string{"halil.kocoglu", "example.com", "1111111111-2222222222-3333333333"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("sanitized identity leaked %q in %s", forbidden, body)
		}
	}
	if !strings.Contains(body, "S-1-5-21-***-***-***-1001") {
		t.Fatalf("SID mask missing from %s", body)
	}
	if !strings.Contains(body, "sha256:") {
		t.Fatalf("hash marker missing from %s", body)
	}
}

func TestInventorySanitizesTenantAndDeviceIdentifiers(t *testing.T) {
	reachable := true
	inv := Inventory{
		DomainReachable: &reachable,
		DomainProbe:     "PASS",
		TenantIDHash:    HashIdentifier("11111111-2222-3333-4444-555555555555"),
		DeviceIDHash:    HashIdentifier("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"),
		DeviceNameHash:  HashIdentifier("HALILKOOLUB735"),
		LoggedIn: BuildLoggedInIdentity(
			`HALILKOOLUB735\halilkocoglu`,
			"halilkocoglu@example.com",
			"S-1-5-21-1111111111-2222222222-3333333333-1001",
		),
	}
	payload, err := json.Marshal(inv)
	if err != nil {
		t.Fatal(err)
	}
	body := string(payload)
	for _, forbidden := range []string{
		"11111111-2222-3333-4444-555555555555",
		"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
		"halilkocoglu@example.com",
		"1111111111-2222222222-3333333333",
	} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("inventory leaked raw identifier %q in %s", forbidden, body)
		}
	}
}
