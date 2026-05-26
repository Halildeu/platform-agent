package identity

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strings"
	"time"
)

type Classification string

const (
	ClassificationLocal     Classification = "LOCAL"
	ClassificationDomain    Classification = "DOMAIN"
	ClassificationEntra     Classification = "ENTRA"
	ClassificationWorkplace Classification = "WORKPLACE"
	ClassificationUnknown   Classification = "UNKNOWN"
)

type JoinSignals struct {
	PartOfDomain    bool
	Domain          string
	Workgroup       string
	AzureAdJoined   string
	DomainJoined    string
	WorkplaceJoined string
}

type LoggedInIdentity struct {
	AccountHash          string `json:"accountHash,omitempty"`
	AccountAuthorityHash string `json:"accountAuthorityHash,omitempty"`
	UPNHash              string `json:"upnHash,omitempty"`
	SIDHash              string `json:"sidHash,omitempty"`
	SIDMask              string `json:"sidMask,omitempty"`
}

type Inventory struct {
	Hostname        string           `json:"hostname,omitempty"`
	OSVersion       string           `json:"osVersion,omitempty"`
	OSBuild         string           `json:"osBuild,omitempty"`
	Domain          string           `json:"domain,omitempty"`
	Workgroup       string           `json:"workgroup,omitempty"`
	PartOfDomain    bool             `json:"partOfDomain"`
	AzureAdJoined   string           `json:"azureAdJoined,omitempty"`
	DomainJoined    string           `json:"domainJoined,omitempty"`
	WorkplaceJoined string           `json:"workplaceJoined,omitempty"`
	DomainReachable *bool            `json:"domainReachable,omitempty"`
	DomainProbe     string           `json:"domainProbe,omitempty"`
	TenantIDHash    string           `json:"tenantIdHash,omitempty"`
	DeviceIDHash    string           `json:"deviceIdHash,omitempty"`
	DeviceNameHash  string           `json:"deviceNameHash,omitempty"`
	LoggedIn        LoggedInIdentity `json:"loggedIn,omitempty"`
	Classification  Classification   `json:"classification"`
	CollectedAt     time.Time        `json:"collectedAt"`
	ProbeErrors     []string         `json:"probeErrors,omitempty"`
}

func Classify(signals JoinSignals) Classification {
	switch {
	case isYes(signals.DomainJoined) || signals.PartOfDomain:
		return ClassificationDomain
	case isYes(signals.AzureAdJoined):
		return ClassificationEntra
	case isYes(signals.WorkplaceJoined):
		return ClassificationWorkplace
	case strings.TrimSpace(signals.Workgroup) != "" || strings.TrimSpace(signals.Domain) != "":
		return ClassificationLocal
	default:
		return ClassificationUnknown
	}
}

func NormalizeJoinValue(value string) string {
	value = strings.TrimSpace(strings.ToUpper(value))
	switch value {
	case "YES", "NO":
		return value
	case "TRUE":
		return "YES"
	case "FALSE":
		return "NO"
	case "":
		return "UNKNOWN"
	default:
		return value
	}
}

func HashIdentifier(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(value))
	return "sha256:" + hex.EncodeToString(sum[:])[:16]
}

var domainSIDPattern = regexp.MustCompile(`(?i)^(S-1-5-21)-([0-9]+)-([0-9]+)-([0-9]+)-([0-9]+)$`)

func MaskSID(sid string) string {
	sid = strings.TrimSpace(sid)
	if sid == "" {
		return ""
	}
	matches := domainSIDPattern.FindStringSubmatch(sid)
	if len(matches) == 6 {
		return matches[1] + "-***-***-***-" + matches[5]
	}
	return "sid:" + strings.TrimPrefix(HashIdentifier(sid), "sha256:")
}

func BuildLoggedInIdentity(username, upn, sid string) LoggedInIdentity {
	account, authority := splitAccount(username)
	return LoggedInIdentity{
		AccountHash:          HashIdentifier(account),
		AccountAuthorityHash: HashIdentifier(authority),
		UPNHash:              HashIdentifier(upn),
		SIDHash:              HashIdentifier(sid),
		SIDMask:              MaskSID(sid),
	}
}

func splitAccount(username string) (string, string) {
	username = strings.TrimSpace(username)
	if username == "" {
		return "", ""
	}
	if parts := strings.SplitN(username, `\`, 2); len(parts) == 2 {
		return parts[1], parts[0]
	}
	if parts := strings.SplitN(username, "@", 2); len(parts) == 2 {
		return parts[0], parts[1]
	}
	return username, ""
}

func isYes(value string) bool {
	return NormalizeJoinValue(value) == "YES"
}
