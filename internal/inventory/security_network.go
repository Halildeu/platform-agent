package inventory

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"sort"
	"strings"
	"time"
)

// AG-043 / #527 — structured security/network block evidence.
//
// The probe feeds backend failed-device-queue EDR_NETWORK auto-ingest.
// HARD BOUNDARY: the wire payload never carries raw process paths,
// destination IPs/hosts, URLs, account identifiers, command lines, or
// provider free text. Windows implementations may read blocked WFP event-log
// records locally, but only hash/token projections are serialized.

const SecurityNetworkSchemaVersion = 1
const MaxSecurityNetworkEvents = 20
const MaxSecurityNetworkProbeErrors = 16
const SecurityNetworkProbeTimeout = 10 * time.Second

const (
	SecurityNetworkErrUnsupportedPlatform = "UNSUPPORTED_PLATFORM"
	SecurityNetworkErrEventLogUnavailable = "EVENT_LOG_UNAVAILABLE"
	SecurityNetworkErrAccessDenied        = "ACCESS_DENIED"
	SecurityNetworkErrProbeTimeout        = "PROBE_TIMEOUT"
	SecurityNetworkErrProbeFailed         = "PROBE_FAILED"
	SecurityNetworkErrNoEvidence          = "NO_EVIDENCE"
	SecurityNetworkErrEventsTruncated     = "EVENTS_TRUNCATED"
)

const SecurityNetworkVendorWindowsFirewall = "windows-firewall"

var securityNetworkSafeToken = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_.:-]{1,127}$`)

type SecurityNetworkResult struct {
	SchemaVersion   int                         `json:"schemaVersion"`
	Supported       bool                        `json:"supported"`
	ProbeComplete   bool                        `json:"probeComplete"`
	Events          []SecurityNetworkEvent      `json:"events"`
	ProbeErrors     []SecurityNetworkProbeError `json:"probeErrors"`
	ProbeDurationMs int                         `json:"probeDurationMs"`
}

type SecurityNetworkEvent struct {
	NetworkSegmentID         *string `json:"networkSegmentId"`
	EDRVendor                string  `json:"edrVendor"`
	BlockedProcessHashPrefix *string `json:"blockedProcessHashPrefix"`
	BlockedDestination       *string `json:"blockedDestination"`
	FirewallRuleID           *string `json:"firewallRuleId"`
	LastSuccessfulContactAt  *string `json:"lastSuccessfulContactAt"`
	ObservedAt               string  `json:"observedAt"`
}

type SecurityNetworkProbeError struct {
	Code    string  `json:"code"`
	Summary *string `json:"summary,omitempty"`
}

type rawSecurityNetworkEvent struct {
	ProcessPath        string
	DestinationAddress string
	DestinationPort    string
	Protocol           string
	FilterID           string
	ObservedAt         time.Time
}

func orchestrateSecurityNetworkProbe(
	_ context.Context,
	now func() time.Time,
	supported bool,
	rawEvents []rawSecurityNetworkEvent,
	rawErrors []SecurityNetworkProbeError,
	startedAt time.Time,
) SecurityNetworkResult {
	if now == nil {
		now = time.Now
	}
	events := make([]SecurityNetworkEvent, 0, len(rawEvents))
	for _, raw := range rawEvents {
		event, ok := projectSecurityNetworkEvent(raw)
		if ok {
			events = append(events, event)
		}
	}

	eventsTruncated := false
	if len(events) > MaxSecurityNetworkEvents {
		events = events[:MaxSecurityNetworkEvents]
		eventsTruncated = true
	}
	errors := boundedSecurityNetworkProbeErrors(rawErrors, eventsTruncated)

	sort.SliceStable(events, func(i, j int) bool {
		if events[i].ObservedAt != events[j].ObservedAt {
			return events[i].ObservedAt < events[j].ObservedAt
		}
		return nullableString(events[i].FirewallRuleID) < nullableString(events[j].FirewallRuleID)
	})

	if events == nil {
		events = []SecurityNetworkEvent{}
	}
	if errors == nil {
		errors = []SecurityNetworkProbeError{}
	}

	return SecurityNetworkResult{
		SchemaVersion:   SecurityNetworkSchemaVersion,
		Supported:       supported,
		ProbeComplete:   supported && !hasDecisionCriticalSecurityNetworkError(errors),
		Events:          events,
		ProbeErrors:     errors,
		ProbeDurationMs: int(now().Sub(startedAt) / time.Millisecond),
	}
}

func boundedSecurityNetworkProbeErrors(rawErrors []SecurityNetworkProbeError, eventsTruncated bool) []SecurityNetworkProbeError {
	errors := append([]SecurityNetworkProbeError{}, rawErrors...)
	if len(errors) > MaxSecurityNetworkProbeErrors {
		errors = errors[:MaxSecurityNetworkProbeErrors]
	}
	if eventsTruncated {
		sentinel := SecurityNetworkProbeError{
			Code:    SecurityNetworkErrEventsTruncated,
			Summary: securityNetworkSummaryPtr("Security/network events truncated at cap"),
		}
		if len(errors) >= MaxSecurityNetworkProbeErrors {
			errors = errors[:MaxSecurityNetworkProbeErrors-1]
		}
		errors = append(errors, sentinel)
	}
	return errors
}

func projectSecurityNetworkEvent(raw rawSecurityNetworkEvent) (SecurityNetworkEvent, bool) {
	if raw.ObservedAt.IsZero() {
		return SecurityNetworkEvent{}, false
	}
	processHash := sha256PrefixPtr(raw.ProcessPath, 16)
	blockedDestination := redactedBlockedDestination(raw.DestinationAddress, raw.DestinationPort, raw.Protocol)
	firewallRuleID := redactedFirewallRuleID(raw.FilterID)
	if processHash == nil && blockedDestination == nil && firewallRuleID == nil {
		return SecurityNetworkEvent{}, false
	}
	return SecurityNetworkEvent{
		NetworkSegmentID:         nil,
		EDRVendor:                SecurityNetworkVendorWindowsFirewall,
		BlockedProcessHashPrefix: processHash,
		BlockedDestination:       blockedDestination,
		FirewallRuleID:           firewallRuleID,
		LastSuccessfulContactAt:  nil,
		ObservedAt:               raw.ObservedAt.UTC().Format(time.RFC3339Nano),
	}, true
}

func redactedBlockedDestination(address, port, protocol string) *string {
	address = strings.TrimSpace(address)
	if address == "" || address == "-" || address == "::" {
		return nil
	}
	material := strings.ToLower(address) + "|" + strings.TrimSpace(port) + "|" + strings.TrimSpace(protocol)
	prefix := sha256Prefix(material, 32)
	out := "dest-sha256-" + prefix
	return &out
}

func redactedFirewallRuleID(raw string) *string {
	raw = strings.TrimSpace(raw)
	if raw == "" || raw == "-" {
		return nil
	}
	token := "wfp-filter-" + sha256Prefix(raw, 16)
	if !securityNetworkSafeToken.MatchString(token) {
		return nil
	}
	return &token
}

func sha256PrefixPtr(raw string, n int) *string {
	raw = strings.TrimSpace(raw)
	if raw == "" || raw == "-" {
		return nil
	}
	out := sha256Prefix(raw, n)
	return &out
}

func sha256Prefix(raw string, n int) string {
	sum := sha256.Sum256([]byte(raw))
	hexed := hex.EncodeToString(sum[:])
	if n <= 0 || n > len(hexed) {
		return hexed
	}
	return hexed[:n]
}

func hasDecisionCriticalSecurityNetworkError(errors []SecurityNetworkProbeError) bool {
	for _, e := range errors {
		switch e.Code {
		case SecurityNetworkErrEventLogUnavailable,
			SecurityNetworkErrAccessDenied,
			SecurityNetworkErrProbeTimeout,
			SecurityNetworkErrProbeFailed,
			SecurityNetworkErrUnsupportedPlatform:
			return true
		}
	}
	return false
}

func securityNetworkSummaryPtr(s string) *string {
	s = strings.TrimSpace(strings.ReplaceAll(strings.ReplaceAll(s, "\r", " "), "\n", " "))
	if len(s) > 200 {
		s = s[:200]
	}
	if s == "" {
		return nil
	}
	return &s
}

func nullableString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
