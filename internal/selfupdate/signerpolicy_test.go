package selfupdate

import "testing"

func TestSignerAllowlist_Contains(t *testing.T) {
	allow := SignerAllowlist{Thumbprints: []string{"AB:CD:EF:01:23", "deadbeef"}}
	for _, in := range []string{"AB:CD:EF:01:23", "abcdef0123", "ab cd ef 01 23", "DEADBEEF", "DeadBeef"} {
		if !allow.Contains(in) {
			t.Errorf("Contains(%q) = false, want true", in)
		}
	}
	for _, in := range []string{"", "00000000", "abcd", "feedface"} {
		if allow.Contains(in) {
			t.Errorf("Contains(%q) = true, want false", in)
		}
	}
}

func TestEvaluateSignerPolicy(t *testing.T) {
	allow := SignerAllowlist{Thumbprints: []string{"ABCDEF0123"}}
	if d := EvaluateSignerPolicy("", allow); d.Allowed || d.Code != ErrSignerNotAllowed {
		t.Errorf("empty thumbprint: %+v", d)
	}
	if d := EvaluateSignerPolicy("00112233", allow); d.Allowed || d.Code != ErrSignerNotAllowed {
		t.Errorf("not-allowlisted: %+v", d)
	}
	if d := EvaluateSignerPolicy("ab:cd:ef:01:23", allow); !d.Allowed || d.Code != "" {
		t.Errorf("allowlisted (formatted): %+v", d)
	}
}

func TestEvaluateTierPolicy(t *testing.T) {
	cases := []struct {
		name    string
		tier    SigningTier
		pol     TierPolicy
		allowed bool
		code    ErrorCode
	}{
		{"trusted always", TierTrusted, TierPolicy{}, true, ""},
		{"trusted ignores domain", TierTrusted, TierPolicy{DomainJoined: true}, true, ""},
		{"lab no opt-in refused", TierLabOnlyEvidence, TierPolicy{}, false, ErrLabTierRefused},
		{"lab opt-in non-domain ok", TierLabOnlyEvidence, TierPolicy{AllowLabOnly: true, DomainJoined: false}, true, ""},
		{"lab opt-in domain refused", TierLabOnlyEvidence, TierPolicy{AllowLabOnly: true, DomainJoined: true}, false, ErrLabTierRefused},
		{"unknown tier refused", SigningTier("WHATEVER"), TierPolicy{AllowLabOnly: true}, false, ErrLabTierRefused},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := EvaluateTierPolicy(c.tier, c.pol)
			if d.Allowed != c.allowed || d.Code != c.code {
				t.Errorf("got {Allowed:%v Code:%q} want {Allowed:%v Code:%q}", d.Allowed, d.Code, c.allowed, c.code)
			}
		})
	}
}

func TestEvaluateAuthenticodePolicy(t *testing.T) {
	base := AuthenticodeEvidence{ChainValid: true, HasCodeSigningEKU: true, SignerThumbprint: "ABCDEF", CurrentTimeValid: true}
	cases := []struct {
		name    string
		ev      AuthenticodeEvidence
		tier    SigningTier
		allowed bool
		code    ErrorCode
	}{
		{"trusted chain invalid", AuthenticodeEvidence{ChainValid: false, HasCodeSigningEKU: true, CurrentTimeValid: true}, TierTrusted, false, ErrSignatureInvalid},
		{"missing code-signing EKU", AuthenticodeEvidence{ChainValid: true, HasCodeSigningEKU: false, CurrentTimeValid: true}, TierTrusted, false, ErrSignatureInvalid},
		{"untimestamped current-valid ok", base, TierTrusted, true, ""},
		{"untimestamped current-invalid rejected", AuthenticodeEvidence{ChainValid: true, HasCodeSigningEKU: true, CurrentTimeValid: false}, TierTrusted, false, ErrSignatureInvalid},
		{"timestamped signing-valid ok even if current invalid", AuthenticodeEvidence{ChainValid: true, HasCodeSigningEKU: true, Timestamped: true, SigningTimeValid: true, CurrentTimeValid: false}, TierTrusted, true, ""},
		{"timestamped signing-invalid rejected", AuthenticodeEvidence{ChainValid: true, HasCodeSigningEKU: true, Timestamped: true, SigningTimeValid: false, CurrentTimeValid: true}, TierTrusted, false, ErrSignatureInvalid},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := EvaluateAuthenticodePolicy(c.ev, c.tier)
			if d.Allowed != c.allowed || d.Code != c.code {
				t.Errorf("got {Allowed:%v Code:%q} want {Allowed:%v Code:%q}", d.Allowed, d.Code, c.allowed, c.code)
			}
		})
	}
}
