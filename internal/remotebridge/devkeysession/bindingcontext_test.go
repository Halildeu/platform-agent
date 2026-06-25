package devkeysession_test

import (
	"bytes"
	"encoding/binary"
	"testing"

	"platform-agent/internal/remotebridge/devkeysession"
)

// independentBindingContext re-derives the canonical bytes with a DIFFERENT implementation (append vs the
// production bytes.Buffer) so this test catches a marshaling bug in either, and documents the EXACT layout the
// broker's Java DeviceKeySessionBindingContext.compute must match byte-for-byte.
func independentBindingContext(sessionID, challengeID string, nonce []byte, peer string, expiry int64) []byte {
	var b []byte
	b = append(b, []byte(devkeysession.DomainTag)...)
	b = append(b, 0)
	b = appendLP(b, []byte(sessionID))
	b = appendLP(b, []byte(challengeID))
	b = appendLP(b, nonce)
	b = appendLP(b, []byte(peer))
	var u [8]byte
	binary.BigEndian.PutUint64(u[:], uint64(expiry))
	return append(b, u[:]...)
}

func appendLP(b, field []byte) []byte {
	var p [4]byte
	binary.BigEndian.PutUint32(p[:], uint32(len(field)))
	b = append(b, p[:]...)
	return append(b, field...)
}

func TestBindingContext_MatchesIndependentLayout(t *testing.T) {
	nonce := []byte{0xde, 0xad, 0xbe, 0xef}
	got, err := devkeysession.BindingContext("sess-1", "00112233445566778899aabbccddeeff", nonce, "abPEER", 1_900_060_000_000)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := independentBindingContext("sess-1", "00112233445566778899aabbccddeeff", nonce, "abPEER", 1_900_060_000_000)
	if !bytes.Equal(got, want) {
		t.Fatalf("binding context bytes differ from the independent layout\n got=%x\nwant=%x", got, want)
	}
	if !bytes.HasPrefix(got, append([]byte(devkeysession.DomainTag), 0)) {
		t.Fatalf("binding context must start with the domain tag + NUL")
	}
}

func TestBindingContext_Deterministic(t *testing.T) {
	a, _ := devkeysession.BindingContext("s", "c", []byte{1}, "p", 7)
	b, _ := devkeysession.BindingContext("s", "c", []byte{1}, "p", 7)
	if !bytes.Equal(a, b) {
		t.Fatalf("not deterministic")
	}
}

func TestBindingContext_AnyFieldChangeChangesBytes(t *testing.T) {
	base, _ := devkeysession.BindingContext("s", "c", []byte{1}, "p", 7)
	cases := [][]byte{
		mustBC(t, "S", "c", []byte{1}, "p", 7),
		mustBC(t, "s", "C", []byte{1}, "p", 7),
		mustBC(t, "s", "c", []byte{2}, "p", 7),
		mustBC(t, "s", "c", []byte{1}, "P", 7),
		mustBC(t, "s", "c", []byte{1}, "p", 8),
	}
	for i, c := range cases {
		if bytes.Equal(base, c) {
			t.Fatalf("case %d: a changed field did not change the bytes", i)
		}
	}
}

func TestBindingContext_LengthPrefixRemovesConcatenationAmbiguity(t *testing.T) {
	// ("ab","c") must not collide with ("a","bc") — the UINT32 length prefixes disambiguate
	left, _ := devkeysession.BindingContext("s", "ab", []byte("c"), "p", 1)
	right, _ := devkeysession.BindingContext("s", "a", []byte("bc"), "p", 1)
	if bytes.Equal(left, right) {
		t.Fatalf("length-prefixing failed: distinct field tuples collided")
	}
}

func TestBindingContext_RejectsMissingInputs(t *testing.T) {
	if _, err := devkeysession.BindingContext("", "c", []byte{1}, "p", 1); err == nil {
		t.Fatal("blank sessionID must error")
	}
	if _, err := devkeysession.BindingContext("s", "", []byte{1}, "p", 1); err == nil {
		t.Fatal("blank challengeID must error")
	}
	if _, err := devkeysession.BindingContext("s", "c", nil, "p", 1); err == nil {
		t.Fatal("empty nonce must error")
	}
	if _, err := devkeysession.BindingContext("s", "c", []byte{1}, "", 1); err == nil {
		t.Fatal("blank transportPeerKey must error")
	}
}

func mustBC(t *testing.T, s, c string, nonce []byte, p string, e int64) []byte {
	t.Helper()
	b, err := devkeysession.BindingContext(s, c, nonce, p, e)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	return b
}
