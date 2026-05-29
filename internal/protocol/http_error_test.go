package protocol

import (
	"errors"
	"fmt"
	"net/http"
	"testing"
)

func TestHTTPErrorMessage(t *testing.T) {
	err := &HTTPError{
		StatusCode: 401,
		Method:     "POST",
		Path:       "/enrollments/consume",
		Body:       `{"error":"Invalid enrollment token."}`,
	}
	want := `POST /enrollments/consume returned 401: {"error":"Invalid enrollment token."}`
	if got := err.Error(); got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
}

func TestIsUnauthorized(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"plain", errors.New("other"), false},
		{"401 direct", &HTTPError{StatusCode: 401}, true},
		{"409", &HTTPError{StatusCode: 409}, false},
		{"401 wrapped", fmt.Errorf("re-enroll after 401 failed: %w", &HTTPError{StatusCode: 401}), true},
		{"500 wrapped", fmt.Errorf("heartbeat failed: %w", &HTTPError{StatusCode: 500}), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsUnauthorized(tc.err); got != tc.want {
				t.Errorf("IsUnauthorized = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestIsUnauthorizedDistinguishesFromTextMatch(t *testing.T) {
	// Sanity: a plain error whose message contains "401" must NOT be
	// classified as unauthorized — the whole point of the typed surface
	// (Codex 019e7314 constraint #3) is to avoid string-contains routing.
	textOnly := errors.New("got status 401 from upstream")
	if IsUnauthorized(textOnly) {
		t.Fatal("IsUnauthorized must not match by string contents")
	}

	// Real http status code accessible via errors.As.
	wantStatus := http.StatusUnauthorized
	typed := &HTTPError{StatusCode: wantStatus}
	var extracted *HTTPError
	if !errors.As(typed, &extracted) {
		t.Fatal("errors.As must extract HTTPError")
	}
	if extracted.StatusCode != wantStatus {
		t.Errorf("StatusCode: got %d want %d", extracted.StatusCode, wantStatus)
	}
}
