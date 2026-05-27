package autoenroll

import (
	"net/http"
	"time"

	"platform-agent/internal/mtls"
)

// mtlsClientFor is the single place tests build the mTLS *http.Client.
// It exists so both client_test.go and runner_test.go can share the
// same builder without cyclic helper references.
func mtlsClientFor(pki *testPKI) (*http.Client, error) {
	return mtls.NewClient(mtls.Options{
		Cert:       pki.clientCert,
		RootCAs:    pki.caPool,
		ServerName: "127.0.0.1",
		Timeout:    5 * time.Second,
	})
}
