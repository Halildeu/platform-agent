package tpmenroll

import (
	"os"
	"path/filepath"
)

// DeviceClientCertFileName is the file the TPM auto-enroll writes the /attest-issued
// device client certificate (PEM) to, and the file the remote-bridge #548 device-key
// session reads its mTLS transport leaf from. It is shared so the writer (cmd
// auto-enroll) and the reader (remote-bridge device-key identity) can never drift on
// the location.
const DeviceClientCertFileName = "tpm-client-cert.pem"

// DeviceClientCertPath returns the path of the enrollment-issued device client cert
// under %ProgramData%\EndpointAgent. ProgramData is empty off-Windows (and on a
// misconfigured host); the "." fallback matches the writer so the reader always resolves
// the identical path. The device-key session transport is Windows-only in practice.
func DeviceClientCertPath() string {
	base := os.Getenv("ProgramData")
	if base == "" {
		base = "."
	}
	return filepath.Join(base, "EndpointAgent", DeviceClientCertFileName)
}
