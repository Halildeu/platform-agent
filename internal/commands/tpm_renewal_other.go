//go:build !windows

package commands

import (
	"context"
	"fmt"
)

func platformSupportsTPMRenewal() bool {
	return false
}

func platformRenewTPMCertificate(
	_ context.Context,
	_ TPMRenewalOptions,
	_ TPMRenewalRequest,
) (TPMRenewalResult, error) {
	return TPMRenewalResult{}, fmt.Errorf("TPM_RENEWAL_UNSUPPORTED_PLATFORM")
}
