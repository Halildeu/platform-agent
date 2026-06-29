//go:build !windows

package dataplane

import "context"

// ShowActiveBanner is unsupported off Windows: it returns ErrBannerUnsupported
// immediately so a fail-closed caller refuses to start a VIEW_ONLY session
// without endpoint awareness (build-tag parity with banner_windows.go).
func ShowActiveBanner(_ context.Context) error { return ErrBannerUnsupported }

// BannerSelfVerify is unsupported off Windows (build-tag parity): fail-closed.
func BannerSelfVerify() error { return ErrBannerUnsupported }
