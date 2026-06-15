//go:build !windows

package dataplane

// bannerSelfVerify is unsupported off Windows (build-tag parity with
// banner_session_windows_test.go); the banner gold-proof is windows-only. This
// keeps the shared runBannerHelper compiling on the host test build.
func bannerSelfVerify() error { return ErrBannerUnsupported }
