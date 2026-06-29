//go:build !windows

package dataplane

// The off-Windows banner self-verify now lives in production as
// dataplane.BannerSelfVerify (banner_other.go) — the shared runBannerHelper calls
// that exported function, so no test-only stub is needed here.
