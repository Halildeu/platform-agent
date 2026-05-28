//go:build !windows

package inventory

// AG-035 — non-Windows builds do not ship a hardware probe. The package
// default (collectHardwareImpl = collectHardwareUnsupported) is the
// correct behaviour for these platforms — Supported=false with the
// canonical OS metadata and an UNSUPPORTED_PLATFORM probe error.
//
// This file exists to make the build tag relationship explicit and to
// give non-Windows builds a place to install an init() override if we
// later want to wire e.g. a Linux probe (uname / lscpu / /sys parsing)
// without changing the cross-platform default in hardware.go.
//
// Today: no-op marker.
