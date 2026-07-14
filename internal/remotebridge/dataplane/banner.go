package dataplane

import "errors"

// Endpoint-visible "remote support active" banner — the ADR-0034 D10
// endpoint-AWARENESS control. The in-frame active-indicator (exfil.go) marks the
// streamed frame for the VIEWER, but it never reaches the endpoint USER's screen;
// this banner is the on-screen window the user sees while a VIEW_ONLY session is
// live. It is an AWARENESS control, NOT an enforcement control — enforcement is
// the user local-abort + recording fail-closed gate (slice-1). We deliberately do
// NOT try to make it unkillable (that would be malware-like + fragile); the audit
// trail + recording are the enforcement layer.
//
// This file holds the OS-agnostic config, geometry, DPI scaling, and the distinct
// failure sentinels; the actual window is windows-only (banner_windows.go), with
// a no-op stub elsewhere (banner_other.go).
//
// SCOPE (MVP / owner-gated pilot): a single banner on the PRIMARY monitor only.
// Per-active-monitor / all-monitor coverage is an explicit follow-up slice — a
// user working solely on a secondary monitor may not see this first cut.
// Disabled-by-default; shown only by the (owner-gated) session runtime.

const (
	// BannerTitle is the window title / class-visible name.
	BannerTitle = "Uzaktan Destek / Remote Support"
	// BannerText is the user-facing notice. ASCII-safe (no emoji) so it renders
	// in any system font; the red background carries the visual alarm. Bilingual.
	BannerText = "UZAKTAN DESTEK OTURUMU AKTIF - ekraniniz goruntuleniyor.   |   REMOTE SUPPORT SESSION ACTIVE - your screen is being viewed."
	// bannerClassName is the Win32 window-class name (also used by the gold-proof
	// to FindWindow + verify visibility from within session 1; TEST use only —
	// not a production security assertion).
	bannerClassName = "AcikRemoteSupportActiveBanner"

	// bannerBaseHeight is the banner height in px at 96 DPI (100% scaling); it is
	// scaled up by scaleForDPI on hi-DPI displays so the bar stays legible.
	bannerBaseHeight = 48
	// banner width = screenW * num/den (most of the width, so it is unmissable).
	bannerWidthNum = 4
	bannerWidthDen = 5
	// bannerMinWidth keeps the bar visible on a degenerate/small screen.
	bannerMinWidth = 320
	// dpiDefault is the 100%-scaling DPI baseline Windows uses.
	dpiDefault = 96
)

// Distinct failure sentinels so the session runtime + telemetry can tell WHERE
// the endpoint-awareness banner failed (Codex review): a fail-closed caller must
// treat ANY of these as "no banner → no endpoint awareness → do not start the
// VIEW_ONLY session", mirroring the recording_ready gate.
var (
	// ErrBannerUnsupported is returned by the non-windows stub.
	ErrBannerUnsupported = errors.New("dataplane: endpoint banner not supported on this platform")
	// ErrBannerClassRegister: RegisterClassExW failed.
	ErrBannerClassRegister = errors.New("dataplane: endpoint banner class registration failed")
	// ErrBannerCreate: CreateWindowExW failed (class or child).
	ErrBannerCreate = errors.New("dataplane: endpoint banner window creation failed")
	// ErrBannerShow: the window could not be shown / verified visible.
	ErrBannerShow = errors.New("dataplane: endpoint banner could not be shown")
	// ErrBannerNotFound is returned when the acceptance trigger cannot find the
	// exact session-bound active banner. Wrong/stale sessions fail closed here.
	ErrBannerNotFound = errors.New("dataplane: session-bound endpoint banner not found")
	// ErrBannerTrigger is returned when Win32 refuses the fixed WM_CLOSE signal.
	ErrBannerTrigger = errors.New("dataplane: endpoint banner close signal failed")
)

func bannerWindowTitle(binding string) string {
	if binding == "" {
		return BannerTitle
	}
	// Keep the opaque binding in the exact title. TriggerIndicatorLoss searches
	// by BOTH this title and the private banner class, preventing a stale/wrong
	// session from falling back to an unrelated active banner.
	return BannerTitle + " [acceptance:" + binding + "]"
}

// rgb packs r,g,b into a Win32 COLORREF (0x00BBGGRR). OS-agnostic (pure bit-pack)
// so the colour constants are unit-testable off Windows.
func rgb(r, g, b uint32) uintptr { return uintptr(r | g<<8 | b<<16) }

// scaleForDPI scales a 96-DPI base measurement to the given DPI, rounding to the
// nearest px. A non-positive dpi falls back to 100% (dpiDefault) so a failed DPI
// query never yields a zero/invisible size.
func scaleForDPI(base, dpi int) int {
	if dpi <= 0 {
		dpi = dpiDefault
	}
	return (base*dpi + dpiDefault/2) / dpiDefault
}

// bannerBounds computes the banner rectangle (x, y, w) for a primary monitor of
// screenW×screenH given a (already DPI-scaled) height h: a wide bar pinned to the
// TOP and horizontally centered, overlaying the top of the active desktop where
// the user cannot miss it. Fail-safe: non-positive screen dims clamp to a minimum
// visible bar at the origin.
func bannerBounds(screenW, screenH, h int) (x, y, w int) {
	if screenW <= 0 || screenH <= 0 {
		return 0, 0, bannerMinWidth // degenerate screen: still emit a visible bar
	}
	w = screenW * bannerWidthNum / bannerWidthDen
	if w < bannerMinWidth {
		w = bannerMinWidth
	}
	if w > screenW {
		w = screenW
	}
	x = (screenW - w) / 2
	if x < 0 {
		x = 0
	}
	return x, 0, w // y=0: pinned to the very top
}
