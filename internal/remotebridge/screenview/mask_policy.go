package screenview

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"platform-agent/internal/remotebridge/dataplane"
)

const (
	maskBasisPoints        = 10_000
	maxMaskPolicyTextBytes = 23 // four 5-digit fields plus three commas
)

var canonicalMaskPolicy = regexp.MustCompile(`^[0-9]{1,5},[0-9]{1,5},[0-9]{1,5},[0-9]{1,5}$`)

// MaskPolicy is a disabled-by-default, resolution-independent screen mask.
// Coordinates are basis points of the captured primary monitor. The mask color
// is deliberately fixed to opaque black so policy cannot request a transparent
// or misleading overlay.
type MaskPolicy struct {
	X      int
	Y      int
	Width  int
	Height int
}

func (p MaskPolicy) Enabled() bool {
	return p.Width > 0 && p.Height > 0
}

func (p MaskPolicy) String() string {
	if !p.Enabled() {
		return ""
	}
	return fmt.Sprintf("%d,%d,%d,%d", p.X, p.Y, p.Width, p.Height)
}

// ParseMaskPolicy accepts an empty string as the explicit disabled state. An
// enabled policy must be exactly x,y,width,height in basis points and must fit
// fully inside the captured primary monitor.
func ParseMaskPolicy(raw string) (MaskPolicy, error) {
	if raw == "" {
		return MaskPolicy{}, nil
	}
	if len(raw) > maxMaskPolicyTextBytes {
		return MaskPolicy{}, fmt.Errorf("view-only mask exceeds the canonical length")
	}
	if !canonicalMaskPolicy.MatchString(raw) {
		return MaskPolicy{}, fmt.Errorf("view-only mask is not canonical ASCII x,y,width,height")
	}
	parts := strings.Split(raw, ",")
	if len(parts) != 4 {
		return MaskPolicy{}, fmt.Errorf("view-only mask must be x,y,width,height basis points")
	}
	values := make([]int, len(parts))
	for i, part := range parts {
		value, err := strconv.Atoi(part)
		if err != nil || value < 0 || value > maskBasisPoints {
			return MaskPolicy{}, fmt.Errorf("view-only mask field %d must be 0-%d", i+1, maskBasisPoints)
		}
		values[i] = value
	}
	policy := MaskPolicy{X: values[0], Y: values[1], Width: values[2], Height: values[3]}
	if policy.Width == 0 || policy.Height == 0 {
		return MaskPolicy{}, fmt.Errorf("view-only mask width and height must be positive")
	}
	if policy.X+policy.Width > maskBasisPoints || policy.Y+policy.Height > maskBasisPoints {
		return MaskPolicy{}, fmt.Errorf("view-only mask must fit inside the primary monitor")
	}
	return policy, nil
}

func (p MaskPolicy) apply(frame *dataplane.RawFrame) {
	if !p.Enabled() || frame == nil || frame.Width <= 0 || frame.Height <= 0 {
		return
	}
	// int64 keeps policy scaling independent of the platform int width. The
	// quotient/remainder form also avoids total*basisPoints overflow.
	width := int64(frame.Width)
	height := int64(frame.Height)
	x := int(scaleBasisPoints(width, int64(p.X), false))
	y := int(scaleBasisPoints(height, int64(p.Y), false))
	// Round the far edge up so a non-empty policy never collapses to zero on a
	// small display and the configured sensitive region is never under-masked.
	xEnd := int(scaleBasisPoints(width, int64(p.X+p.Width), true))
	yEnd := int(scaleBasisPoints(height, int64(p.Y+p.Height), true))
	if xEnd <= x || yEnd <= y {
		return // defensive fail-closed for an invalid or future non-canonical policy
	}
	dataplane.MaskRect(frame, x, y, xEnd-x, yEnd-y, 0, 0, 0, 0xFF)
}

func scaleBasisPoints(total, basisPoints int64, roundUp bool) int64 {
	whole, remainder := total/maskBasisPoints, total%maskBasisPoints
	scaledRemainder := remainder * basisPoints
	if roundUp && scaledRemainder > 0 {
		scaledRemainder += maskBasisPoints - 1
	}
	return whole*basisPoints + scaledRemainder/maskBasisPoints
}
