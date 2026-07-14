package screenview

import (
	"math"
	"testing"

	"platform-agent/internal/remotebridge/dataplane"
)

func TestParseMaskPolicy(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		want    MaskPolicy
		wantErr bool
	}{
		{name: "disabled", raw: "", want: MaskPolicy{}},
		{name: "bounded", raw: "7500,7500,2500,2500", want: MaskPolicy{X: 7500, Y: 7500, Width: 2500, Height: 2500}},
		{name: "wrong field count", raw: "0,0,1000", wantErr: true},
		{name: "outer whitespace is not canonical", raw: " 0,0,1000,1000", wantErr: true},
		{name: "whitespace is not canonical", raw: "0, 0,1000,1000", wantErr: true},
		{name: "unicode digits are not canonical", raw: "٠,0,1000,1000", wantErr: true},
		{name: "plus sign is not canonical", raw: "+0,0,1000,1000", wantErr: true},
		{name: "zero width", raw: "0,0,0,1000", wantErr: true},
		{name: "negative", raw: "-1,0,1000,1000", wantErr: true},
		{name: "overflow x", raw: "9000,0,1001,1000", wantErr: true},
		{name: "overflow y", raw: "0,9000,1000,1001", wantErr: true},
		{name: "oversized input", raw: "00000,00000,00001,00001x", wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseMaskPolicy(tc.raw)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("ParseMaskPolicy(%q) unexpectedly passed: %+v", tc.raw, got)
				}
				return
			}
			if err != nil || got != tc.want || got.String() != tc.raw {
				t.Fatalf("ParseMaskPolicy(%q) = %+v, %v; want %+v", tc.raw, got, err, tc.want)
			}
		})
	}
}

func TestMaskPolicyApplyDoesNotCollapseOnTinyFrame(t *testing.T) {
	frame := dataplane.RawFrame{Width: 1, Height: 1, Stride: 4, Pixels: []byte{0xFF, 0xFF, 0xFF, 0xFF}}
	MaskPolicy{X: 9999, Y: 9999, Width: 1, Height: 1}.apply(&frame)
	if got := frame.Pixels; got[0] != 0 || got[1] != 0 || got[2] != 0 || got[3] != 0xFF {
		t.Fatalf("tiny-frame sensitive pixel = %v; want opaque black", got)
	}
}

func TestScaleBasisPointsDoesNotOverflow(t *testing.T) {
	if got := scaleBasisPoints(math.MaxInt64, maskBasisPoints, false); got != math.MaxInt64 {
		t.Fatalf("full-scale MaxInt64 = %d; want %d", got, int64(math.MaxInt64))
	}
	if got := scaleBasisPoints(3, 1, true); got != 1 {
		t.Fatalf("rounded non-empty region = %d; want 1", got)
	}
}

func TestMaskPolicyApplyUsesBasisPointsAndOpaqueBlack(t *testing.T) {
	frame := dataplane.RawFrame{Width: 8, Height: 8, Stride: 32, Pixels: make([]byte, 8*8*4)}
	for i := range frame.Pixels {
		frame.Pixels[i] = 0xFF
	}
	policy := MaskPolicy{X: 7500, Y: 7500, Width: 2500, Height: 2500}
	policy.apply(&frame)

	for y := 0; y < frame.Height; y++ {
		for x := 0; x < frame.Width; x++ {
			offset := y*frame.Stride + x*4
			masked := x >= 6 && y >= 6
			if masked {
				if got := frame.Pixels[offset : offset+4]; got[0] != 0 || got[1] != 0 || got[2] != 0 || got[3] != 0xFF {
					t.Fatalf("pixel (%d,%d) = %v; want opaque black", x, y, got)
				}
			} else if got := frame.Pixels[offset : offset+4]; got[0] != 0xFF || got[1] != 0xFF || got[2] != 0xFF || got[3] != 0xFF {
				t.Fatalf("pixel (%d,%d) outside mask changed: %v", x, y, got)
			}
		}
	}
}
