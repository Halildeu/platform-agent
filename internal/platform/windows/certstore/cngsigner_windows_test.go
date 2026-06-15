//go:build windows

package certstore

import (
	"crypto"
	"testing"

	"golang.org/x/sys/windows"
)

func TestBcryptHashAlgID(t *testing.T) {
	ok := map[crypto.Hash]string{
		crypto.SHA256: "SHA256",
		crypto.SHA384: "SHA384",
		crypto.SHA512: "SHA512",
		crypto.SHA1:   "SHA1",
	}
	for h, want := range ok {
		got, err := bcryptHashAlgID(h)
		if err != nil || got != want {
			t.Errorf("bcryptHashAlgID(%v) = %q, %v; want %q, nil", h, got, err, want)
		}
	}
	if _, err := bcryptHashAlgID(crypto.MD5); err == nil {
		t.Error("bcryptHashAlgID(MD5): expected error for unsupported hash")
	}
}

func TestAcquireFlagsPreferNCryptNoCache(t *testing.T) {
	if cryptAcquirePreferNCryptFlag != 0x00020000 {
		t.Errorf("PREFER_NCRYPT = 0x%x, want 0x20000 (0x10000 is ALLOW_NCRYPT)", cryptAcquirePreferNCryptFlag)
	}
	if cryptAcquireSilentFlag != 0x40 {
		t.Errorf("SILENT = 0x%x, want 0x40", cryptAcquireSilentFlag)
	}
	// Must NOT regress to the certtostore flags that access-violated.
	const cacheFlag, onlyNCryptFlag = 0x1, 0x40000
	eff := cryptAcquireSilentFlag | cryptAcquirePreferNCryptFlag
	if eff&cacheFlag != 0 || eff&onlyNCryptFlag != 0 {
		t.Errorf("effective acquire flags 0x%x must not include CACHE(0x1) or ONLY_NCRYPT(0x40000)", eff)
	}
}

func TestAcquireResultIsNCrypt_AllowsATNoneWhenHandleProbesAsNCrypt(t *testing.T) {
	tests := []struct {
		name          string
		keySpec       uint32
		ncryptProbeOK bool
		want          bool
	}{
		{
			name:          "canonical NCrypt key spec",
			keySpec:       certNCryptKeySpec,
			ncryptProbeOK: false,
			want:          true,
		},
		{
			name:          "AD CS CNG template reports AT_NONE but handle is NCrypt",
			keySpec:       0,
			ncryptProbeOK: true,
			want:          true,
		},
		{
			name:          "AT_NONE without NCrypt handle probe stays unsupported",
			keySpec:       0,
			ncryptProbeOK: false,
			want:          false,
		},
		{
			name:          "legacy AT_KEYEXCHANGE without NCrypt probe stays unsupported",
			keySpec:       1,
			ncryptProbeOK: false,
			want:          false,
		},
		{
			name:          "noncanonical key spec is allowed only when handle probes as NCrypt",
			keySpec:       1,
			ncryptProbeOK: true,
			want:          true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := acquireResultIsNCrypt(tt.keySpec, tt.ncryptProbeOK); got != tt.want {
				t.Fatalf("acquireResultIsNCrypt(0x%x, %v) = %v, want %v",
					tt.keySpec, tt.ncryptProbeOK, got, tt.want)
			}
		})
	}
}

func TestCngSignerCloseDoesNotFreeCertContext(t *testing.T) {
	// Regression for #165: dry-run cleanup crashed inside
	// CertFreeCertificateContext. Close must not invoke that API; the
	// duplicated context is intentionally retained for process lifetime.
	s := &cngSigner{
		ctx: &windows.CertContext{},
	}

	s.Close()
	if s.ctx != nil {
		t.Fatal("Close should clear the retained context pointer after deciding not to free it")
	}

	s.Close()
}
