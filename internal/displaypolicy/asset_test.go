package displaypolicy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

func pngBytes(n int) []byte {
	b := make([]byte, n)
	copy(b, []byte{0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A})
	for i := 8; i < n; i++ {
		b[i] = byte(i)
	}
	return b
}

func hashOf(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func managedWallpaper(content []byte) *Wallpaper {
	h := hashOf(content)
	return &Wallpaper{
		Enabled:          true,
		Style:            "FILL",
		UserCannotChange: true,
		AssetRef:         ManagedAssetRefPrefix + h,
		AssetSha256:      h,
		ContentType:      "image/png",
	}
}

type fakeFetcher struct {
	content []byte
	err     error
	calls   int
	gotSha  string
	gotMax  int64
}

func (f *fakeFetcher) FetchDisplayPolicyAsset(_ context.Context, sha string, max int64) ([]byte, error) {
	f.calls++
	f.gotSha, f.gotMax = sha, max
	return f.content, f.err
}

type fakeStore struct {
	committed map[string][]byte
	err       error
}

func (s *fakeStore) Commit(name string, content []byte) (string, error) {
	if s.err != nil {
		return "", s.err
	}
	if s.committed == nil {
		s.committed = map[string][]byte{}
	}
	s.committed[name] = append([]byte(nil), content...)
	return `C:\ProgramData\EndpointAgent\wallpaper\` + name, nil
}

func TestValidate_ManagedWallpaperRef(t *testing.T) {
	good := managedWallpaper(pngBytes(64))
	if err := Validate(Command{Operation: OperationEnforce, Wallpaper: good}); err != nil {
		t.Fatalf("valid managed wallpaper rejected: %v", err)
	}

	cases := map[string]func(w *Wallpaper){
		"hash in ref differs from assetSha256": func(w *Wallpaper) { w.AssetSha256 = strings.Repeat("a", 64) },
		"missing assetSha256":                  func(w *Wallpaper) { w.AssetSha256 = "" },
		"uppercase hex": func(w *Wallpaper) {
			w.AssetRef = ManagedAssetRefPrefix + strings.ToUpper(w.AssetSha256)
			w.AssetSha256 = strings.ToUpper(w.AssetSha256)
		},
		"short hash":                   func(w *Wallpaper) { w.AssetRef = ManagedAssetRefPrefix + "abc" },
		"path smuggled after the hash": func(w *Wallpaper) { w.AssetRef += `\..\evil.png` },
		"unsupported type":             func(w *Wallpaper) { w.ContentType = "image/gif" },
		"missing type":                 func(w *Wallpaper) { w.ContentType = "" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			w := *good
			mutate(&w)
			if err := Validate(Command{Operation: OperationEnforce, Wallpaper: &w}); err == nil {
				t.Fatal("malformed managed ref accepted")
			}
		})
	}
}

func TestVerifyAsset(t *testing.T) {
	img := pngBytes(128)
	h := hashOf(img)
	if err := VerifyAsset(img, h, "image/png"); err != nil {
		t.Fatalf("matching image rejected: %v", err)
	}
	tampered := append([]byte(nil), img...)
	tampered[100] ^= 0xFF
	if err := VerifyAsset(tampered, h, "image/png"); err == nil {
		t.Fatal("tampered bytes accepted")
	}
	// Right hash, wrong kind of file: an executable renamed to .png.
	exe := append([]byte("MZ"), bytes.Repeat([]byte{0}, 62)...)
	if err := VerifyAsset(exe, hashOf(exe), "image/png"); err == nil {
		t.Fatal("non-image content accepted as image/png")
	}
	if err := VerifyAsset(img, h, "image/jpeg"); err == nil {
		t.Fatal("PNG bytes accepted as image/jpeg")
	}
}

func TestManagedFileNameIsHashPlusFixedExtension(t *testing.T) {
	h := strings.Repeat("c", 64)
	for typ, want := range map[string]string{"image/png": h + ".png", "image/jpeg": h + ".jpg", "image/bmp": h + ".bmp"} {
		got, err := ManagedFileName(h, typ)
		if err != nil || got != want {
			t.Fatalf("ManagedFileName(%s) = %q, %v; want %q", typ, got, err, want)
		}
	}
	for _, bad := range []string{"", "../" + h[:61], strings.ToUpper(h)} {
		if _, err := ManagedFileName(bad, "image/png"); err == nil {
			t.Fatalf("ManagedFileName accepted %q", bad)
		}
	}
}

func TestResolveManagedWallpaper_StoresTheVerifiedImageAndPointsThePolicyAtIt(t *testing.T) {
	img := pngBytes(256)
	w := managedWallpaper(img)
	fetch := &fakeFetcher{content: img}
	store := &fakeStore{}

	out, err := ResolveManagedWallpaper(context.Background(), w, fetch, store)
	if err != nil {
		t.Fatalf("ResolveManagedWallpaper: %v", err)
	}
	name := w.AssetSha256 + ".png"
	if !bytes.Equal(store.committed[name], img) {
		t.Fatalf("stored %d bytes under %q, want the downloaded image", len(store.committed[name]), name)
	}
	if want := `C:\ProgramData\EndpointAgent\wallpaper\` + name; w.AssetRef != want || out.LocalPath != want {
		t.Fatalf("AssetRef=%q LocalPath=%q, want both %q", w.AssetRef, out.LocalPath, want)
	}
	if fetch.gotSha != w.AssetSha256 || fetch.gotMax != MaxAssetBytes {
		t.Fatalf("fetched sha=%q max=%d", fetch.gotSha, fetch.gotMax)
	}
	if out.Bytes != len(img) || out.Sha256 != w.AssetSha256 {
		t.Fatalf("outcome = %+v", out)
	}
}

func TestResolveManagedWallpaper_NothingIsStoredWhenTheDownloadDoesNotVerify(t *testing.T) {
	img := pngBytes(256)
	w := managedWallpaper(img)
	originalRef := w.AssetRef
	other := pngBytes(300) // a valid PNG, just not the approved one
	store := &fakeStore{}

	_, err := ResolveManagedWallpaper(context.Background(), w, &fakeFetcher{content: other}, store)
	if err == nil || !strings.Contains(err.Error(), "hash mismatch") {
		t.Fatalf("err = %v, want a hash mismatch", err)
	}
	if len(store.committed) != 0 {
		t.Fatal("an unverified image was stored")
	}
	if w.AssetRef != originalRef {
		t.Fatalf("AssetRef rewritten to %q after a failed verification", w.AssetRef)
	}
}

func TestResolveManagedWallpaper_DownloadAndStoreErrorsStopTheCommand(t *testing.T) {
	img := pngBytes(64)

	w := managedWallpaper(img)
	if _, err := ResolveManagedWallpaper(context.Background(), w, &fakeFetcher{err: errors.New("GET returned 404")}, &fakeStore{}); err == nil {
		t.Fatal("download failure not reported")
	}

	w = managedWallpaper(img)
	if _, err := ResolveManagedWallpaper(context.Background(), w, &fakeFetcher{content: img}, &fakeStore{err: errors.New("access denied")}); err == nil {
		t.Fatal("store failure not reported")
	}

	w = managedWallpaper(img)
	if _, err := ResolveManagedWallpaper(context.Background(), w, nil, &fakeStore{}); err == nil {
		t.Fatal("missing fetcher not reported")
	}
}
