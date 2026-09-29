package displaypolicy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
)

// MaxAssetBytes mirrors the backend's 10 MiB upload cap (V83 ck_edpa_size).
const MaxAssetBytes int64 = 10 * 1024 * 1024

// imageExtensions maps the three types the wallpaper policy renders to the
// file extension the stored image gets.
var imageExtensions = map[string]string{
	"image/png":  ".png",
	"image/jpeg": ".jpg",
	"image/bmp":  ".bmp",
}

var imageMagic = map[string][]byte{
	"image/png":  {0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A},
	"image/jpeg": {0xFF, 0xD8, 0xFF},
	"image/bmp":  {'B', 'M'},
}

// AssetFetcher downloads a managed wallpaper image the backend holds for this
// device's approved policy. *protocol.Client implements it.
type AssetFetcher interface {
	FetchDisplayPolicyAsset(ctx context.Context, sha256 string, maxBytes int64) ([]byte, error)
}

// AssetStore keeps verified wallpaper images where the interactive user's
// desktop can read them but not change them.
type AssetStore interface {
	// Commit stores content under name as a new file, replacing whatever
	// directory entry is there, and returns the local path the wallpaper
	// policy should point at.
	Commit(name string, content []byte) (path string, err error)
}

// AssetOutcome records which verified file the policy points at.
type AssetOutcome struct {
	Sha256      string `json:"sha256"`
	ContentType string `json:"contentType"`
	Bytes       int    `json:"bytes"`
	LocalPath   string `json:"localPath"`
}

// VerifyAsset checks that content is exactly the approved image: its SHA-256
// equals sha256Hex and its leading bytes are those of contentType. The hash in
// the command is what the admin approved; the transport is not the proof.
func VerifyAsset(content []byte, sha256Hex, contentType string) error {
	if int64(len(content)) > MaxAssetBytes {
		return fmt.Errorf("image is %d bytes, over the %d-byte limit", len(content), MaxAssetBytes)
	}
	sum := sha256.Sum256(content)
	if got := hex.EncodeToString(sum[:]); got != sha256Hex {
		return fmt.Errorf("image hash mismatch (got %s…, want %s…)", got[:12], shortHash(sha256Hex))
	}
	magic, ok := imageMagic[contentType]
	if !ok {
		return fmt.Errorf("unsupported image type %q", contentType)
	}
	if !bytes.HasPrefix(content, magic) {
		return fmt.Errorf("image content is not %s", contentType)
	}
	return nil
}

// ManagedFileName is the stored file name for an image: derived only from the
// validated hash and a fixed extension, so it can never carry a path.
func ManagedFileName(sha256Hex, contentType string) (string, error) {
	ext, ok := imageExtensions[contentType]
	if !ok || !isLowerHexSha256(sha256Hex) {
		return "", fmt.Errorf("cannot name managed image %q (%s)", shortHash(sha256Hex), contentType)
	}
	return sha256Hex + ext, nil
}

// ResolveManagedWallpaper turns a validated managed wallpaper into a local file
// and rewrites w.AssetRef to that path, so the registry writer only ever sees a
// verified image on disk. The image is downloaded and committed as a fresh
// file on every command: a previously stored file is never trusted, because a
// file the agent did not just write could have been placed or altered by the
// signed-in user. Any failure leaves w untouched and must stop the command
// before a registry write.
func ResolveManagedWallpaper(ctx context.Context, w *Wallpaper, fetch AssetFetcher, store AssetStore) (AssetOutcome, error) {
	if fetch == nil || store == nil {
		return AssetOutcome{}, errors.New("managed wallpaper download is not configured on this agent")
	}
	name, err := ManagedFileName(w.AssetSha256, w.ContentType)
	if err != nil {
		return AssetOutcome{}, err
	}
	content, err := fetch.FetchDisplayPolicyAsset(ctx, w.AssetSha256, MaxAssetBytes)
	if err != nil {
		return AssetOutcome{}, fmt.Errorf("download image: %w", err)
	}
	if err := VerifyAsset(content, w.AssetSha256, w.ContentType); err != nil {
		return AssetOutcome{}, err
	}
	path, err := store.Commit(name, content)
	if err != nil {
		return AssetOutcome{}, fmt.Errorf("store image: %w", err)
	}
	w.AssetRef = path
	return AssetOutcome{
		Sha256:      w.AssetSha256,
		ContentType: w.ContentType,
		Bytes:       len(content),
		LocalPath:   path,
	}, nil
}

func shortHash(h string) string {
	if len(h) > 12 {
		return h[:12]
	}
	return h
}
