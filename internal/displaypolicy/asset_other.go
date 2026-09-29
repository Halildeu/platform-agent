//go:build !windows

package displaypolicy

// DefaultAssetStore is nil off Windows: the wallpaper policy exists only on
// Windows, so the managed-asset capability is never advertised here.
func DefaultAssetStore() AssetStore {
	return nil
}
