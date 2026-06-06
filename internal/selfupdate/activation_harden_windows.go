//go:build windows

package selfupdate

func hardenActivationArtifact(path string) error {
	return setSelfUpdateHardenedACL(path)
}
