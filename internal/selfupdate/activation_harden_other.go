//go:build !windows

package selfupdate

func hardenActivationArtifact(_ string) error {
	return nil
}
