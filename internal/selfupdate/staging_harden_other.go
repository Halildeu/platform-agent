//go:build !windows

package selfupdate

func hardenStagedFile(_ string) error {
	return nil
}
