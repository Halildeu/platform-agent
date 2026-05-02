//go:build !windows

package users

func ListLocal() ([]LocalUserSnapshot, error) {
	return nil, ErrLocalUserListingUnsupported
}
