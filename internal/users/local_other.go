//go:build !windows

package users

func ListLocal() ([]LocalUserSnapshot, error) {
	return nil, ErrLocalUserListingUnsupported
}

func MutateLocal(LocalUserMutationRequest) (LocalUserMutationResult, error) {
	return LocalUserMutationResult{}, ErrLocalUserMutationUnsupported
}
