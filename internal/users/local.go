package users

import "errors"

var ErrLocalUserListingUnsupported = errors.New("local user listing is only supported on Windows in this build")
var ErrLocalUserMutationUnsupported = errors.New("local user mutation is only supported on Windows in this build")

type LocalUserMutationAction string

const (
	ActionLockUserLogin       LocalUserMutationAction = "LOCK_USER_LOGIN"
	ActionUnlockUserLogin     LocalUserMutationAction = "UNLOCK_USER_LOGIN"
	ActionChangeLocalPassword LocalUserMutationAction = "CHANGE_LOCAL_PASSWORD"
)

type LocalUserSnapshot struct {
	Username         string `json:"username"`
	FullName         string `json:"fullName,omitempty"`
	Comment          string `json:"comment,omitempty"`
	Disabled         bool   `json:"disabled"`
	LockedOut        bool   `json:"lockedOut"`
	PasswordRequired bool   `json:"passwordRequired"`
}

type LocalUserMutationRequest struct {
	Action      LocalUserMutationAction
	Username    string
	NewPassword string
}

type LocalUserMutationResult struct {
	Username        string `json:"username"`
	Action          string `json:"action"`
	Disabled        *bool  `json:"disabled,omitempty"`
	LockedOut       *bool  `json:"lockedOut,omitempty"`
	PasswordChanged bool   `json:"passwordChanged,omitempty"`
}
