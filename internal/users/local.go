package users

import "errors"

var ErrLocalUserListingUnsupported = errors.New("local user listing is only supported on Windows in this build")

type LocalUserSnapshot struct {
	Username         string `json:"username"`
	FullName         string `json:"fullName,omitempty"`
	Comment          string `json:"comment,omitempty"`
	Disabled         bool   `json:"disabled"`
	LockedOut        bool   `json:"lockedOut"`
	PasswordRequired bool   `json:"passwordRequired"`
}
