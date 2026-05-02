package users

import (
	"os/user"
	"path/filepath"
	"strings"
)

type CurrentUserSnapshot struct {
	Username string `json:"username"`
	Name     string `json:"name,omitempty"`
	UID      string `json:"uid,omitempty"`
	GID      string `json:"gid,omitempty"`
	HomeDir  string `json:"homeDir,omitempty"`
}

type HomePaths struct {
	Home      string `json:"home"`
	Desktop   string `json:"desktop"`
	Documents string `json:"documents"`
	Downloads string `json:"downloads"`
}

func Current() (CurrentUserSnapshot, error) {
	current, err := user.Current()
	if err != nil {
		return CurrentUserSnapshot{}, err
	}
	return CurrentUserSnapshot{
		Username: current.Username,
		Name:     current.Name,
		UID:      current.Uid,
		GID:      current.Gid,
		HomeDir:  current.HomeDir,
	}, nil
}

func CurrentHomePaths() (HomePaths, error) {
	current, err := user.Current()
	if err != nil {
		return HomePaths{}, err
	}
	home := strings.TrimRight(current.HomeDir, string(filepath.Separator))
	return HomePaths{
		Home:      home,
		Desktop:   filepath.Join(home, "Desktop"),
		Documents: filepath.Join(home, "Documents"),
		Downloads: filepath.Join(home, "Downloads"),
	}, nil
}
