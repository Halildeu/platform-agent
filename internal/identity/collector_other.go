//go:build !windows

package identity

import (
	"os"
	"os/user"
	"runtime"
	"time"
)

func collect(now time.Time) Inventory {
	hostname, _ := os.Hostname()
	inv := Inventory{
		Hostname:        hostname,
		OSVersion:       runtime.GOOS,
		OSBuild:         runtime.GOARCH,
		AzureAdJoined:   "UNKNOWN",
		DomainJoined:    "UNKNOWN",
		WorkplaceJoined: "UNKNOWN",
		DomainProbe:     "SKIPPED_NON_WINDOWS",
		Classification:  ClassificationLocal,
		CollectedAt:     now,
	}
	if current, err := user.Current(); err == nil {
		inv.LoggedIn = BuildLoggedInIdentity(current.Username, "", current.Uid)
	} else {
		inv.ProbeErrors = append(inv.ProbeErrors, "current user probe failed")
	}
	return inv
}
