package identity

import "time"

func Collect(now time.Time) Inventory {
	return collect(now)
}
