//go:build !aix && !darwin && !dragonfly && !freebsd && !illumos && !ios && !linux && !netbsd && !openbsd && !solaris

package cache

import "os"

// Some platforms do not expose a portable file-owner identifier through
// os.FileInfo. The private directory and marker checks still apply there.
func ownedByCurrentUser(info os.FileInfo) bool {
	return info != nil
}
