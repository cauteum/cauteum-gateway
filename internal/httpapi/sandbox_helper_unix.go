//go:build !windows

package httpapi

import "os"

func sandboxHelperExecutable(info os.FileInfo) bool {
	return info.Mode().IsRegular() && info.Mode().Perm()&0o111 != 0
}
