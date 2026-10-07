package httpapi

import "os"

func sandboxHelperExecutable(info os.FileInfo) bool {
	return info.Mode().IsRegular()
}
