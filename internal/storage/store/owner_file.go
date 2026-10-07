package store

import (
	"os"
	"path/filepath"
)

// writeOwnerOnlyAtomic restricts a temporary file before putting a token or
// state on disk. The final rename never exposes the bytes under a broad ACL.
func writeOwnerOnlyAtomic(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".private-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := restrictOwnerAccess(tmp.Name(), false); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
