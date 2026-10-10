//go:build !windows

package httpapi

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSandboxHelperRequiresExecutePermission(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("CAUTEUM_HELPERS_DIR", dir)
	path := filepath.Join(dir, "cauteum-init")
	if err := os.WriteFile(path, []byte("binary"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := sandboxHelperPath("cauteum-init"); err == nil {
		t.Fatal("non-executable helper was accepted")
	}
	if err := os.Chmod(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if got, err := sandboxHelperPath("cauteum-init"); err != nil || got != path {
		t.Fatalf("executable helper path=%q err=%v", got, err)
	}
}
