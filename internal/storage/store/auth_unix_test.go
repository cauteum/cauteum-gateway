//go:build !windows

package store

import (
	"os"
	"path/filepath"
	"testing"
)

func TestStateAndTokenFilePermissions(t *testing.T) {
	st := openTest(t)
	path, err := st.WriteAuthTokenFile()
	if err != nil {
		t.Fatal(err)
	}
	for p, want := range map[string]os.FileMode{
		st.DataDir:                              0o700,
		path:                                    0o600,
		filepath.Join(st.DataDir, "state.json"): 0o600,
	} {
		fi, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		if got := fi.Mode().Perm(); got != want {
			t.Errorf("%s mode = %o, want %o", p, got, want)
		}
	}
}
