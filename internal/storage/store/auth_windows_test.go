package store

import (
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func TestStateAndTokenFileOwnerACL(t *testing.T) {
	st := openTest(t)
	path, err := st.WriteAuthTokenFile()
	if err != nil {
		t.Fatal(err)
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{st.DataDir, path, filepath.Join(st.DataDir, "state.json")} {
		sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
		if err != nil {
			t.Fatal(err)
		}
		dacl, _, err := sd.DACL()
		if err != nil || dacl == nil || dacl.AceCount != 1 {
			t.Fatalf("%s DACL: ace count=%v err=%v", path, dacl, err)
		}
		control, _, err := sd.Control()
		if err != nil || control&windows.SE_DACL_PROTECTED == 0 {
			t.Fatalf("%s inherited DACL: control=%v err=%v", path, control, err)
		}
		if !strings.Contains(sd.String(), user.User.Sid.String()) {
			t.Fatalf("%s DACL does not name current user: %s", path, sd.String())
		}
	}
}
