package store

import (
	"strings"
	"testing"
)

func TestProfileImportAndUpdateAreDistinct(t *testing.T) {
	s, err := Open(t.TempDir(), "test")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.CreateProfile("openai", "id: openai\n"); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.GetProfile("openai"); got.ResourceVersion != "1" || got.Version != 1 {
		t.Fatalf("unexpected initial resource version: %+v", got)
	}
	if err := s.CreateProfile("openai", "id: openai\ndescription: overwrite\n"); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("expected duplicate import error, got %v", err)
	}
	if got, _ := s.GetProfile("openai"); got.YAML != "id: openai\n" {
		t.Fatalf("duplicate import changed profile: %q", got.YAML)
	}
	if err := s.ReplaceProfile("missing", "id: missing\n"); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("expected update-missing error, got %v", err)
	}
	if err := s.ReplaceProfileIfVersion("openai", "id: openai\ndescription: updated\n", "1"); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.GetProfile("openai"); !strings.Contains(got.YAML, "updated") || got.ResourceVersion != "2" {
		t.Fatalf("profile update did not persist: %q", got.YAML)
	}
	if err := s.ReplaceProfileIfVersion("openai", "id: openai\n", "1"); err == nil {
		t.Fatal("expected stale resource version conflict")
	}
}

func TestWorkspaceProfilesOverrideGlobalCatalog(t *testing.T) {
	s, err := Open(t.TempDir(), "test")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.CreateProfile("openai", "id: openai\ndescription: global\n"); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateProfileScoped("workspace", "team-ml", "openai", "id: openai\ndescription: team\n"); err != nil {
		t.Fatal(err)
	}
	got, ok := s.GetProfileScoped("openai", "team-ml")
	if !ok || got.Scope != "workspace" || !strings.Contains(got.YAML, "team") {
		t.Fatalf("workspace profile did not override global: %+v", got)
	}
	got, ok = s.GetProfileScoped("openai", "other")
	if !ok || got.Scope != "global" || !strings.Contains(got.YAML, "global") {
		t.Fatalf("global fallback missing: %+v", got)
	}
	if _, ok := s.GetProfileInScope("workspace", "other", "openai"); ok {
		t.Fatal("workspace profile leaked into another workspace")
	}
}
