package store

import (
	"testing"
)

func TestSandboxStopTransitionsAreDurableAndRecoverable(t *testing.T) {
	st, err := Open(t.TempDir(), "lifecycle")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertSandbox(Sandbox{Name: "demo", Status: "running"}); err != nil {
		t.Fatal(err)
	}
	started, err := st.BeginSandboxStop("demo")
	if err != nil || started.Status != "stopping" {
		t.Fatalf("begin stop=%+v err=%v", started, err)
	}
	if _, err := st.MarkSandboxRunning("demo"); err != nil {
		t.Fatal(err)
	}
	retried, err := st.BeginSandboxStop("demo")
	if err != nil || retried.Status != "stopping" {
		t.Fatalf("retry stop=%+v err=%v", retried, err)
	}
	stopped, err := st.MarkSandboxStopped("demo")
	if err != nil || stopped.Status != "stopped" {
		t.Fatalf("mark stopped=%+v err=%v", stopped, err)
	}
	loaded, ok := st.GetSandbox("demo")
	if !ok || loaded.Status != "stopped" || loaded.ResourceVersion != stopped.ResourceVersion {
		t.Fatalf("durable stopped record=%+v ok=%v", loaded, ok)
	}
}
