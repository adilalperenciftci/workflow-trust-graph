package scan

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func workflowDir(t *testing.T) (string, string) {
	t.Helper()
	root := t.TempDir()
	dir := filepath.Join(root, ".github", "workflows")
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	return root, dir
}

func TestDiscoverSortsAndParsesOnlyWorkflowYAML(t *testing.T) {
	root, dir := workflowDir(t)
	for name, data := range map[string]string{
		"z.yml":     "on: pull_request\njobs: {}\n",
		"a.yaml":    "on: pull_request_target\njobs: {}\n",
		"notes.txt": "not a workflow",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(data), 0644); err != nil {
			t.Fatal(err)
		}
	}
	got, err := Discover(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Path != ".github/workflows/a.yaml" || got[1].Path != ".github/workflows/z.yml" {
		t.Fatalf("unexpected workflows: %#v", got)
	}
}

func TestDiscoverRejectsSymlinkedWorkflowFile(t *testing.T) {
	root, dir := workflowDir(t)
	target := filepath.Join(root, "outside.yml")
	if err := os.WriteFile(target, []byte("on: pull_request\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(dir, "link.yml")); err != nil {
		t.Fatal(err)
	}
	if _, err := Discover(root); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("expected symlink error, got %v", err)
	}
}

func TestDiscoverRejectsSymlinkedWorkflowDirectory(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, ".github"), 0755); err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(root, ".github", "workflows")); err != nil {
		t.Fatal(err)
	}
	if _, err := Discover(root); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("expected symlink error, got %v", err)
	}
}

func TestDiscoverRejectsOversizedWorkflow(t *testing.T) {
	root, dir := workflowDir(t)
	if err := os.WriteFile(filepath.Join(dir, "huge.yml"), []byte(strings.Repeat("x", int(maxWorkflowBytes+1))), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := Discover(root); err == nil || !strings.Contains(err.Error(), "size") {
		t.Fatalf("expected size error, got %v", err)
	}
}

func TestDiscoverAbortsOnAmbiguousYAML(t *testing.T) {
	root, dir := workflowDir(t)
	if err := os.WriteFile(filepath.Join(dir, "bad.yml"), []byte("on: pull_request\non: push\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := Discover(root); err == nil {
		t.Fatal("expected parse error")
	}
}
