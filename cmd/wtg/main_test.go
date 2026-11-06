package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func cliRepo(t *testing.T, data string) string {
	t.Helper()
	root := t.TempDir()
	dir := filepath.Join(root, ".github", "workflows")
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "probe.yml"), []byte(data), 0644); err != nil {
		t.Fatal(err)
	}
	return root
}

func TestJSONReportsEvidenceAndStableOutput(t *testing.T) {
	root := cliRepo(t, "on: pull_request_target\npermissions:\n  contents: write\njobs:\n  review:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo ${{ github.event.pull_request.title }}\n")
	var first, second, stderr bytes.Buffer
	if code := run([]string{"--json", root}, &first, &stderr); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	stderr.Reset()
	if code := run([]string{"--json", root}, &second, &stderr); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	if !bytes.Equal(first.Bytes(), second.Bytes()) {
		t.Fatal("identical input produced different JSON")
	}
	var result struct {
		Version   int               `json:"version"`
		Workflows int               `json:"workflows"`
		Findings  []json.RawMessage `json:"findings"`
	}
	if err := json.Unmarshal(first.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Version == 0 || result.Workflows != 1 || len(result.Findings) != 1 {
		t.Fatalf("unexpected report: %s", first.String())
	}
}

func TestMalformedWorkflowIsErrorNotPartialReport(t *testing.T) {
	root := cliRepo(t, "on: pull_request\non: push\n")
	var stdout, stderr bytes.Buffer
	if code := run([]string{"--json", root}, &stdout, &stderr); code != 2 {
		t.Fatalf("expected exit 2; got %d, %q", code, stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatal("unexpected partial JSON")
	}
}

func TestFailOnFindingsExitCode(t *testing.T) {
	root := cliRepo(t, "on: pull_request_target\npermissions: write-all\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo ${{ github.event.pull_request.title }}\n")
	var stdout, stderr bytes.Buffer
	if code := run([]string{"--fail-on-findings", root}, &stdout, &stderr); code != 3 {
		t.Fatalf("expected exit 3; got %d, %q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "2 review candidates;") {
		t.Fatalf("missing singular candidate summary: %q", stdout.String())
	}
}

func TestHumanSummaryUsesSingularWorkflowFile(t *testing.T) {
	root := cliRepo(t, "on: push\njobs: {}\n")
	var stdout, stderr bytes.Buffer
	if code := run([]string{root}, &stdout, &stderr); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	if !strings.HasPrefix(stdout.String(), "1 workflow file;") {
		t.Fatalf("unexpected summary: %q", stdout.String())
	}
}

func TestHumanSummaryUsesSingularCoverageGap(t *testing.T) {
	root := cliRepo(t, "on: pull_request_target\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo ok\n")
	var stdout, stderr bytes.Buffer
	if code := run([]string{root}, &stdout, &stderr); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "1 coverage gap\n") {
		t.Fatalf("unexpected summary: %q", stdout.String())
	}
}

func TestHumanSummaryUsesSingularCandidate(t *testing.T) {
	root := cliRepo(t, "on: pull_request_target\npermissions: {contents: write}\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo ${{ github.event.pull_request.title }}\n")
	var stdout, stderr bytes.Buffer
	if code := run([]string{root}, &stdout, &stderr); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "1 review candidate;") {
		t.Fatalf("unexpected summary: %q", stdout.String())
	}
}

func TestHumanOutputMarksTruncatedFindings(t *testing.T) {
	data := "on: pull_request_target\npermissions: {contents: write}\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n" +
		strings.Repeat("      - run: echo ${{ github.event.pull_request.title }}\n", 10002)
	root := cliRepo(t, data)
	var stdout, stderr bytes.Buffer
	if code := run([]string{root}, &stdout, &stderr); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "findings truncated") {
		t.Fatalf("missing truncation notice in human output")
	}
}
