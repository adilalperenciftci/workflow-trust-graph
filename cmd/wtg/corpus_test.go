package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/adilalperenciftci/workflow-trust-graph/internal/analysis"
	"github.com/adilalperenciftci/workflow-trust-graph/internal/workflow"
)

func TestControlledCorpus(t *testing.T) {
	cases := []struct {
		file     string
		findings int
		gap      string
	}{
		{"direct-title.yml", 1, ""},
		{"server-number.yml", 0, ""},
		{"literal-context.yml", 0, ""},
		{"read-only.yml", 0, ""},
		{"unknown-default.yml", 0, "permission_unknown"},
		{"checkout-before.yml", 1, ""},
		{"checkout-after.yml", 0, ""},
		{"needs-direct.yml", 1, ""},
		{"needs-missing.yml", 0, "needs_edge_unresolved"},
		{"unknown-scope.yml", 0, "permission_scope_unmodeled"},
		{"push-control.yml", 0, ""},
		{"reusable.yml", 0, "reusable_workflow_unmodeled"},
		{"environment-shadow.yml", 0, ""},
		{"environment-root.yml", 1, ""},
		{"environment-step.yml", 1, ""},
		{"conditioned.yml", 1, "condition_unmodeled"},
	}
	for _, tc := range cases {
		t.Run(tc.file, func(t *testing.T) {
			source, err := os.ReadFile(filepath.Join("..", "..", "testdata", "corpus", tc.file))
			if err != nil {
				t.Fatal(err)
			}
			root := cliRepo(t, string(source))
			var stdout, stderr bytes.Buffer
			if code := run([]string{"--json", root}, &stdout, &stderr); code != 0 {
				t.Fatalf("exit %d: %s", code, stderr.String())
			}
			var report struct {
				Findings []json.RawMessage `json:"findings"`
				Gaps     []struct {
					Reason string `json:"reason"`
				} `json:"gaps"`
			}
			if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
				t.Fatal(err)
			}
			if len(report.Findings) != tc.findings {
				t.Fatalf("findings=%d, want %d; report=%s", len(report.Findings), tc.findings, stdout.String())
			}
			if tc.gap != "" {
				found := false
				for _, gap := range report.Gaps {
					if gap.Reason == tc.gap {
						found = true
					}
				}
				if !found {
					t.Fatalf("missing gap %s; report=%s", tc.gap, stdout.String())
				}
			}
		})
	}
}

var benchmarkReport analysis.Report

func BenchmarkControlledCorpus(b *testing.B) {
	entries, err := os.ReadDir(filepath.Join("..", "..", "testdata", "corpus"))
	if err != nil {
		b.Fatal(err)
	}
	type fixture struct {
		name string
		data []byte
	}
	inputs := make([]fixture, 0, len(entries))
	for _, entry := range entries {
		data, err := os.ReadFile(filepath.Join("..", "..", "testdata", "corpus", entry.Name()))
		if err != nil {
			b.Fatal(err)
		}
		inputs = append(inputs, fixture{name: entry.Name(), data: data})
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		parsed := make([]workflow.Workflow, 0, len(inputs))
		for _, input := range inputs {
			item, err := workflow.Parse(input.name, input.data)
			if err != nil {
				b.Fatal(err)
			}
			parsed = append(parsed, item)
		}
		benchmarkReport = analysis.Analyze(parsed)
	}
}

func TestIndependentJobReorderingPreservesSemanticEvidence(t *testing.T) {
	header := "on: pull_request_target\npermissions: {contents: write}\njobs:\n"
	alpha := "  alpha:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo ${{ github.event.pull_request.title }}\n"
	beta := "  beta:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo ${{ github.head_ref }}\n"
	analyze := func(source string) analysis.Report {
		parsed, err := workflow.Parse("reorder.yml", []byte(source))
		if err != nil {
			t.Fatal(err)
		}
		report := analysis.Analyze([]workflow.Workflow{parsed})
		for i := range report.Findings {
			report.Findings[i].Source = workflow.Pos{}
			report.Findings[i].Sink = workflow.Pos{}
			report.Findings[i].PermissionAt = workflow.Pos{}
			for j := range report.Findings[i].Path {
				report.Findings[i].Path[j].At = workflow.Pos{}
			}
		}
		for i := range report.Gaps {
			report.Gaps[i].At = workflow.Pos{}
		}
		return report
	}
	first := analyze(header + alpha + beta)
	second := analyze(header + beta + alpha)
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("semantic evidence changed after independent job reorder: %#v vs %#v", first, second)
	}
}

func TestControlledCorpusFindingsCarryPositionedWitnesses(t *testing.T) {
	for _, name := range []string{
		"direct-title.yml", "checkout-before.yml", "needs-direct.yml",
		"environment-root.yml", "environment-step.yml", "conditioned.yml",
	} {
		t.Run(name, func(t *testing.T) {
			source, err := os.ReadFile(filepath.Join("..", "..", "testdata", "corpus", name))
			if err != nil {
				t.Fatal(err)
			}
			root := cliRepo(t, string(source))
			var stdout, stderr bytes.Buffer
			if code := run([]string{"--json", root}, &stdout, &stderr); code != 0 {
				t.Fatalf("exit %d: %s", code, stderr.String())
			}
			var report analysis.Report
			if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
				t.Fatal(err)
			}
			if len(report.Findings) == 0 {
				t.Fatal("positive control lacks finding")
			}
			for _, finding := range report.Findings {
				if finding.Source.Line == 0 || finding.Sink.Line == 0 || finding.PermissionAt.Line == 0 {
					t.Fatalf("missing source/sink/permission position: %#v", finding)
				}
				if len(finding.Path) < 3 || finding.Path[0].Kind != "permission" ||
					finding.Path[1].Kind != "origin" || finding.Path[len(finding.Path)-1].Kind != "run" {
					t.Fatalf("invalid evidence ordering: %#v", finding.Path)
				}
				if finding.Capability == "oidc-token" && finding.Scope != "id-token" {
					t.Fatalf("mixed capability classes: %#v", finding)
				}
			}
		})
	}
}
