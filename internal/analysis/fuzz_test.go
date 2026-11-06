package analysis

import (
	"testing"

	"github.com/adilalperenciftci/workflow-trust-graph/internal/workflow"
)

func FuzzPermissionWeakening(f *testing.F) {
	f.Add("contents", "echo ${{ github.event.pull_request.title }}")
	f.Add("id-token", "echo ${{ github.head_ref }}")
	f.Add("made-up-scope", "echo ${{ github.event.pull_request.body }}")
	f.Add("issues", "echo plain")
	f.Fuzz(func(t *testing.T, scope, command string) {
		if len(scope) > 128 || len(command) > 4096 {
			return
		}
		count := func(level string) int {
			j := workflow.Job{
				ID:    "j",
				Pos:   workflow.Pos{File: "fuzz.yml", Line: 1, Column: 1},
				Steps: []workflow.Step{{Run: workflow.Scalar{Text: command, Pos: workflow.Pos{File: "fuzz.yml", Line: 2, Column: 1}}}},
			}
			w := workflow.Workflow{
				Path:   "fuzz.yml",
				Events: []string{"pull_request_target"},
				Permissions: workflow.Permission{
					Specified: true,
					Scopes:    map[string]string{scope: level},
					Pos:       workflow.Pos{File: "fuzz.yml", Line: 1, Column: 1},
				},
				Jobs: map[string]workflow.Job{"j": j},
			}
			return len(Analyze([]workflow.Workflow{w}).Findings)
		}
		write, read, none := count("write"), count("read"), count("none")
		if read > write || none > read {
			t.Fatalf("permission weakening introduced candidates: write=%d read=%d none=%d", write, read, none)
		}
	})
}
