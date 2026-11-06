package workflow

import (
	"reflect"
	"strings"
	"testing"
)

func TestParseScalarEventAndPositions(t *testing.T) {
	src := strings.Join([]string{
		"name: audit",
		"on: pull_request",
		"permissions:",
		"  contents: read",
		"  pull-requests: write",
		"jobs:",
		"  inspect:",
		"    needs: [prepare, lint]",
		"    permissions:",
		"      contents: write",
		"    if: always()",
		"    env:",
		"      TITLE: value",
		"    outputs:",
		"      detail: result",
		"    steps:",
		"      - id: show",
		"        run: echo title",
		"        with:",
		"          token: sample",
		"        env:",
		"          STEP: local",
	}, "\n") + "\n"
	wf, err := Parse("sample.yml", []byte(src))
	if err != nil {
		t.Fatal(err)
	}
	if wf.Path != "sample.yml" || wf.Name != "audit" {
		t.Fatalf("workflow identity: %#v", wf)
	}
	if !reflect.DeepEqual(wf.Events, []string{"pull_request"}) {
		t.Fatalf("events: %#v", wf.Events)
	}
	if got := wf.Permissions.Scopes["pull-requests"]; got != "write" {
		t.Fatalf("permission: %q", got)
	}
	if wf.Permissions.Pos != (Pos{File: "sample.yml", Line: 3, Column: 1}) {
		t.Fatalf("permission position: %#v", wf.Permissions.Pos)
	}
	job := wf.Jobs["inspect"]
	if job.Pos != (Pos{File: "sample.yml", Line: 7, Column: 3}) {
		t.Fatalf("job position: %#v", job.Pos)
	}
	if !reflect.DeepEqual(job.Needs, []string{"prepare", "lint"}) {
		t.Fatalf("needs: %#v", job.Needs)
	}
	if !job.Permissions.Specified || job.Permissions.Scopes["contents"] != "write" {
		t.Fatalf("job permissions: %#v", job.Permissions)
	}
	if job.If.Text != "always()" || job.If.Pos.Line != 11 {
		t.Fatalf("if: %#v", job.If)
	}
	if job.Env["TITLE"].Text != "value" || job.Env["TITLE"].Pos.Line != 13 {
		t.Fatalf("env: %#v", job.Env)
	}
	if job.Outputs["detail"].Text != "result" {
		t.Fatalf("outputs: %#v", job.Outputs)
	}
	if len(job.Steps) != 1 || job.Steps[0].ID != "show" {
		t.Fatalf("steps: %#v", job.Steps)
	}
	if job.Steps[0].Run.Text != "echo title" || job.Steps[0].Run.Pos.Line != 18 {
		t.Fatalf("run: %#v", job.Steps[0].Run)
	}
	if job.Steps[0].With["token"].Text != "sample" || job.Steps[0].Env["STEP"].Text != "local" {
		t.Fatalf("step values: %#v", job.Steps[0])
	}
}

func TestParseEventForms(t *testing.T) {
	cases := []struct {
		src  string
		want []string
	}{
		{"on: [workflow_dispatch, pull_request]\n", []string{"workflow_dispatch", "pull_request"}},
		{"on:\n  workflow_dispatch:\n  pull_request:\n    types: [opened]\n", []string{"workflow_dispatch", "pull_request"}},
		{"on: pull_request_target\n", []string{"pull_request_target"}},
	}
	for _, tc := range cases {
		wf, err := Parse("events.yaml", []byte(tc.src))
		if err != nil {
			t.Fatalf("%q: %v", tc.src, err)
		}
		if !reflect.DeepEqual(wf.Events, tc.want) {
			t.Fatalf("%q: got %#v want %#v", tc.src, wf.Events, tc.want)
		}
	}
}

func TestParsePermissionForms(t *testing.T) {
	cases := []struct {
		src, all string
		scopes   map[string]string
	}{
		{"permissions: read-all\n", "read-all", map[string]string{}},
		{"permissions: write-all\n", "write-all", map[string]string{}},
		{"permissions: {}\n", "", map[string]string{}},
		{"permissions:\n  contents: read\n  id-token: write\n", "", map[string]string{"contents": "read", "id-token": "write"}},
	}
	for _, tc := range cases {
		wf, err := Parse("perm.yml", []byte(tc.src))
		if err != nil {
			t.Fatalf("%q: %v", tc.src, err)
		}
		if !wf.Permissions.Specified || wf.Permissions.All != tc.all || !reflect.DeepEqual(wf.Permissions.Scopes, tc.scopes) {
			t.Fatalf("%q: %#v", tc.src, wf.Permissions)
		}
	}
	wf, err := Parse("none.yml", []byte("on: push\n"))
	if err != nil || wf.Permissions.Specified {
		t.Fatalf("omitted permissions: %#v, %v", wf.Permissions, err)
	}
}

func TestParseRejectsAmbiguityAndInvalidShapes(t *testing.T) {
	cases := []struct{ name, src string }{
		{"duplicate root", "on: pull_request\non: push\n"},
		{"duplicate nested", "permissions:\n  contents: read\n  contents: write\n"},
		{"duplicate step", "jobs:\n  x:\n    steps:\n      - run: echo x\n        run: echo y\n"},
		{"alias", "x: &anchor value\ny: *anchor\n"},
		{"merge", "jobs:\n  x:\n    <<: {steps: []}\n"},
		{"unknown tag", "on: !event pull_request\n"},
		{"bad scalar permission", "permissions: something\n"},
		{"bad scope permission", "permissions:\n  contents: execute\n"},
		{"null permission", "permissions:\n"},
		{"bad event", "on: true\n"},
		{"nonmapping root", "- on\n- pull_request\n"},
		{"bad needs", "jobs:\n  x:\n    needs: {one: two}\n"},
		{"bad env", "jobs:\n  x:\n    env:\n      TITLE: [a, b]\n"},
		{"bad steps", "jobs:\n  x:\n    steps: {run: echo x}\n"},
		{"malformed yaml", "on: [pull_request\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Parse("invalid.yml", []byte(tc.src)); err == nil {
				t.Fatalf("accepted %q", tc.src)
			}
		})
	}
}

func TestParseReusableJobAndNeedsString(t *testing.T) {
	src := "on: workflow_call\njobs:\n  reuse:\n    uses: ./.github/workflows/child.yml\n    needs: setup\n    with:\n      revision: main\n"
	wf, err := Parse("call.yml", []byte(src))
	if err != nil {
		t.Fatal(err)
	}
	job := wf.Jobs["reuse"]
	if !reflect.DeepEqual(job.Needs, []string{"setup"}) || job.Uses.Text != "./.github/workflows/child.yml" || job.Uses.Pos.Line != 4 || job.With["revision"].Text != "main" {
		t.Fatalf("reusable job: %#v", job)
	}
}

func TestParseLongStandardTag(t *testing.T) {
	wf, err := Parse("long-tag.yml", []byte("on: !<tag:yaml.org,2002:str> pull_request\n"))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(wf.Events, []string{"pull_request"}) {
		t.Fatalf("events: %#v", wf.Events)
	}
}

func TestShortTagLongForm(t *testing.T) {
	if got := shortTag("tag:yaml.org,2002:str"); got != "!!str" {
		t.Fatalf("short tag: %q", got)
	}
}

func FuzzParse(f *testing.F) {
	for _, seed := range []string{
		"on: pull_request\n",
		"on: [pull_request, push]\npermissions:\n  contents: write\n",
		"jobs:\n  one:\n    steps:\n      - run: echo ok\n",
		"x: &base [one]\ny: *base\n",
		"permissions:\n  contents: read\n  contents: write\n",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, source string) {
		if len(source) > 1<<20 {
			return
		}
		wf, err := Parse("fuzz.yml", []byte(source))
		if err == nil && wf.Path != "fuzz.yml" {
			t.Fatalf("wrong path: %q", wf.Path)
		}
	})
}

func TestParseRootEnvironmentAndStepCondition(t *testing.T) {
	src := "on: pull_request\nenv:\n  ROOT: root-value\njobs:\n  check:\n    steps:\n      - if: success()\n        run: echo ok\n"
	wf, err := Parse("env.yml", []byte(src))
	if err != nil {
		t.Fatal(err)
	}
	if got := wf.Env["ROOT"]; got.Text != "root-value" || got.Pos != (Pos{File: "env.yml", Line: 3, Column: 9}) {
		t.Fatalf("workflow env: %#v", got)
	}
	step := wf.Jobs["check"].Steps[0]
	if step.If.Text != "success()" || step.If.Pos != (Pos{File: "env.yml", Line: 7, Column: 13}) {
		t.Fatalf("step if: %#v", step.If)
	}
}
