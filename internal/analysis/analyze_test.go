package analysis

import (
	"encoding/json"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/adilalperenciftci/workflow-trust-graph/internal/workflow"
)

func sc(text string, line int) workflow.Scalar {
	return workflow.Scalar{Text: text, Pos: workflow.Pos{File: ".github/workflows/ci.yml", Line: line, Column: 3}}
}

func perm(scopes map[string]string) workflow.Permission {
	return workflow.Permission{Specified: true, Scopes: scopes, Pos: workflow.Pos{File: ".github/workflows/ci.yml", Line: 2, Column: 1}}
}

func baseJob(run string) workflow.Job {
	return workflow.Job{
		ID:    "publish",
		Pos:   workflow.Pos{File: ".github/workflows/ci.yml", Line: 4, Column: 3},
		Steps: []workflow.Step{{ID: "script", Pos: workflow.Pos{File: ".github/workflows/ci.yml", Line: 5, Column: 5}, Run: sc(run, 6)}},
	}
}

func baseWorkflow(job workflow.Job) workflow.Workflow {
	return workflow.Workflow{
		Path:        ".github/workflows/ci.yml",
		Events:      []string{"pull_request_target"},
		Permissions: perm(map[string]string{"contents": "write"}),
		Jobs:        map[string]workflow.Job{job.ID: job},
	}
}

func hasGap(r Report, reason string) bool {
	for _, gap := range r.Gaps {
		if gap.Reason == reason {
			return true
		}
	}
	return false
}

func TestDirectRunRequiresExpressionAndExplicitWrite(t *testing.T) {
	j := baseJob("echo ${{ github.event.pull_request.title }}")
	r := Analyze([]workflow.Workflow{baseWorkflow(j)})
	if len(r.Findings) != 1 {
		t.Fatalf("findings: %#v", r.Findings)
	}
	f := r.Findings[0]
	if f.Event != "pull_request_target" || f.Kind != "run-expression" || f.Scope != "contents" || f.Capability != "github-token-write" || f.PermissionOrigin != "workflow" {
		t.Fatalf("wrong finding: %#v", f)
	}
	if f.Source.Line != 6 || f.Sink.Line != 6 || len(f.Path) < 2 {
		t.Fatalf("missing positioned evidence: %#v", f)
	}
	if len(Analyze([]workflow.Workflow{baseWorkflow(baseJob("echo github.event.pull_request.title"))}).Findings) != 0 {
		t.Fatal("plain text must not be treated as expression provenance")
	}
	if len(Analyze([]workflow.Workflow{baseWorkflow(baseJob("echo ${{ 'github.event.pull_request.title' }}"))}).Findings) != 0 {
		t.Fatal("quoted expression literal must not be treated as provenance")
	}
}

func TestPermissionPrecedenceAndUnknownAreDistinct(t *testing.T) {
	j := baseJob("echo ${{ github.head_ref }}")
	w := baseWorkflow(j)
	w.Permissions = workflow.Permission{}
	r := Analyze([]workflow.Workflow{w})
	if len(r.Findings) != 0 || !hasGap(r, "permission_unknown") {
		t.Fatalf("omitted default is unknown: %#v", r)
	}
	w.Permissions = perm(map[string]string{"contents": "write"})
	j.Permissions = perm(map[string]string{"contents": "read"})
	w.Jobs[j.ID] = j
	r = Analyze([]workflow.Workflow{w})
	if len(r.Findings) != 0 || hasGap(r, "permission_unknown") {
		t.Fatalf("job declaration overrides workflow: %#v", r)
	}
	j.Permissions = perm(map[string]string{"issues": "write"})
	w.Jobs[j.ID] = j
	r = Analyze([]workflow.Workflow{w})
	if len(r.Findings) != 1 || r.Findings[0].Scope != "issues" || r.Findings[0].PermissionOrigin != "job" {
		t.Fatalf("explicit map does not inherit unmentioned scopes: %#v", r.Findings)
	}
}

func TestWriteAllAndOIDCAreSeparateCapabilities(t *testing.T) {
	j := baseJob("echo ${{ github.head_ref }}")
	w := baseWorkflow(j)
	w.Permissions = perm(map[string]string{"id-token": "write"})
	r := Analyze([]workflow.Workflow{w})
	if len(r.Findings) != 1 || r.Findings[0].Capability != "oidc-token" || r.Findings[0].Scope != "id-token" {
		t.Fatalf("id-token not separated: %#v", r.Findings)
	}
	w.Permissions = workflow.Permission{Specified: true, All: "write-all", Pos: w.Permissions.Pos}
	r = Analyze([]workflow.Workflow{w})
	if len(r.Findings) != 2 {
		t.Fatalf("write-all should expose token and OIDC classes: %#v", r.Findings)
	}
	seen := map[string]bool{}
	for _, f := range r.Findings {
		seen[f.Capability] = true
	}
	if !seen["github-token-write"] || !seen["oidc-token"] {
		t.Fatalf("write-all class split: %#v", r.Findings)
	}
	w.Permissions = workflow.Permission{Specified: true, All: "read-all"}
	if len(Analyze([]workflow.Workflow{w}).Findings) != 0 {
		t.Fatal("read-all is not write-capable")
	}
}

func TestEventScopedAndUnknownTriggerIgnored(t *testing.T) {
	j := baseJob("echo ${{ github.event.pull_request.title }}")
	w := baseWorkflow(j)
	w.Events = []string{"push", "pull_request", "pull_request_target"}
	r := Analyze([]workflow.Workflow{w})
	if len(r.Findings) != 2 || r.Findings[0].Event != "pull_request" || r.Findings[1].Event != "pull_request_target" {
		t.Fatalf("event-scoped findings: %#v", r.Findings)
	}
}

func TestEnvironmentReachabilityIsNotClaimedAsConsumption(t *testing.T) {
	j := baseJob("echo ok")
	j.Env = map[string]workflow.Scalar{"TITLE": sc("${{ github.event.pull_request.title }}", 4)}
	j.Steps[0].Env = map[string]workflow.Scalar{"REF": sc("${{ github.head_ref }}", 5)}
	r := Analyze([]workflow.Workflow{baseWorkflow(j)})
	if len(r.Findings) != 2 {
		t.Fatalf("environment witnesses: %#v", r.Findings)
	}
	for _, f := range r.Findings {
		if f.Kind != "run-environment" || f.Sink.Line != 6 {
			t.Fatalf("wrong environment semantics: %#v", f)
		}
	}
}

func TestCheckoutRequiresSubsequentRun(t *testing.T) {
	checkout := workflow.Step{ID: "co", Pos: workflow.Pos{File: ".github/workflows/ci.yml", Line: 5, Column: 5}, Uses: sc("actions/checkout@v4", 5), With: map[string]workflow.Scalar{"ref": sc("${{ github.event.pull_request.head.sha }}", 6)}}
	run := workflow.Step{ID: "run", Pos: workflow.Pos{File: ".github/workflows/ci.yml", Line: 7, Column: 5}, Run: sc("make test", 8)}
	j := baseJob("")
	j.Steps = []workflow.Step{checkout, run}
	r := Analyze([]workflow.Workflow{baseWorkflow(j)})
	if len(r.Findings) != 1 || r.Findings[0].Kind != "checkout-then-run" || r.Findings[0].Source.Line != 6 || r.Findings[0].Sink.Line != 8 {
		t.Fatalf("checkout path: %#v", r.Findings)
	}
	j.Steps = []workflow.Step{run, checkout}
	if len(Analyze([]workflow.Workflow{baseWorkflow(j)}).Findings) != 0 {
		t.Fatal("later checkout cannot reach earlier run")
	}
}

func TestNeedsPropagationRequiresDirectOutputAndDeclaredNeed(t *testing.T) {
	producer := workflow.Job{ID: "collect", Pos: workflow.Pos{File: ".github/workflows/ci.yml", Line: 10, Column: 3}, Outputs: map[string]workflow.Scalar{"title": sc("${{ github.event.pull_request.title }}", 11)}}
	consumer := baseJob("echo ${{ needs.collect.outputs.title }}")
	consumer.Needs = []string{"collect"}
	w := baseWorkflow(consumer)
	w.Jobs[producer.ID] = producer
	r := Analyze([]workflow.Workflow{w})
	if len(r.Findings) != 1 || r.Findings[0].Source.Line != 11 || !strings.Contains(r.Findings[0].SourceExpression, "github.event.pull_request.title") || len(r.Findings[0].Path) < 3 {
		t.Fatalf("needs path: %#v", r.Findings)
	}
	consumer.Needs = nil
	w.Jobs[consumer.ID] = consumer
	r = Analyze([]workflow.Workflow{w})
	if len(r.Findings) != 0 || !hasGap(r, "needs_edge_unresolved") {
		t.Fatalf("undeclared dependency must not propagate: %#v", r)
	}
	producer.Outputs["title"] = sc("${{ steps.collect.outputs.title }}", 11)
	consumer.Needs = []string{"collect"}
	w.Jobs[consumer.ID], w.Jobs[producer.ID] = consumer, producer
	r = Analyze([]workflow.Workflow{w})
	if len(r.Findings) != 0 || !hasGap(r, "output_origin_unknown") {
		t.Fatalf("indirect origin must remain unknown: %#v", r)
	}
}

func TestReusableAndNeedsCycleAreCoverageGaps(t *testing.T) {
	call := workflow.Job{ID: "call", Uses: sc("./.github/workflows/reusable.yml", 5), Pos: workflow.Pos{File: ".github/workflows/ci.yml", Line: 5, Column: 3}}
	a := workflow.Job{ID: "a", Needs: []string{"b"}, Pos: workflow.Pos{File: ".github/workflows/ci.yml", Line: 10, Column: 3}}
	b := workflow.Job{ID: "b", Needs: []string{"a"}, Pos: workflow.Pos{File: ".github/workflows/ci.yml", Line: 20, Column: 3}}
	w := baseWorkflow(call)
	w.Jobs["a"], w.Jobs["b"] = a, b
	r := Analyze([]workflow.Workflow{w})
	if !hasGap(r, "reusable_workflow_unmodeled") || !hasGap(r, "needs_cycle") {
		t.Fatalf("coverage gaps: %#v", r.Gaps)
	}
}

func TestPermissionReductionCannotIntroduceConfirmedCandidate(t *testing.T) {
	j := baseJob("echo ${{ github.head_ref }}")
	for _, p := range []workflow.Permission{
		perm(map[string]string{"contents": "write"}),
		perm(map[string]string{"contents": "read"}),
		perm(map[string]string{}),
	} {
		w := baseWorkflow(j)
		w.Permissions = p
		got := len(Analyze([]workflow.Workflow{w}).Findings)
		if p.Scopes["contents"] == "write" && got != 1 {
			t.Fatalf("expected one finding at write: %d", got)
		}
		if p.Scopes["contents"] != "write" && got != 0 {
			t.Fatalf("reduced permission introduced finding: %d", got)
		}
	}
}

func TestIndependentJobOrderDoesNotAlterSemanticResults(t *testing.T) {
	j := baseJob("echo ${{ github.head_ref }}")
	k := baseJob("echo ${{ github.event.pull_request.title }}")
	k.ID = "other"
	w1, w2 := baseWorkflow(j), baseWorkflow(k)
	w1.Jobs[k.ID] = k
	w2.Jobs[j.ID] = j
	r1, r2 := Analyze([]workflow.Workflow{w1}), Analyze([]workflow.Workflow{w2})
	if !reflect.DeepEqual(r1, r2) {
		b1, _ := json.Marshal(r1)
		b2, _ := json.Marshal(r2)
		t.Fatalf("unstable map order: %s vs %s", b1, b2)
	}
}

func TestStepEnvironmentShadowsJobEnvironment(t *testing.T) {
	j := baseJob("echo ok")
	j.Env = map[string]workflow.Scalar{"TITLE": sc("${{ github.event.pull_request.title }}", 4)}
	j.Steps[0].Env = map[string]workflow.Scalar{"TITLE": sc("safe", 5)}
	r := Analyze([]workflow.Workflow{baseWorkflow(j)})
	if len(r.Findings) != 0 {
		t.Fatalf("shadowed job env cannot reach step process: %#v", r.Findings)
	}
}

func TestContextNameMustBeRootOfExpressionPath(t *testing.T) {
	j := baseJob("echo ${{ vars.github.event.pull_request.title }}")
	r := Analyze([]workflow.Workflow{baseWorkflow(j)})
	if len(r.Findings) != 0 {
		t.Fatalf("nested property named github is not the GitHub context: %#v", r.Findings)
	}
}

func TestDuplicateEventDeclarationDoesNotDuplicateFinding(t *testing.T) {
	j := baseJob("echo ${{ github.head_ref }}")
	w := baseWorkflow(j)
	w.Events = []string{"pull_request", "pull_request"}
	r := Analyze([]workflow.Workflow{w})
	if len(r.Findings) != 1 {
		t.Fatalf("event deduplication: %#v", r.Findings)
	}
}

func TestEnvironmentPrecedenceAcrossAllScopes(t *testing.T) {
	j := baseJob("echo ok")
	w := baseWorkflow(j)
	w.Env = map[string]workflow.Scalar{"TITLE": sc("${{ github.event.pull_request.title }}", 3)}
	r := Analyze([]workflow.Workflow{w})
	if len(r.Findings) != 1 || !strings.Contains(r.Findings[0].Path[2].Detail, "workflow.env.TITLE") {
		t.Fatalf("workflow env should reach run: %#v", r.Findings)
	}

	j.Env = map[string]workflow.Scalar{"TITLE": sc("safe", 4)}
	w.Jobs[j.ID] = j
	if got := Analyze([]workflow.Workflow{w}); len(got.Findings) != 0 {
		t.Fatalf("job env must shadow workflow env: %#v", got.Findings)
	}

	j.Env["TITLE"] = sc("${{ github.head_ref }}", 4)
	w.Jobs[j.ID] = j
	r = Analyze([]workflow.Workflow{w})
	if len(r.Findings) != 1 || r.Findings[0].SourceExpression != "github.head_ref" {
		t.Fatalf("job env source must replace workflow source: %#v", r.Findings)
	}

	j.Steps[0].Env = map[string]workflow.Scalar{"TITLE": sc("safe", 5)}
	w.Jobs[j.ID] = j
	if got := Analyze([]workflow.Workflow{w}); len(got.Findings) != 0 {
		t.Fatalf("step env must shadow job env: %#v", got.Findings)
	}

	j.Steps[0].Env["TITLE"] = sc("${{ github.event.pull_request.body }}", 5)
	w.Jobs[j.ID] = j
	r = Analyze([]workflow.Workflow{w})
	if len(r.Findings) != 1 || r.Findings[0].SourceExpression != "github.event.pull_request.body" {
		t.Fatalf("step env source must replace all outer sources: %#v", r.Findings)
	}
}

func TestConditionalStepRemainsCandidateWithReachabilityGap(t *testing.T) {
	j := baseJob("echo ${{ github.head_ref }}")
	j.Steps[0].If = sc("${{ github.event.pull_request.draft == false }}", 5)
	r := Analyze([]workflow.Workflow{baseWorkflow(j)})
	if len(r.Findings) != 1 || !hasGap(r, "condition_unmodeled") {
		t.Fatalf("condition must not be assumed true or false: %#v", r)
	}
}

func TestFindingIncludesPermissionEvidence(t *testing.T) {
	j := baseJob("echo ${{ github.head_ref }}")
	r := Analyze([]workflow.Workflow{baseWorkflow(j)})
	if len(r.Findings) != 1 || len(r.Findings[0].Path) < 3 || r.Findings[0].Path[0].Kind != "permission" || r.Findings[0].Path[0].At.Line != 2 {
		t.Fatalf("permission witness missing from path: %#v", r.Findings)
	}
}

func TestPlatformAssignedPRNumberIsNotContributorOrigin(t *testing.T) {
	j := baseJob("echo ${{ github.event.pull_request.number }}")
	if got := Analyze([]workflow.Workflow{baseWorkflow(j)}); len(got.Findings) != 0 {
		t.Fatalf("platform-assigned PR number is not an allowlisted source: %#v", got.Findings)
	}
	j.Steps[0].Run = sc("echo ${{ github.event.pull_request.title }}", 6)
	if got := Analyze([]workflow.Workflow{baseWorkflow(j)}); len(got.Findings) != 1 {
		t.Fatalf("contributor-controlled title remains a source: %#v", got.Findings)
	}
}

func TestUnknownWriteScopeIsCoverageGapNotCapability(t *testing.T) {
	j := baseJob("echo ${{ github.head_ref }}")
	w := baseWorkflow(j)
	w.Permissions = perm(map[string]string{"made-up": "write"})
	r := Analyze([]workflow.Workflow{w})
	if len(r.Findings) != 0 || !hasGap(r, "permission_scope_unmodeled") {
		t.Fatalf("unknown scope cannot become confirmed capability: %#v", r)
	}
}

func TestActionInputsAndInheritedEnvironmentAreCoverageGaps(t *testing.T) {
	action := workflow.Step{ID: "external", Uses: sc("vendor/action@v1", 8),
		With: map[string]workflow.Scalar{"message": sc("${{ github.event.pull_request.title }}", 9)}}
	j := baseJob("")
	j.Steps = []workflow.Step{action}
	w := baseWorkflow(j)
	r := Analyze([]workflow.Workflow{w})
	if !hasGap(r, "action_input_unmodeled") || len(r.Findings) != 0 {
		t.Fatalf("external action input must be an explicit gap: %#v", r)
	}

	action.With["message"] = sc("github.event.pull_request.title", 9)
	j.Steps = []workflow.Step{action}
	w.Jobs[j.ID] = j
	r = Analyze([]workflow.Workflow{w})
	if hasGap(r, "action_input_unmodeled") {
		t.Fatalf("plain text is not contributor origin: %#v", r.Gaps)
	}

	w.Env = map[string]workflow.Scalar{"TITLE": sc("${{ github.event.pull_request.title }}", 3)}
	r = Analyze([]workflow.Workflow{w})
	if !hasGap(r, "action_input_unmodeled") {
		t.Fatalf("inherited workflow env reaches action process: %#v", r.Gaps)
	}

	action.Env = map[string]workflow.Scalar{"TITLE": sc("safe", 8)}
	j.Steps = []workflow.Step{action}
	w.Jobs[j.ID] = j
	r = Analyze([]workflow.Workflow{w})
	if hasGap(r, "action_input_unmodeled") {
		t.Fatalf("step env shadows workflow env for action: %#v", r.Gaps)
	}
}

func TestQuotedClosingDelimiterDoesNotHideLaterOrigin(t *testing.T) {
	j := baseJob("echo ${{ format('}}{0}', github.event.pull_request.title) }}")
	r := Analyze([]workflow.Workflow{baseWorkflow(j)})
	if len(r.Findings) != 1 || r.Findings[0].SourceExpression != "github.event.pull_request.title" {
		t.Fatalf("quoted delimiter must not end expression: %#v", r.Findings)
	}
}

func TestRepeatedOriginInOneScalarProducesOneWitness(t *testing.T) {
	j := baseJob("echo ${{ github.head_ref }} ${{ github.head_ref }}")
	r := Analyze([]workflow.Workflow{baseWorkflow(j)})
	if len(r.Findings) != 1 {
		t.Fatalf("same source scalar should produce one witness: %#v", r.Findings)
	}
}

func TestFindingLimitAndCheckoutTraversal(t *testing.T) {
	j := baseJob("")
	j.Steps = nil
	for i := 0; i < 200; i++ {
		j.Steps = append(j.Steps, workflow.Step{ID: "checkout-" + strconv.Itoa(i), Uses: sc("actions/checkout@v4", i+10),
			With: map[string]workflow.Scalar{"ref": sc("${{ github.event.pull_request.head.sha }}", i+10)}})
	}
	for i := 0; i < 200; i++ {
		j.Steps = append(j.Steps, workflow.Step{ID: "run-" + strconv.Itoa(i), Run: sc("echo ok", i+210)})
	}
	w := baseWorkflow(j)
	w.Permissions = perm(map[string]string{"contents": "write", "issues": "write"})
	r := Analyze([]workflow.Workflow{w})
	if len(r.Findings) != 10000 {
		t.Fatalf("expected bounded findings, got %d", len(r.Findings))
	}
	n := 0
	for _, gap := range r.Gaps {
		if gap.Reason == "finding_limit_reached" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("expected one truncation gap, got %d: %#v", n, r.Gaps)
	}
}

func TestRepeatedNeedsOriginInOneScalarProducesOneWitness(t *testing.T) {
	producer := workflow.Job{ID: "collect", Outputs: map[string]workflow.Scalar{"title": sc("${{ github.event.pull_request.title }}", 11)}}
	consumer := baseJob("echo ${{ needs.collect.outputs.title }} ${{ needs.collect.outputs.title }}")
	consumer.Needs = []string{"collect"}
	w := baseWorkflow(consumer)
	w.Jobs[producer.ID] = producer
	r := Analyze([]workflow.Workflow{w})
	if len(r.Findings) != 1 {
		t.Fatalf("same needs output in one scalar should produce one witness: %#v", r.Findings)
	}
}

func TestReadOnlyManyCheckoutRunStepsStayLinear(t *testing.T) {
	j := baseJob("")
	j.Steps = nil
	for i := 0; i < 1000; i++ {
		j.Steps = append(j.Steps, workflow.Step{Uses: sc("actions/checkout@v4", i+10),
			With: map[string]workflow.Scalar{"ref": sc("${{ github.event.pull_request.head.sha }}", i+10)}})
	}
	for i := 0; i < 1000; i++ {
		j.Steps = append(j.Steps, workflow.Step{Run: sc("echo ok", i+1010)})
	}
	w := baseWorkflow(j)
	w.Permissions = perm(map[string]string{"contents": "read"})
	r := Analyze([]workflow.Workflow{w})
	if len(r.Findings) != 0 {
		t.Fatalf("read-only job cannot produce confirmed write candidate: %d", len(r.Findings))
	}
}

func TestGapLimitIsExplicitAndBounded(t *testing.T) {
	w := workflow.Workflow{
		Path:   ".github/workflows/large.yml",
		Events: []string{"pull_request"},
		Jobs:   make(map[string]workflow.Job),
	}
	for i := 0; i < 10050; i++ {
		id := "job-" + strconv.Itoa(i)
		w.Jobs[id] = workflow.Job{ID: id, Pos: workflow.Pos{File: w.Path, Line: i + 1, Column: 1}}
	}
	r := Analyze([]workflow.Workflow{w})
	if len(r.Gaps) != 10001 || !r.GapsTruncated {
		t.Fatalf("expected capped gaps plus sentinel: count=%d truncated=%v", len(r.Gaps), r.GapsTruncated)
	}
	sentinel := 0
	for _, gap := range r.Gaps {
		if gap.Reason == "gap_limit_reached" {
			sentinel++
		}
	}
	if sentinel != 1 {
		t.Fatalf("expected one gap-limit sentinel, got %d", sentinel)
	}
}

func TestCheckoutOtherInputsAndEnvironmentAreUnknown(t *testing.T) {
	checkout := workflow.Step{
		ID: "checkout", Uses: sc("actions/checkout@v4", 5),
		With: map[string]workflow.Scalar{
			"ref":  sc("${{ github.event.pull_request.head.sha }}", 6),
			"path": sc("${{ github.event.pull_request.title }}", 7),
		},
	}
	j := baseJob("")
	j.Steps = []workflow.Step{checkout, {Run: sc("echo ok", 8)}}
	w := baseWorkflow(j)
	w.Env = map[string]workflow.Scalar{"TITLE": sc("${{ github.event.pull_request.body }}", 3)}
	r := Analyze([]workflow.Workflow{w})
	if len(r.Findings) != 2 || !hasGap(r, "action_input_unmodeled") {
		t.Fatalf("modeled ref and unmodeled path/env must be separate: %#v", r)
	}
	for _, gap := range r.Gaps {
		if gap.Reason == "action_input_unmodeled" && gap.At.Line == 6 {
			t.Fatalf("modeled ref must not get duplicate action-input gap: %#v", r.Gaps)
		}
	}
}

func TestCheckoutWithoutLaterRunIsExplicitCoverageGap(t *testing.T) {
	j := baseJob("")
	j.Steps = []workflow.Step{{
		ID: "checkout", Uses: sc("actions/checkout@v4", 5),
		With: map[string]workflow.Scalar{"ref": sc("${{ github.event.pull_request.head.sha }}", 6)},
	}}
	w := baseWorkflow(j)
	r := Analyze([]workflow.Workflow{w})
	if len(r.Findings) != 0 || !hasGap(r, "checkout_followup_unmodeled") {
		t.Fatalf("checkout source without a later run must be a gap: %#v", r)
	}
	j.Steps = append(j.Steps, workflow.Step{Run: sc("echo ok", 8)})
	w.Jobs[j.ID] = j
	r = Analyze([]workflow.Workflow{w})
	if len(r.Findings) != 1 || hasGap(r, "checkout_followup_unmodeled") {
		t.Fatalf("later run should form modeled path: %#v", r)
	}
}
