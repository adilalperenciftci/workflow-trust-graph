package analysis

import (
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/adilalperenciftci/workflow-trust-graph/internal/workflow"
)

// Report is a syntax-backed review aid, not a statement about runtime authority.
type Report struct {
	Version           int       `json:"version"`
	Workflows         int       `json:"workflows"`
	Findings          []Finding `json:"findings"`
	Gaps              []Gap     `json:"gaps"`
	FindingsTruncated bool      `json:"findings_truncated"`
	GapsTruncated     bool      `json:"gaps_truncated"`
}

type Finding struct {
	Event            string       `json:"event"`
	Workflow         string       `json:"workflow"`
	Job              string       `json:"job"`
	Step             string       `json:"step"`
	Kind             string       `json:"kind"`
	Capability       string       `json:"capability"`
	Scope            string       `json:"scope"`
	PermissionOrigin string       `json:"permission_origin"`
	SourceExpression string       `json:"source_expression"`
	Source           workflow.Pos `json:"source"`
	Sink             workflow.Pos `json:"sink"`
	PermissionAt     workflow.Pos `json:"permission_at"`
	Path             []Evidence   `json:"path"`
}

type Evidence struct {
	Kind   string       `json:"kind"`
	Detail string       `json:"detail"`
	At     workflow.Pos `json:"at"`
}

type Gap struct {
	Event    string       `json:"event"`
	Workflow string       `json:"workflow"`
	Job      string       `json:"job"`
	Reason   string       `json:"reason"`
	At       workflow.Pos `json:"at"`
}

type origin struct {
	expression string
	at         workflow.Pos
	path       []Evidence
}

type capability struct {
	scope string
	class string
}

type envBinding struct {
	value workflow.Scalar
	layer string
}

type checkoutOrigin struct {
	source origin
	name   string
	at     workflow.Pos
}

const (
	maxFindings = 10000
	maxGaps     = 10000
)

var directRE = regexp.MustCompile(`(?i)\b(?:github\.head_ref|github\.event\.pull_request\.(?:head\.repo\.full_name|head\.label|head\.ref|head\.sha|title|body))\b`)
var needsRE = regexp.MustCompile(`(?i)\bneeds\.([A-Za-z_][A-Za-z0-9_-]*)\.outputs\.([A-Za-z_][A-Za-z0-9_-]*)\b`)

// Analyze derives event-scoped, syntax-backed candidate paths from parsed workflows.
func Analyze(workflows []workflow.Workflow) Report {
	report := Report{Version: 1, Workflows: len(workflows), Findings: []Finding{}, Gaps: []Gap{}}
	gapSeen := make(map[string]bool)
	findingLimitReached := false
	gapLimitReached := false

	for _, w := range workflows {
		events := append([]string(nil), w.Events...)
		sort.Strings(events)
		jobIDs := sortedJobIDs(w.Jobs)
		cyclic := needsCycles(w.Jobs)
		for eventIndex, event := range events {
			if eventIndex > 0 && events[eventIndex-1] == event {
				continue
			}
			if event != "pull_request" && event != "pull_request_target" {
				continue
			}
			for _, jobID := range jobIDs {
				j := w.Jobs[jobID]
				addGap := func(reason string, at workflow.Pos) {
					g := Gap{Event: event, Workflow: w.Path, Job: jobID, Reason: reason, At: at}
					key := strings.Join([]string{g.Event, g.Workflow, g.Job, g.Reason, g.At.File, strconv.Itoa(g.At.Line), strconv.Itoa(g.At.Column)}, "\x00")
					if gapSeen[key] || gapLimitReached {
						return
					}
					if len(report.Gaps) >= maxGaps {
						report.GapsTruncated = true
						report.Gaps = append(report.Gaps, Gap{
							Event: event, Workflow: w.Path, Job: jobID,
							Reason: "gap_limit_reached", At: at,
						})
						gapLimitReached = true
						return
					}
					gapSeen[key] = true
					report.Gaps = append(report.Gaps, g)
				}

				p, permissionOrigin := effectivePermission(w, j)
				if !p.Specified {
					addGap("permission_unknown", j.Pos)
				}
				if cyclic[jobID] {
					addGap("needs_cycle", j.Pos)
				}
				if j.If.Text != "" && strings.TrimSpace(j.If.Text) != "true" {
					addGap("condition_unmodeled", j.If.Pos)
				}
				if j.Uses.Text != "" {
					addGap("reusable_workflow_unmodeled", j.Uses.Pos)
					continue
				}

				caps, unknownScopes := writeCapabilities(p)
				if len(unknownScopes) > 0 {
					addGap("permission_scope_unmodeled", p.Pos)
				}
				emit := func(kind string, source origin, sink workflow.Pos, step string, trail []Evidence) {
					if findingLimitReached {
						return
					}
					for _, cap := range caps {
						if len(report.Findings) >= maxFindings {
							addGap("finding_limit_reached", sink)
							report.FindingsTruncated = true
							findingLimitReached = true
							return
						}
						path := []Evidence{{Kind: "permission", Detail: cap.scope + "=write (" + permissionOrigin + ")", At: p.Pos}}
						path = append(path, source.path...)
						path = append(path, trail...)
						report.Findings = append(report.Findings, Finding{
							Event: event, Workflow: w.Path, Job: jobID, Step: step,
							Kind: kind, Capability: cap.class, Scope: cap.scope,
							PermissionOrigin: permissionOrigin,
							SourceExpression: source.expression,
							Source:           source.at, Sink: sink, PermissionAt: p.Pos,
							Path: path,
						})
					}
				}
				resolve := func(value workflow.Scalar) []origin {
					origins := directOrigins(value)
					for _, ref := range needsReferences(value) {
						if !contains(j.Needs, ref.job) || cyclic[jobID] || cyclic[ref.job] {
							addGap("needs_edge_unresolved", value.Pos)
							continue
						}
						producer, ok := w.Jobs[ref.job]
						if !ok {
							addGap("needs_edge_unresolved", value.Pos)
							continue
						}
						produced, ok := producer.Outputs[ref.output]
						if !ok {
							addGap("output_origin_unknown", value.Pos)
							continue
						}
						fromOutput := directOrigins(produced)
						if len(fromOutput) == 0 {
							addGap("output_origin_unknown", produced.Pos)
							continue
						}
						for _, source := range fromOutput {
							source.path = append(source.path,
								Evidence{Kind: "job-output", Detail: ref.job + "." + ref.output, At: produced.Pos},
								Evidence{Kind: "needs", Detail: ref.job + "." + ref.output, At: value.Pos})
							origins = append(origins, source)
						}
					}
					return origins
				}

				priorCheckouts := make([]checkoutOrigin, 0)
				futureRun := make([]bool, len(j.Steps))
				hasLaterRun := false
				for index := len(j.Steps) - 1; index >= 0; index-- {
					futureRun[index] = hasLaterRun
					if j.Steps[index].Run.Text != "" {
						hasLaterRun = true
					}
				}
				for index, step := range j.Steps {
					if step.If.Text != "" && strings.TrimSpace(step.If.Text) != "true" {
						addGap("condition_unmodeled", step.If.Pos)
					}
					stepID := step.ID
					if stepID == "" {
						stepID = "#" + strconv.Itoa(index+1)
					}
					isCheckout := strings.HasPrefix(strings.ToLower(step.Uses.Text), "actions/checkout@")
					env := mergedEnv(w.Env, j.Env, step.Env)

					if step.Uses.Text != "" {
						for _, name := range sortedEnvKeys(step.With) {
							if isCheckout && (name == "ref" || name == "repository") {
								continue
							}
							value := step.With[name]
							if len(resolve(value)) > 0 {
								addGap("action_input_unmodeled", value.Pos)
							}
						}
						for _, name := range sortedEnvKeys(env) {
							value := env[name].value
							if len(resolve(value)) > 0 {
								addGap("action_input_unmodeled", value.Pos)
							}
						}
					}
					var checkoutCandidates []checkoutOrigin
					if isCheckout {
						for _, name := range []string{"ref", "repository"} {
							value, ok := step.With[name]
							if !ok {
								continue
							}
							origins := resolve(value)
							if len(origins) > 0 && !futureRun[index] {
								addGap("checkout_followup_unmodeled", value.Pos)
							}
							if futureRun[index] && !findingLimitReached && len(caps) > 0 {
								for _, source := range origins {
									if len(checkoutCandidates) < maxFindings+1 {
										checkoutCandidates = append(checkoutCandidates, checkoutOrigin{source: source, name: name, at: value.Pos})
									}
								}
							}
						}
					}
					if findingLimitReached || len(caps) == 0 {
						continue
					}

					if step.Run.Text != "" {
						for _, source := range resolve(step.Run) {
							emit("run-expression", source, step.Run.Pos, stepID,
								[]Evidence{{Kind: "run", Detail: "expression interpolation", At: step.Run.Pos}})
							if findingLimitReached {
								break
							}
						}
						if !findingLimitReached {
							for _, name := range sortedEnvKeys(env) {
								binding := env[name]
								for _, source := range resolve(binding.value) {
									emit("run-environment", source, step.Run.Pos, stepID,
										[]Evidence{
											{Kind: "environment", Detail: binding.layer + ".env." + name, At: binding.value.Pos},
											{Kind: "run", Detail: "process environment reachable", At: step.Run.Pos},
										})
									if findingLimitReached {
										break
									}
								}
								if findingLimitReached {
									break
								}
							}
						}
						if !findingLimitReached {
							for _, checkout := range priorCheckouts {
								emit("checkout-then-run", checkout.source, step.Run.Pos, stepID,
									[]Evidence{
										{Kind: "checkout", Detail: "actions/checkout with." + checkout.name, At: checkout.at},
										{Kind: "run", Detail: "subsequent run step", At: step.Run.Pos},
									})
								if findingLimitReached {
									break
								}
							}
						}
					}

					if !findingLimitReached {
						for _, candidate := range checkoutCandidates {
							if len(priorCheckouts) < maxFindings+1 {
								priorCheckouts = append(priorCheckouts, candidate)
							}
						}
					}
				}
			}
		}
	}

	sort.Slice(report.Findings, func(i, j int) bool { return findingKey(report.Findings[i]) < findingKey(report.Findings[j]) })
	sort.Slice(report.Gaps, func(i, j int) bool { return gapKey(report.Gaps[i]) < gapKey(report.Gaps[j]) })
	return report
}

func sortedJobIDs(jobs map[string]workflow.Job) []string {
	ids := make([]string, 0, len(jobs))
	for id := range jobs {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

func sortedEnvKeys[T any](values map[string]T) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func mergedEnv(workflowEnv, jobEnv, stepEnv map[string]workflow.Scalar) map[string]envBinding {
	env := make(map[string]envBinding)
	for name, value := range workflowEnv {
		env[name] = envBinding{value: value, layer: "workflow"}
	}
	for name, value := range jobEnv {
		env[name] = envBinding{value: value, layer: "job"}
	}
	for name, value := range stepEnv {
		env[name] = envBinding{value: value, layer: "step"}
	}
	return env
}

func effectivePermission(w workflow.Workflow, j workflow.Job) (workflow.Permission, string) {
	if j.Permissions.Specified {
		return j.Permissions, "job"
	}
	if w.Permissions.Specified {
		return w.Permissions, "workflow"
	}
	return workflow.Permission{}, "unknown"
}

var knownScopes = map[string]bool{
	"actions": true, "attestations": true, "checks": true,
	"contents": true, "deployments": true, "discussions": true,
	"id-token": true, "issues": true, "models": true,
	"packages": true, "pages": true, "pull-requests": true,
	"repository-projects": true, "security-events": true, "statuses": true,
}

func writeCapabilities(p workflow.Permission) ([]capability, []string) {
	if !p.Specified {
		return nil, nil
	}
	if p.All == "write-all" {
		return []capability{{scope: "*", class: "github-token-write"}, {scope: "id-token", class: "oidc-token"}}, nil
	}
	if p.All != "" {
		return nil, nil
	}
	var caps []capability
	var unknown []string
	for scope, level := range p.Scopes {
		if !knownScopes[scope] {
			unknown = append(unknown, scope)
			continue
		}
		if level != "write" {
			continue
		}
		class := "github-token-write"
		if scope == "id-token" {
			class = "oidc-token"
		}
		caps = append(caps, capability{scope: scope, class: class})
	}
	sort.Slice(caps, func(i, j int) bool { return caps[i].scope < caps[j].scope })
	sort.Strings(unknown)
	return caps, unknown
}

func directOrigins(value workflow.Scalar) []origin {
	var origins []origin
	seen := make(map[string]bool)
	for _, expression := range expressions(value.Text) {
		for _, match := range directRE.FindAllStringIndex(expression, -1) {
			if match[0] > 0 && expression[match[0]-1] == '.' {
				continue
			}
			token := expression[match[0]:match[1]]
			key := strings.ToLower(token)
			if seen[key] {
				continue
			}
			seen[key] = true
			origins = append(origins, origin{
				expression: token,
				at:         value.Pos,
				path:       []Evidence{{Kind: "origin", Detail: token, At: value.Pos}},
			})
		}
	}
	return origins
}

type outputRef struct {
	job    string
	output string
}

func needsReferences(value workflow.Scalar) []outputRef {
	var refs []outputRef
	seen := make(map[string]bool)
	for _, expression := range expressions(value.Text) {
		for _, match := range needsRE.FindAllStringSubmatchIndex(expression, -1) {
			if match[0] > 0 && expression[match[0]-1] == '.' {
				continue
			}
			job := expression[match[2]:match[3]]
			output := expression[match[4]:match[5]]
			key := job + "\x00" + output
			if seen[key] {
				continue
			}
			seen[key] = true
			refs = append(refs, outputRef{job: job, output: output})
		}
	}
	return refs
}

func expressions(text string) []string {
	var matches []string
	for from := 0; from < len(text); {
		relative := strings.Index(text[from:], "$"+"{{")
		if relative < 0 {
			break
		}
		start := from + relative + 3
		var quote byte
		closed := false
		for index := start; index+1 < len(text); index++ {
			ch := text[index]
			if quote != 0 {
				if ch == quote {
					if index+1 < len(text) && text[index+1] == quote {
						index++
						continue
					}
					quote = 0
				} else if ch == '\\' && quote == '"' && index+1 < len(text) {
					index++
				}
				continue
			}
			if ch == '\'' || ch == '"' {
				quote = ch
				continue
			}
			if ch == '}' && text[index+1] == '}' {
				matches = append(matches, blankQuoted(text[start:index]))
				from = index + 2
				closed = true
				break
			}
		}
		if !closed {
			break
		}
	}
	return matches
}

// blankQuoted prevents a context name inside a string literal from becoming evidence.
func blankQuoted(expression string) string {
	bytes := []byte(expression)
	var quote byte
	for index := 0; index < len(bytes); index++ {
		c := bytes[index]
		if quote == 0 {
			if c == '\'' || c == '"' {
				quote = c
				bytes[index] = ' '
			}
			continue
		}
		bytes[index] = ' '
		if c == quote {
			if index+1 < len(bytes) && bytes[index+1] == quote {
				index++
				bytes[index] = ' '
			} else {
				quote = 0
			}
		}
	}
	return string(bytes)
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func needsCycles(jobs map[string]workflow.Job) map[string]bool {
	color := make(map[string]uint8, len(jobs))
	cyclic := make(map[string]bool)
	stack := []string{}
	var visit func(string)
	visit = func(id string) {
		color[id] = 1
		stack = append(stack, id)
		for _, dep := range jobs[id].Needs {
			if _, exists := jobs[dep]; !exists {
				continue
			}
			switch color[dep] {
			case 0:
				visit(dep)
			case 1:
				for index := len(stack) - 1; index >= 0; index-- {
					cyclic[stack[index]] = true
					if stack[index] == dep {
						break
					}
				}
			}
		}
		stack = stack[:len(stack)-1]
		color[id] = 2
	}
	for _, id := range sortedJobIDs(jobs) {
		if color[id] == 0 {
			visit(id)
		}
	}
	return cyclic
}

func findingKey(f Finding) string {
	return strings.Join([]string{
		f.Workflow, f.Event, f.Job, f.Step, f.Kind, f.Capability, f.Scope,
		f.SourceExpression, f.Source.File, strconv.Itoa(f.Source.Line),
		strconv.Itoa(f.Source.Column), f.Sink.File, strconv.Itoa(f.Sink.Line),
	}, "\x00")
}

func gapKey(g Gap) string {
	return strings.Join([]string{g.Workflow, g.Event, g.Job, g.Reason, g.At.File,
		strconv.Itoa(g.At.Line), strconv.Itoa(g.At.Column)}, "\x00")
}
