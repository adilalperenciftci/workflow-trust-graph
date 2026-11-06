package workflow

import (
	"fmt"
	"io"
	"strings"

	"gopkg.in/yaml.v3"
)

// Pos identifies syntax in the input workflow. It is not a runtime trace.
type Pos struct {
	File   string `json:"file"`
	Line   int    `json:"line"`
	Column int    `json:"column"`
}

// Scalar retains both the interpreted YAML scalar and its original position.
type Scalar struct {
	Text string `json:"text"`
	Pos  Pos    `json:"pos"`
}

// Permission describes only an explicit YAML declaration, not server defaults.
type Permission struct {
	Specified bool              `json:"specified"`
	All       string            `json:"all,omitempty"`
	Scopes    map[string]string `json:"scopes,omitempty"`
	Pos       Pos               `json:"pos"`
}

type Workflow struct {
	Path        string
	Name        string
	Events      []string
	Permissions Permission
	Env         map[string]Scalar
	Jobs        map[string]Job
}

type Job struct {
	ID          string
	Pos         Pos
	Needs       []string
	If          Scalar
	Permissions Permission
	Uses        Scalar
	With        map[string]Scalar
	Env         map[string]Scalar
	Outputs     map[string]Scalar
	Steps       []Step
}

type Step struct {
	ID   string
	Pos  Pos
	If   Scalar
	Run  Scalar
	Uses Scalar
	With map[string]Scalar
	Env  map[string]Scalar
}

// Parse accepts a single workflow document. Ambiguous YAML is rejected before
// any field extraction so ignored fields cannot hide aliases or duplicate keys.
func Parse(path string, data []byte) (Workflow, error) {
	wf := Workflow{Path: path, Jobs: make(map[string]Job), Env: make(map[string]Scalar)}
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	var document yaml.Node
	if err := dec.Decode(&document); err != nil {
		return wf, fmt.Errorf("%s: %w", path, err)
	}
	if len(document.Content) != 1 || document.Content[0].Kind != yaml.MappingNode {
		return wf, fmt.Errorf("%s: workflow root must be a mapping", path)
	}
	if err := validateTree(path, &document); err != nil {
		return wf, err
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); err != io.EOF {
		if err == nil {
			return wf, fmt.Errorf("%s: multiple YAML documents are not supported", path)
		}
		return wf, fmt.Errorf("%s: %w", path, err)
	}
	root := document.Content[0]
	if value := field(root, "name"); value != nil {
		name, err := stringScalar(path, value, "name")
		if err != nil {
			return wf, err
		}
		wf.Name = name.Text
	}
	if value := field(root, "on"); value != nil {
		events, err := parseEvents(path, value)
		if err != nil {
			return wf, err
		}
		wf.Events = events
	}
	if value := field(root, "permissions"); value != nil {
		declaration := fieldKey(root, "permissions")
		permissions, err := parsePermission(path, declaration, value)
		if err != nil {
			return wf, err
		}
		wf.Permissions = permissions
	}
	if value := field(root, "env"); value != nil {
		env, err := scalarMap(path, value, "env")
		if err != nil {
			return wf, err
		}
		wf.Env = env
	}
	if value := field(root, "jobs"); value != nil {
		if value.Kind != yaml.MappingNode {
			return wf, at(path, value, "jobs must be a mapping")
		}
		for i := 0; i < len(value.Content); i += 2 {
			key, body := value.Content[i], value.Content[i+1]
			if body.Kind != yaml.MappingNode {
				return wf, at(path, body, "job must be a mapping")
			}
			job, err := parseJob(path, key, body)
			if err != nil {
				return wf, err
			}
			wf.Jobs[key.Value] = job
		}
	}
	return wf, nil
}

func parseJob(path string, key, body *yaml.Node) (Job, error) {
	job := Job{
		ID: key.Value, Pos: pos(path, key),
		With: make(map[string]Scalar), Env: make(map[string]Scalar),
		Outputs: make(map[string]Scalar),
	}
	if value := field(body, "needs"); value != nil {
		needs, err := stringList(path, value, "needs")
		if err != nil {
			return job, err
		}
		job.Needs = needs
	}
	if value := field(body, "if"); value != nil {
		scalar, err := scalarValue(path, value, "if")
		if err != nil {
			return job, err
		}
		job.If = scalar
	}
	if value := field(body, "permissions"); value != nil {
		permissions, err := parsePermission(path, fieldKey(body, "permissions"), value)
		if err != nil {
			return job, err
		}
		job.Permissions = permissions
	}
	if value := field(body, "uses"); value != nil {
		scalar, err := stringScalar(path, value, "uses")
		if err != nil {
			return job, err
		}
		job.Uses = scalar
	}
	for _, item := range []struct {
		name string
		dest *map[string]Scalar
	}{{"with", &job.With}, {"env", &job.Env}, {"outputs", &job.Outputs}} {
		if value := field(body, item.name); value != nil {
			parsed, err := scalarMap(path, value, item.name)
			if err != nil {
				return job, err
			}
			*item.dest = parsed
		}
	}
	if value := field(body, "steps"); value != nil {
		if value.Kind != yaml.SequenceNode {
			return job, at(path, value, "steps must be a sequence")
		}
		for _, node := range value.Content {
			if node.Kind != yaml.MappingNode {
				return job, at(path, node, "step must be a mapping")
			}
			step, err := parseStep(path, node)
			if err != nil {
				return job, err
			}
			job.Steps = append(job.Steps, step)
		}
	}
	return job, nil
}

func parseStep(path string, body *yaml.Node) (Step, error) {
	step := Step{
		Pos:  pos(path, body),
		With: make(map[string]Scalar), Env: make(map[string]Scalar),
	}
	if value := field(body, "if"); value != nil {
		condition, err := scalarValue(path, value, "if")
		if err != nil {
			return step, err
		}
		step.If = condition
	}
	if value := field(body, "id"); value != nil {
		id, err := stringScalar(path, value, "step id")
		if err != nil {
			return step, err
		}
		step.ID = id.Text
	}
	for _, item := range []struct {
		name string
		dest *Scalar
	}{{"run", &step.Run}, {"uses", &step.Uses}} {
		if value := field(body, item.name); value != nil {
			scalar, err := scalarValue(path, value, item.name)
			if err != nil {
				return step, err
			}
			*item.dest = scalar
		}
	}
	for _, item := range []struct {
		name string
		dest *map[string]Scalar
	}{{"with", &step.With}, {"env", &step.Env}} {
		if value := field(body, item.name); value != nil {
			parsed, err := scalarMap(path, value, item.name)
			if err != nil {
				return step, err
			}
			*item.dest = parsed
		}
	}
	return step, nil
}

func parseEvents(path string, node *yaml.Node) ([]string, error) {
	var events []string
	switch node.Kind {
	case yaml.ScalarNode:
		event, err := stringScalar(path, node, "on")
		if err != nil {
			return nil, err
		}
		events = append(events, event.Text)
	case yaml.SequenceNode:
		for _, child := range node.Content {
			event, err := stringScalar(path, child, "on event")
			if err != nil {
				return nil, err
			}
			events = append(events, event.Text)
		}
	case yaml.MappingNode:
		for i := 0; i < len(node.Content); i += 2 {
			events = append(events, node.Content[i].Value)
		}
	default:
		return nil, at(path, node, "on must be an event name, list, or mapping")
	}
	seen := make(map[string]bool)
	unique := events[:0]
	for _, event := range events {
		if event == "" {
			return nil, at(path, node, "event name must not be empty")
		}
		if !seen[event] {
			unique = append(unique, event)
			seen[event] = true
		}
	}
	return unique, nil
}

func parsePermission(path string, key, node *yaml.Node) (Permission, error) {
	permission := Permission{
		Specified: true, Scopes: make(map[string]string), Pos: pos(path, key),
	}
	switch node.Kind {
	case yaml.ScalarNode:
		value, err := stringScalar(path, node, "permissions")
		if err != nil {
			return permission, err
		}
		if value.Text != "read-all" && value.Text != "write-all" {
			return permission, at(path, node, "permissions must be read-all, write-all, or a mapping")
		}
		permission.All = value.Text
	case yaml.MappingNode:
		for i := 0; i < len(node.Content); i += 2 {
			key, value := node.Content[i], node.Content[i+1]
			level, err := stringScalar(path, value, "permission level")
			if err != nil {
				return permission, err
			}
			switch level.Text {
			case "read", "write", "none":
				permission.Scopes[key.Value] = level.Text
			default:
				return permission, at(path, value, "permission level must be read, write, or none")
			}
		}
	default:
		return permission, at(path, node, "permissions must be read-all, write-all, or a mapping")
	}
	return permission, nil
}

func scalarMap(path string, node *yaml.Node, name string) (map[string]Scalar, error) {
	if node.Kind != yaml.MappingNode {
		return nil, at(path, node, name+" must be a mapping")
	}
	out := make(map[string]Scalar)
	for i := 0; i < len(node.Content); i += 2 {
		scalar, err := scalarValue(path, node.Content[i+1], name+" value")
		if err != nil {
			return nil, err
		}
		out[node.Content[i].Value] = scalar
	}
	return out, nil
}

func stringList(path string, node *yaml.Node, name string) ([]string, error) {
	switch node.Kind {
	case yaml.ScalarNode:
		scalar, err := stringScalar(path, node, name)
		if err != nil {
			return nil, err
		}
		return []string{scalar.Text}, nil
	case yaml.SequenceNode:
		result := make([]string, 0, len(node.Content))
		for _, child := range node.Content {
			scalar, err := stringScalar(path, child, name)
			if err != nil {
				return nil, err
			}
			result = append(result, scalar.Text)
		}
		return result, nil
	default:
		return nil, at(path, node, name+" must be a string or list of strings")
	}
}

func scalarValue(path string, node *yaml.Node, name string) (Scalar, error) {
	if node.Kind != yaml.ScalarNode {
		return Scalar{}, at(path, node, name+" must be a scalar")
	}
	return Scalar{Text: node.Value, Pos: pos(path, node)}, nil
}

func stringScalar(path string, node *yaml.Node, name string) (Scalar, error) {
	scalar, err := scalarValue(path, node, name)
	if err != nil {
		return scalar, err
	}
	if shortTag(node.Tag) != "!!str" {
		return Scalar{}, at(path, node, name+" must be a string")
	}
	return scalar, nil
}

func field(mapping *yaml.Node, name string) *yaml.Node {
	for i := 0; i < len(mapping.Content); i += 2 {
		if mapping.Content[i].Value == name {
			return mapping.Content[i+1]
		}
	}
	return nil
}

func fieldKey(mapping *yaml.Node, name string) *yaml.Node {
	for i := 0; i < len(mapping.Content); i += 2 {
		if mapping.Content[i].Value == name {
			return mapping.Content[i]
		}
	}
	return nil
}

func validateTree(path string, node *yaml.Node) error {
	switch node.Kind {
	case yaml.AliasNode:
		return at(path, node, "YAML aliases are not supported")
	case yaml.DocumentNode:
		if len(node.Content) != 1 {
			return at(path, node, "expected one document root")
		}
	case yaml.MappingNode:
		if tag := shortTag(node.Tag); tag != "" && tag != "!!map" {
			return at(path, node, "custom YAML mapping tag is not supported")
		}
		seen := make(map[string]bool)
		for i := 0; i < len(node.Content); i += 2 {
			key := node.Content[i]
			if key.Kind != yaml.ScalarNode || shortTag(key.Tag) != "!!str" {
				return at(path, key, "mapping key must be a string")
			}
			if key.Value == "<<" {
				return at(path, key, "YAML merge keys are not supported")
			}
			if seen[key.Value] {
				return at(path, key, fmt.Sprintf("duplicate mapping key %q", key.Value))
			}
			seen[key.Value] = true
		}
	case yaml.SequenceNode:
		if tag := shortTag(node.Tag); tag != "" && tag != "!!seq" {
			return at(path, node, "custom YAML sequence tag is not supported")
		}
	case yaml.ScalarNode:
		switch shortTag(node.Tag) {
		case "!!str", "!!int", "!!float", "!!bool", "!!null", "!!timestamp", "!!binary":
		default:
			return at(path, node, "custom YAML scalar tag is not supported")
		}
	default:
		return at(path, node, "unsupported YAML node")
	}
	for _, child := range node.Content {
		if err := validateTree(path, child); err != nil {
			return err
		}
	}
	return nil
}

func shortTag(tag string) string {
	if strings.HasPrefix(tag, "tag:yaml.org,2002:") {
		return "!!" + strings.TrimPrefix(tag, "tag:yaml.org,2002:")
	}
	return tag
}

func pos(path string, node *yaml.Node) Pos {
	return Pos{File: path, Line: node.Line, Column: node.Column}
}

func at(path string, node *yaml.Node, message string) error {
	return fmt.Errorf("%s:%d:%d: %s", path, node.Line, node.Column, message)
}
