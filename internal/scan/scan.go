package scan

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/adilalperenciftci/workflow-trust-graph/internal/workflow"
)

const (
	maxWorkflowBytes int64 = 1 << 20
	maxWorkflowFiles       = 256
)

// Discover reads only regular workflow YAML files in the repository-local directory.
// An invalid or ambiguous file aborts the scan instead of producing partial results.
func Discover(root string) ([]workflow.Workflow, error) {
	if err := requireDirectory(root); err != nil {
		return nil, err
	}
	github := filepath.Join(root, ".github")
	if err := requireDirectory(github); os.IsNotExist(err) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	dir := filepath.Join(github, "workflows")
	if err := requireDirectory(dir); os.IsNotExist(err) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		ext := strings.ToLower(filepath.Ext(entry.Name()))
		if ext == ".yml" || ext == ".yaml" {
			names = append(names, entry.Name())
		}
	}
	if len(names) > maxWorkflowFiles {
		return nil, fmt.Errorf("workflow count %d exceeds limit %d", len(names), maxWorkflowFiles)
	}
	sort.Strings(names)

	result := make([]workflow.Workflow, 0, len(names))
	for _, name := range names {
		path := filepath.Join(dir, name)
		info, err := os.Lstat(path)
		if err != nil {
			return nil, err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("symlink workflow file: %s", path)
		}
		if !info.Mode().IsRegular() {
			return nil, fmt.Errorf("non-regular workflow file: %s", path)
		}
		if info.Size() > maxWorkflowBytes {
			return nil, fmt.Errorf("workflow size %d exceeds limit %d: %s", info.Size(), maxWorkflowBytes, path)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		if int64(len(data)) > maxWorkflowBytes {
			return nil, fmt.Errorf("workflow size exceeds limit: %s", path)
		}
		relative := filepath.ToSlash(filepath.Join(".github", "workflows", name))
		parsed, err := workflow.Parse(relative, data)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", relative, err)
		}
		result = append(result, parsed)
	}
	return result, nil
}

func requireDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("symlink directory: %s", path)
	}
	if !info.IsDir() {
		return fmt.Errorf("not a directory: %s", path)
	}
	return nil
}
