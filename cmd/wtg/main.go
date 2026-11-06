package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/adilalperenciftci/workflow-trust-graph/internal/analysis"
	"github.com/adilalperenciftci/workflow-trust-graph/internal/scan"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("wtg", flag.ContinueOnError)
	flags.SetOutput(stderr)
	asJSON := flags.Bool("json", false, "write the deterministic evidence report as JSON")
	failOnFindings := flags.Bool("fail-on-findings", false, "exit 3 if review candidates are found")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if flags.NArg() != 1 {
		fmt.Fprintln(stderr, "usage: wtg [--json] [--fail-on-findings] <repository-path>")
		return 2
	}

	workflows, err := scan.Discover(flags.Arg(0))
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	report := analysis.Analyze(workflows)
	if *asJSON {
		encoder := json.NewEncoder(stdout)
		encoder.SetIndent("", "  ")
		encoder.SetEscapeHTML(false)
		if err := encoder.Encode(report); err != nil {
			fmt.Fprintln(stderr, err)
			return 2
		}
	} else {
		fileWord, candidateWord, gapWord := "files", "candidates", "gaps"
		if report.Workflows == 1 {
			fileWord = "file"
		}
		if len(report.Findings) == 1 {
			candidateWord = "candidate"
		}
		if len(report.Gaps) == 1 {
			gapWord = "gap"
		}
		fmt.Fprintf(stdout, "%d workflow %s; %d review %s; %d coverage %s\n", report.Workflows, fileWord, len(report.Findings), candidateWord, len(report.Gaps), gapWord)
		for _, finding := range report.Findings {
			fmt.Fprintf(stdout, "%s:%d %s %s/%s %s declared %s:%s\n",
				finding.Sink.File, finding.Sink.Line, finding.Event,
				finding.Job, finding.Step, finding.Kind, finding.Capability, finding.Scope)
		}
		for _, gap := range report.Gaps {
			fmt.Fprintf(stdout, "coverage gap: %s:%d %s %s %s\n", gap.At.File, gap.At.Line, gap.Event, gap.Job, gap.Reason)
		}
		if report.FindingsTruncated {
			fmt.Fprintln(stdout, "findings truncated; inspect JSON truncation flags")
		}
		if report.GapsTruncated {
			fmt.Fprintln(stdout, "coverage gaps truncated; inspect JSON truncation flags")
		}
	}
	if *failOnFindings && len(report.Findings) > 0 {
		return 3
	}
	return 0
}
