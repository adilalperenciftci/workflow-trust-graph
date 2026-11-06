# Workflow Trust Graph

An offline, event-scoped evidence graph for reviewing GitHub Actions workflow files.

The narrow question is: **where does a declared write-capable job also contain a syntactically witnessed path from contributor-origin pull-request data to a modeled run surface?** The answer is a review queue, not a vulnerability verdict. Unknown server defaults, reusable workflow bodies, conditions, and action internals remain explicit coverage gaps.

## What is modeled

- `pull_request` and `pull_request_target` are analyzed separately.
- Workflow/job `permissions` precedence and explicit-map defaults are applied. An omitted permission declaration is **unknown**, never assumed read-only.
- Contributor-origin references are restricted to PR title/body, head ref/SHA/repository identifiers, and `github.head_ref`. A platform-assigned PR number is **not** treated as contributor-origin.
- Evidence paths connect these references to `run` interpolation, inherited process environment, a PR-derived checkout followed by a later `run`, or a direct job output consumed through a declared `needs` edge. Contributor-origin inputs to other action steps, and source-derived checkouts without a later run, are reported as unmodeled rather than silently treated as safe.
- GitHub-token write scopes and `id-token: write` are separate capability classes. The report records the declaration, not the effective runtime token.

Every candidate includes the event, job, step, source/sink YAML positions, permission origin, and ordered path. A coverage gap is emitted for modeled uncertainty. The output is bounded at 10,000 findings and 10,000 ordinary gaps plus a limit sentinel; JSON has explicit truncation flags. See [the formal model](docs/MODEL.md).

## Use

Go 1.22.2 or newer:

```sh
go run ./cmd/wtg --json /path/to/public/repository
go run ./cmd/wtg --fail-on-findings /path/to/public/repository
```

The CLI reads only `.github/workflows/*.yml` and `*.yaml` under the supplied path. It does not execute workflows or contact GitHub. Exit code 0 means the scan completed, 2 means input/parse error, and 3 means review candidates were found with `--fail-on-findings`. Code 0 does **not** certify a safe repository.

## Reproducible evidence

```sh
go test ./... -count=1 -cover
go vet ./...
go test ./internal/workflow -run '^$' -fuzz FuzzParse -fuzztime=10s -parallel=4
go test ./internal/analysis -run '^$' -fuzz FuzzPermissionWeakening -fuzztime=5s -parallel=4
go test ./cmd/wtg -run '^$' -bench BenchmarkControlledCorpus -benchtime=2s -benchmem -count=3
```

The committed 16-case [controlled corpus](testdata/corpus) tests direct and propagated evidence, negative controls, permission boundaries, shadowing, condition uncertainty, and unresolved reusable workflows. A [pinned public-only case study](docs/CASE_STUDY.md) covers five repositories and 43 workflow files. These are bounded tests and a convenience sample, not a prevalence estimate.

## Interpretation boundary

A declared write permission may be reduced by fork or organization policy. A process environment value is reachable by a command but may never be read. A condition may make a step unreachable. The expression and shell languages are not fully interpreted. Therefore neither a candidate nor an empty finding list is a runtime security conclusion. The report is intended to make the next manual review precise and auditable.

## Development

The parser rejects duplicate YAML mapping keys, aliases, merge keys, custom tags, and unsupported shapes rather than silently choosing an interpretation. Discovery rejects symlinked workflow directory components and YAML leaves, caps file count/size, and aborts on the first ambiguous file. This is a local read-only tool; concurrent checkout mutation is not modeled.

Copyright (c) 2026 Adil Alperen Ciftci. All rights reserved. No open-source license or general reuse permission is granted.
