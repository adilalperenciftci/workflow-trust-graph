# Pinned public workflow study

## Method

The sample was chosen for varied workflow shapes, not statistically sampled. On 2026-11-07, five **public** repositories were checked out at exact commits with sparse checkout limited to `.github/workflows`. No repository workflow was executed and no private repository was read. The table reports model output only.

| Repository | Commit | YAML files | Review candidates | Coverage gaps |
| --- | --- | ---: | ---: | ---: |
| [actions/checkout](https://github.com/actions/checkout) | `f548e57e544e1ff5a4c46bf1e1b8685f8e4a348a` | 7 | 0 | 14 |
| [cli/cli](https://github.com/cli/cli) | `c235ae31c77c5aa99abdf947503b4f3649330938` | 15 | 0 | 15 |
| [hashicorp/raft](https://github.com/hashicorp/raft) | `a5b469295ddc9924541477eafe34bf59a8571063` | 1 | 0 | 4 |
| [kubernetes-sigs/kind](https://github.com/kubernetes-sigs/kind) | `46b5d280a425a0e50511712d84b31a0a36a7191f` | 4 | 0 | 16 |
| [open-policy-agent/opa](https://github.com/open-policy-agent/opa) | `b04b69a0a1a99526635d3ffad953bfe3d6b2751a` | 16 | 0 | 26 |
| **Total** | | **43** | **0** | **75** |

Gap events are not unique workflows: 61 `condition_unmodeled`, 8 `permission_unknown`, and 6 `reusable_workflow_unmodeled`. Zero review candidates is **not** a safety claim. The sample cannot measure false negatives because unmodeled settings and action internals were not inspected.

## Reproduction

For each row, substitute the exact repository and SHA:

```sh
sample=/tmp/wtg-public-OWNER-REPO
git init "$sample"
git -C "$sample" remote add origin https://github.com/OWNER/REPO.git
git -C "$sample" sparse-checkout init --cone
git -C "$sample" sparse-checkout set .github/workflows
git -C "$sample" fetch --filter=blob:none --depth=1 origin COMMIT_SHA
git -C "$sample" checkout --detach FETCH_HEAD
test "$(git -C "$sample" rev-parse HEAD)" = COMMIT_SHA
go run ./cmd/wtg --json "$sample" > /tmp/wtg-public-OWNER-REPO-report.json
```

Run from this project's root and use a distinct empty path outside the product checkout for each repository. The JSON includes the exact file/event/job-level coverage gaps. An archived or removed Git object may make a future fetch unavailable; the input commit SHA makes that failure visible instead of silently substituting a moving branch.

## Controlled counterfactuals

The 16 committed fixtures each change one relevant boundary. Six yield a modeled candidate: direct PR title in `run`, PR-head checkout before `run`, a direct job output through `needs`, root or step environment reaching `run`, and a conditionally guarded `run`. The last case deliberately remains a **candidate plus condition gap**; the model does not claim that `if: false` executes. Negative fixtures check a platform-assigned PR number, plain text outside expressions, read-only/unknown permissions, unknown scope names, missing `needs`, reversed checkout order, environment shadowing, an unrelated `push` trigger, and a reusable call.

The property target `FuzzPermissionWeakening` checks the model's monotonicity requirement: replacing `write` by `read` or `none` cannot introduce a candidate. `FuzzParse` checks bounded parser inputs for crashes and inconsistent successful output. Neither fuzz run proves full semantic correctness.

## Measured verification

On an isolated Ubuntu VM with Go 1.22.2 and an Intel Xeon E5-2690 v4, the 16-fixture parse-plus-analysis benchmark returned 502692, 500495, and 499380 ns/op; roughly 259 kB/op and 2666 allocs/op. The benchmark excludes filesystem discovery, process startup, and network fetches. These figures are machine-specific, not a throughput guarantee.
