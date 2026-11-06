# Event-scoped evidence model

## Review question

For a declared pull-request event, which local jobs combine **contributor-origin data reaching a modeled run surface** with an **explicit write-capable GitHub token declaration**? A result is a syntax-backed review candidate, not proof of runtime authority, reachability, or a defect.

## Parsed state and trust boundary

Each workflow yields an event set, workflow permission declaration, workflow environment, and a job graph. The analyzer instantiates separate results for `pull_request` and `pull_request_target`. Other events are outside this bounded model.

For job `j` and scope `s`, declared permission `P(j,s)` is selected from the job declaration when present, otherwise the workflow declaration, otherwise `unknown`. Within an explicit map, omitted scopes are `none`. `read-all` and `write-all` are modeled as explicit declarations. The known-scope vocabulary is fixed in the source; an unrecognized scope creates `permission_scope_unmodeled` instead of a capability.

A declared write is only an upper bound on effective runtime permission. Fork token downgrades and repository/organization settings are unavailable offline. `id-token: write` is reported as `oidc-token`; all other known write scopes are `github-token-write`. The two classes are not conflated.

## Contributor-origin witnesses

The allowlist is intentionally narrower than the whole PR event object:

- `github.head_ref`;
- `github.event.pull_request.title` and `.body`;
- `github.event.pull_request.head.ref`, `.head.sha`, `.head.label`, and `.head.repo.full_name`.

These tokens count only inside `${{ ... }}` expressions, not in quoted expression literals or shell text. `github.event.pull_request.number` is platform-assigned and is **not** a source witness. Other PR fields may still matter in a real workflow, but are unclassified here. The parser records the enclosing YAML scalar position; it does not pretend to report the exact byte offset of a token inside a multiline scalar.

## Modeled path edges and sinks

- Direct source expression -> `run` scalar interpolation.
- Workflow/job/step `env` source expression -> later `run` process environment, with step > job > workflow shadowing. This proves environment reachability, **not** command consumption.
- Source-derived `actions/checkout` `with.ref` or `with.repository` -> a later `run` in the same job. This proves local step order, not that the later command consumes checked-out content.
- Direct source expression in `jobs.<producer>.outputs.<name>` -> a consumer `needs.<producer>.outputs.<name>` expression, only when the consumer declares the matching `needs` edge. No origin is inferred through `steps.*.outputs.*`.

Any `uses` step with contributor-origin input or effective environment outside the modeled checkout `ref`/`repository` path emits `action_input_unmodeled` because the action body is not interpreted. A contributor-origin checkout `ref` or `repository` without a later `run` emits `checkout_followup_unmodeled`. A finding requires a recognized PR event, one such path, and an explicit write capability in the sink job. The JSON evidence path contains permission declaration, source, intermediate edges, and sink, each with a YAML node position. Unknown permissions yield a gap rather than a finding. A source path in an explicitly read-only job yields no write candidate. Jobs with no declared write capability skip candidate path construction but still report modeled coverage gaps.

## Conditions, cycles, and missing information

Job and step `if` expressions are not evaluated. A nontrivial condition adds `condition_unmodeled`; the syntax-backed candidate may still be reported even for `if: false`. A cyclic `needs` graph terminates with `needs_cycle`, and unresolved output dependencies produce a gap. Local and external reusable workflow calls produce `reusable_workflow_unmodeled`; their bodies, inputs, and secrets are not traversed.

Trigger filter/configuration validity is not checked; a declared but service-invalid trigger may still yield a syntax-backed candidate. Unmodeled inputs include other event types (`workflow_run`, comments, scheduled events), repository defaults, branch/environment rules, action internals, shell control flow, general expression evaluation, arbitrary step-output provenance, artifacts, and cross-job filesystem state. Zero candidates is never a safety finding.

## Checkable properties

**Permission monotonicity.** Fix the parsed evidence graph. Replacing a modeled permission `write` by `read` or `none` cannot add a finding because the finding predicate requires `write`. `FuzzPermissionWeakening` tests this property over generated scopes and commands. It is a property of this bounded model, not of the GitHub service.

**Determinism.** Workflow files, jobs, findings, and gaps are sorted. Identical input bytes yield identical JSON. Independent job reordering changes source positions, but semantic findings remain equal after positions are removed; this is tested separately.

**Fail closed on ambiguity.** Discovery checks directory components and YAML leaves with `Lstat`, caps file size/count, and aborts on the first parse error. The parser rejects duplicate YAML keys, aliases, merge keys, custom tags, extra YAML documents, and malformed recognized fields. Findings are limited to 10,000 per scan. Gaps are limited to 10,000 ordinary entries plus one `gap_limit_reached` sentinel. A would-be additional finding adds `finding_limit_reached`; JSON booleans `findings_truncated` and `gaps_truncated` remain authoritative even if both limits are reached. These checks are not a race-free proof against concurrent checkout mutation.


## Specification anchors

- [GitHub Actions workflow syntax: permissions and job structure](https://docs.github.com/en/actions/reference/workflows/workflow-syntax-for-github-actions)
- [Events that trigger workflows](https://docs.github.com/en/actions/reference/workflows/events-that-trigger-workflows)
- [Reusing workflows](https://docs.github.com/en/actions/how-tos/reuse-automations/reuse-workflows)

These documents define the service vocabulary; this prototype implements only the bounded subset above.
