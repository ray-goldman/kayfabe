# Kayfabe: five reviewed improvement cycles

Review checkpoint: 2026-11-05. Starting local main: `29aa84cc9afe60760e903b2fd9b5e25a81d1ad44` (PR #36). Verify the remote again before execution.

## Outcome and authority

Complete five substantive improvement cycles using subagents to author new applications and implement scanner changes. Each cycle ends with reviewed evidence, one pull request, passing required CI and a merge into main. After approval at this checkpoint, the controller may create branches/worktrees, run harness tests and static scans, push, create and merge these PRs without asking again. No release, deployment, repository permission changes or branch deletion is included.

The user's request for one checkpoint replaces repeated design/merge approval menus. Routine implementation decisions and any change in target order are recorded in a durable ledger. Stop for a genuinely unavailable permission/input or an unsafe action, explain the blocker, and continue unaffected work. Failing checks are repaired, never bypassed to finish a loop.

## Approach

Recommended: three C# precision cycles, then two bounded Rust coverage cycles. Current C# Juliet evidence has 1,036 TP and 470 FP; noise within detected command/SQL families remains substantial. Rust currently supports two reqwest TLS checks with incomplete semantic coverage. A Rust-only program would defer the largest measured precision problem; broad simultaneous language expansion would make causes and regressions harder to attribute.

| Cycle | Initial target | New application contexts | Required improvement |
|---|---|---|---|
| 1 | Complete multiline C# SQL/command sink expressions | Reporting service and background-job scheduler | Reduce reviewed warnings for constant sinks without hiding dynamic later arguments or adjacent unsafe sinks |
| 2 | Narrow C# inferred-literal local proofs | Support utility and export processor | Prove supported literal `var` locals only with sound binding/ownership and mutation controls; retain ambiguous conversions |
| 3 | C# private-helper named arguments | Maintenance API and document service | Map arguments to actual declared parameters, including reordering; preserve unsafe returned parameters and overload ambiguity |
| 4 | Rust flat Result/error-propagating TLS builder expressions | Telemetry uploader and artifact mirror | Distinguish return-type generics from generic functions and support narrow `build()?` expressions; fixed clients stay quiet |
| 5 | Rust local builder state | Webhook relay and backup client | Track supported straight-line builder initialization/settings/build; respect resets, moves, aliases and unknown calls |

These are priorities, not permission to loosen a proof. Each starts with a failing, reviewed example. If a proposed gap is already covered or cannot be resolved safely, investigate, record the reason, and take the next bounded gap in the same family. Each Rust cycle requires a verified detection gain or false-positive reduction with paired controls. Coverage bookkeeping alone, an empty PR or a documentation-only change does not count as one of the five scanner improvements. Do not invent a guaranteed percentage gain.

## Roles and isolation

- Controller: owns the plan/ledger, app/key freezes, evaluation, integration, PRs and merges. One scanner implementation at a time; branches start from the preceding merged main.
- Fresh application author for each cycle: writes two compact realistic apps, each with at least four vulnerable/safe pairs, a separate answer key, build metadata and a case inventory. Author sees only that cycle's application brief and writes into a separate local folder; no scanner rules/results/scorers are supplied.
- Fresh label reviewer: checks every vulnerable/safe claim, API semantics and source/sink/guard evidence before the first scan. Disputed or unsupported cases are marked as such, never silently counted safe.
- Fresh implementation subagent: receives the verified failure package and bounded task, writes scanner code, regression pairs and tests in the cycle worktree, then self-reviews.
- Two fresh-context review passes: first challenges code correctness, ownership, hostile inputs and suppression bypasses; second reviews the repaired branch, regressions, provenance, performance and public claims. Reviewers cannot approve their own implementation. The controller also runs Kayfabe on the generated apps and the changed production scanner scope and manually triages candidates.

Up to three child agents may run concurrently. App generation can overlap read-only preparation; shared scanner mutations, frozen scoring and merges stay sequential. Model choices follow the applicable development skill and are recorded.

## Evidence protocol

These generated apps are **self-authored development/regression evidence**. Fresh agent context and a clean folder do not establish independent authorship: agents share a host/filesystem. Record author, model, brief, accessible context and observed exposure. Never label these scores blind or independently authored, or pool them with third-party benchmarks.

Before scanning each new set, freeze its source, answer key, case inventory and scoring policy in a SHA-256 manifest. Match by declared CWE, file and explicit region under a fixed policy. Freeze expected vulnerable/safe status, unsupported categories and matching rules before baseline results. Keep labeled vulnerable misses in the denominator even when syntax is unsupported; report unsupported coverage separately. A quiet unsupported safe case earns no TN credit. Report raw fixed-case warning counts as well as supported-case rates. Label corrections discovered later create a new version with an explanation and preserve the old measurement; never rewrite a key to improve the score. Once results inform a fix, that set is exposed development data and remains in the cumulative regression replay.

Vulnerable examples must be local static evaluation code: no live credentials, real targets, remote attack infrastructure or exploit automation. Keep the full generated apps, separate keys, raw reports and intermediate scans local. Publish only minimal scanner-owned corpus pairs and sanitized aggregate results. Do not execute, build or install dependencies for generated or supplied apps. Static key/code review does not establish successful compilation or runtime exploitation.

## Every cycle

1. Sync/verify main, create an isolated `codex/` branch, record exact base and runtime hash.
2. Author two new apps; review labels; freeze bytes/policy; scan baseline. Triage all candidates and relevant misses. Do not select only favorable cases.
3. Select one or more verified root causes; add failing harness-owned unit tests and vulnerable/fixed corpus pairs; implement the narrow fix using a subagent. Include unsafe twins for each suppression.
4. Complete review one and repairs, then review two's code pass before freezing the final candidate. A remaining actionable correctness/security issue prevents publication or merge.
5. Run the exact frozen candidate's full `npm test` and CLI selftest. Rerun all seven established benchmarks and the existing supplied/frozen/development/real-code/Hermes/adversarial replays, plus every new set from completed cycles. Compare by unit and finding identity, not only totals.
6. Run the harness against the changed production scanner scope and manually review its findings. Fixture findings are explained as fixtures; they are not removed to manufacture a clean scan. Preserve repository quarantine, redaction and static-only behavior.
7. Finish independent evidence review, publish sanitized per-dataset before/after results and remaining gaps, push and create/attach the PR. Check required CI at the exact reviewed head; merge with head-SHA protection and without bypassing branch protection. Verify remote merge/main and sync local main. Proceed to the next cycle automatically.

## Ship gates, frozen before tuning

- No lost established true-positive units and no newly flagged safe units in supported benchmark cases: `tpToFn=0` and `tnToFp=0`. Improvements `fpToTn` and `fnToTp` are allowed and reported individually. Existing safe-key results and scorer/policy/option hashes remain unchanged. No unsupported native-C scan earns true-negative credit.
- C# cycles reduce at least one verified false positive on a labeled development/benchmark case, preserving its vulnerable twin. Rust cycles add at least one correct detection or reduce a verified FP with paired controls. Report whether established datasets improved or merely stayed unchanged.
- Full suite: zero failures; all corpus pairs pass; platform skips disclosed. New tests cover the exact failure and adversarial alternatives, not only the happy path.
- Candidate runtime bytes are frozen and identical to the reviewed implementation and eventual merged runtime; document-only evidence commits may follow. A runtime repair requires fresh freeze and relevant reruns; retain superseded measurements.
- Juliet C# default scan time <=1.5x the cycle's baseline under comparable concurrency. Preserve existing parser/graph/byte/work bounds and opt-in status; incomplete analysis cannot pass as complete.
- Review two confirms all benchmark input/key/policy/evaluator hashes, individual transitions, confidence/coverage claims and public artifact privacy. Zero findings is not a clean security assessment.
- Required GitHub CI passes at the verified head, with no unresolved actionable review issue. No admin bypass, force push, release or deployment.

## Finish

After five merged improvement cycles, perform a cumulative final-main verification: full suite/corpus, all seven benchmarks and all accumulated app sets, harness self-review, initial-main versus final-main unit transitions and per-cycle attribution. Produce a concise report with all five PRs, before/after counts by dataset/language, remaining FPs/misses, runtime/coverage limits and author exposure. Stop after that report; further cycles require a new request. An unresolved issue in the final review is repaired before completion.

The detailed execution checklist is in [implementation-plan.md](../plans/2026-11-05-five-cycle-improvement.md). No scanner implementation or merge starts until this plan is approved at the single requested review point.
