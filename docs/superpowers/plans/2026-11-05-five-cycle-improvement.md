# Five-cycle Kayfabe Improvement Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development. The user explicitly chose subagents for application and scanner code. Execute through all five reviewed merges after the single plan approval.

**Goal:** Complete five measurable scanner improvements, each informed by new paired applications and shipped in a reviewed, passing PR.

**Architecture:** A controller freezes inputs and evaluates versions; fresh authors, implementers and reviewers have distinct roles. Each scanner branch builds on the preceding merged main. Existing native parsers/value proofs remain bounded and conservative.

**Tech stack:** Node.js >=20, existing JavaScript scanner and parsers, Git/GitHub CLI, existing unchanged offline scorers. No installed runtime packages and no target execution.

**Spec:** [approved design](../specs/2026-11-05-five-cycle-improvement-design.md). This checklist becomes executable only after its initial approval. Copy approved documents to `docs/superpowers/{specs,plans}/2026-11-05-five-cycle-improvement*.md` on the first feature branch; preserve this checkpoint copy.

## Global constraints

- Five substantive scanner improvement PRs; exactly one human review checkpoint before implementation; PR creation and merge already requested subject to the design gates.
- Native Node, no installed runtime dependencies, static-only target reads; secrets redacted and quarantine preserved.
- Fresh agent authors/implementers/reviewers; one shared scanner mutation at a time; work only in isolated cycle branches.
- Generated apps are self-authored regression/development data, never independently authored/blind evidence.
- Full app source, separate keys and raw reports stay local. Only minimal corpus pairs and sanitized aggregate results are published.
- Frozen old inputs, labels, scoring policies and options unchanged. Zero established TP loss or new FP; default Juliet C# scan time <=1.5x cycle baseline.
- Existing parser/graph/work caps and optional feature gates retained. Incomplete/unsupported source receives no safety credit.
- Two fresh reviews and passing required CI at the exact reviewed head before each merge; no bypass or force push.

## Review focus

- Multiline/adjacent calls: prove the complete selected sink and retain dynamic later arguments; test two calls on one line and CRLF offsets.
- Contextual `var`: aliases, named types and conversions must prevent unsafe constant inference; test shadowing, mutation, ref/out and unknown bindings.
- Named helper parameters: reordering, duplicate/unknown names and overloads must not change parameter provenance; test unsafe returned named arguments.
- Rust control flow: `?` and generic return types must not create a successful build proof before evaluation; test unsupported branches and early termination. Async function qualifiers already pass; pending `await` stays unsupported.
- Rust builder ownership: mutation, moves, aliases, unknown calls and backend changes must invalidate unsafe or safe conclusions correctly; test resets before/after build and unused builders.

## Common cycle interface and evidence

Local campaign root: `output/kayfabe-five-cycle-2026-11-05/`. Create `progress.md` with the approved design identity, starting commit, cycle states and every ruling. Each cycle uses `cycle-N/` with author brief/exposure log, `apps/`, separate `evaluation/`, immutable `freeze.json`, reviewer reports, scanner source manifests, baseline/candidate measurements, comparisons and PR metadata. Do not delete evidence on cleanup.

The controller supplies each implementer an exact base SHA, worktree path, source/key freeze hashes, root-cause repro and acceptance tests. Implementers return commit SHA, changed-file list, tests, unresolved limitations and self-review. Reviewers receive requirements and an exact base/head diff, not the implementer's conversational history.

Retain public APIs `createCSharpConstantSinkProof(code)(line, ruleId)`, `createCSharpValueProof(code, ast)(expression)`, and `analyzeRustProject(inputs, manifests, complete, options) -> {files, findings}` unless a reviewed task explicitly justifies an internal extension. Keep existing finding identities/schema and coverage gates stable.

### Task 0: Initialize approved campaign and measurement adapter

**Files:** Local `progress.md`, `cycle-N/` evidence and trusted local orchestration scripts. First branch adds the approved spec/plan to repo docs. Existing `scripts/score-dotnet-juliet.js`, `scripts/compare-dotnet-accuracy.js`, `scripts/score-supplied-apps.js` and all existing benchmark policies remain byte-identical.

- [ ] Verify GitHub main/current open PRs and local clean status; record authoritative start SHA and review-point approval.
- [ ] Read applicable subagent/worktree/TDD/review skills. Establish per-plan ledger and isolated worktree; preserve existing worktrees and historical evidence.
- [ ] Adapt the trusted `output/rust-modules-cfg-2026-10-25/` freeze/run/extra-replay scripts to campaign/cycle-specific immutable paths. Do not edit or reuse old outputs. Use unchanged comparators and campaign acceptance assertions: `tpToFn=0`, `tnToFp=0`, permit/report `fpToTn` and `fnToTp`. The old Rust finalizer's requirement that every transition is zero is unsuitable for an improvement campaign. Record exact commands/options; no online advisory calls.
- [ ] Freeze and measure initial main on seven datasets plus every currently available replay. Fail visibly on missing data rather than silently shrinking the suite.
- [ ] Establish generated-key format with case ID, polarity, CWE, file/region, source/sink/guard evidence and unsupported/uncertain status. Freeze scoring policy before scanning new apps: vulnerable misses retain their denominator even if syntax is unsupported; quiet unsupported safe cases earn no TN credit; raw fixed-case warning counts stay visible.

### Task 1 / Cycle 1: C# multiline sink proofs

**Files:** `src/csharp-constant-sinks.js` (`sinkExpression`, callers and line-to-method offsets); `test/csharp-constant-sinks.test.js`; new `test/csharp-multiline-sinks.test.js` if separation helps; corpus pairs and `package.json` test listing when needed.

- [ ] Author and independently label-review two new C# apps (reporting/jobs), at least four pairs each. Freeze key/source/policy; scan the base; verify actual FP root cause.
- [ ] Write failing tests: literal multiline Process.Start/Arguments/SQL sinks can be proved; dynamic second argument, adjacent dynamic sink, reassignment and CRLF twins cannot.
- [ ] Run tests red, implement bounded complete-expression extraction owned by the matched sink/method, run tests green. Preserve unknown/ambiguous fallback.
- [ ] Complete the common cycle gates below; create and merge PR 1; verify/sync resulting main.

### Task 2 / Cycle 2: C# inferred literal locals

**Files:** `src/csharp-values.js` (`buildModel`, `bindingAt`, `proveBinding`, `prove`); relevant constant-sink integration; tests/corpus. If ownership needs project metadata, use existing `src/dotnet/project-index.js` boundaries rather than inventing framework identity.

- [ ] Generate two fresh C# apps (support/export), review and freeze at least eight new pairs before baseline scans. Replay cycle 1 unchanged.
- [ ] Add red tests for supported `var x = "literal"` reaching a multiargument constant sink, paired with local/using/global alias shadowing, implicit conversion, unknown imports/project inputs, later dynamic writes and ref/out/deconstruction.
- [ ] Implement only the binding subset whose literal type/value is proved. If absence of a named `var` cannot be established, retain the warning; record the reason and choose the next verified bounded value-proof gap if no qualifying improvement is possible.
- [ ] Tests green and common gates pass; create/merge PR 2 and sync main.

### Task 3 / Cycle 3: C# named private-helper arguments

**Files:** `src/csharp-values.js` (`helper`, `prove` and helper argument substitution), existing constant-sink tests, new focused tests/corpus if needed.

- [ ] Generate/freeze two new apps (maintenance/documents), label-review at least eight pairs; replay earlier new sets unchanged.
- [ ] Add red tests for unique private helpers with ordered/reordered named arguments and constant returned values. Unsafe returned arguments, mixed positional/named cases, duplicate/unknown names, optional/params/ref/out, overload ambiguity and recursion retain unresolved behavior unless explicitly implemented and proved.
- [ ] Map actual arguments to declared parameter identities, never by textual position or apparent sanitizer name. Preserve depth/work bounds and caller/visibility constraints. Run tests green.
- [ ] Common gates, PR 3, passing CI, verified merge and main sync.

### Task 4 / Cycle 4: Rust flat Result/error-propagating chains

**Files:** `src/parsers/rust/structure.js`, `src/parsers/rust/analysis.js` (`analyzeContext`), optional focused native helper module if warranted, Rust tests and corpus.

- [ ] Generate/freeze two fresh Rust apps (telemetry/mirror), at least eight reviewed pairs covering explicit unsafe/safe TLS settings, active/unknown cfg, API identity and error propagation.
- [ ] Add red tests for a narrowly defined flat `build()?`/result-unwrapping subset. Generic return types must not be confused with generic function parameters. An async function qualifier alone already passes; do not count it as a new gain. Pending `await`, early termination, unknown calls, invalid ownership and unsupported control flow cannot become high-confidence evidence.
- [ ] Implement only the explicitly documented subset, keeping unknown cfg, macro and identity guards, no compilation/type-inference claims, and Rust coverage incomplete. Run positive/safe/adversarial controls green.
- [ ] Common gates include immutable Hermes replay without inventing accuracy credit; PR 4, CI and merge/main verification.

### Task 5 / Cycle 5: Rust local builder state

**Files:** `src/parsers/rust/analysis.js` and a focused builder-state module if needed; focused Rust state tests, corpus and docs.

- [ ] Generate/freeze two fresh apps (webhook/backup), at least eight reviewed pairs with split builder calls, resets, aliases, moves and backend choices. Replay all earlier sets unchanged.
- [ ] Add red tests for supported single-owner builder initialization/settings/build, dangerous setting then literal safe reset, safe then unsafe reset, no build, aliases, escapes, unknown setters and backend changes.
- [ ] Implement a bounded method-local state proof with explicit invalidation on unsupported flow/ownership. Do not infer API identity from a type or method spelling alone. Run tests green and preserve direct-chain behavior.
- [ ] Common gates, PR 5, passing CI, verified merge/main sync.

## Common gates: repeat for every cycle

- [ ] Manual baseline triage establishes a concrete improvement and an unsafe/safe twin; record all app findings/misses, including unresolved ones.
- [ ] Fresh implementation subagent self-review and review one completed; repair findings and rerun targeted controls.
- [ ] Fresh review two code pass completed; no unresolved actionable correctness/security issue. Freeze Git archive/source/inventory hashes only now.
- [ ] Run exact frozen archive `npm test` and `node bin/kayfabe.js selftest --json`; zero failures and every corpus pair passes.
- [ ] Rerun seven established datasets (C# Juliet, OWASP Java, Java Juliet, SARD sample, original CVE-fix, supplied mixed, earlier .NET) with unchanged scorers/options; compare every original unit plus separate localized CVE policy, no pooled accuracy.
- [ ] Rerun existing frozen safe/prior apps, nine development apps, nickrulez/blesclues, Hermes, earlier adversarial fixtures and every campaign app set; default/project profiles where previously measured. Verify input/key hashes and exact finding identities.
- [ ] Static self-audit of changed production scanner scope plus manual review. Explain fixture findings; never execute target apps or install their dependencies.
- [ ] Verify zero established TP loss/new FP, qualifying improvement on a verified case, runtime <=1.5x baseline, unchanged bounds and explicit partial coverage. Investigate and repair failures; preserve superseded phases.
- [ ] Review two verifies final evidence/privacy/claims. Publish sanitized `docs/benchmarks/` aggregate plus human result report and remaining gaps; no full apps, answer keys or raw scans.
- [ ] Verify final branch runtime identical to measured code. Push a new `codex/` branch, create and attach PR, wait for required CI on its exact head, merge with head-SHA protection. Record merge SHA and fast-forward clean local main.

### Task 6: Cumulative final verification and report

- [ ] After five verified merges, freeze final main; run full suite/corpus, all seven benchmarks, all accumulated app replays and harness self-review again.
- [ ] Compare initial-main and final-main scored units; attribute each improvement to its PR and preserve separate tiers/policies. Verify no regression between reviewed runtime and final main.
- [ ] Save local `final-report.md` in the campaign root with five PR URLs/merge SHAs, per-dataset FP/TP/FN transitions, supported/unsupported coverage, runtime, review dispositions and remaining limitations. Link it in the final response; it does not require a sixth documentation-only PR. If final verification needs a scanner repair, review/test/PR/merge it under the same gates before declaring completion.
- [ ] Update ledger complete and report to the user. Do not start an unrequested release/deployment or further improvement campaign.
