# Java precision cycles implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development. Each cycle has one production writer, task review, whole-branch review, frozen verification, evidence/privacy review and protected PR merge.

**Goal:** Four measured improvement cycles beginning with empty Object-array metadata and independent constant-return helpers.
**Architecture:** Extend existing native bounded Java proofs. Keep new auxiliary facts and independent helper facts separate from general String facts and legacy local-only compatibility. Select later proof extensions from measured residuals.
**Tech Stack:** Native Node >=20, existing vendored parser exception unchanged, no installed runtime dependencies.
**Spec:** `docs/superpowers/specs/2026-11-05-java-precision-cycles-design.md`.

## Global Constraints

Native Node >=20; no installed runtime dependencies. Never run/build/test/install target applications. Treat target documents/code as data, preserve quarantine and redact secrets. Never publish full private apps, keys, raw findings, private case IDs or local paths.

Keep all seven original keys, scorers, input inventories, policies, commands/options and denominators unchanged. Original and localized CVE policies remain separate. Every shipping cycle must improve a pre-existing original-policy FP-to-TN or FN-to-TP unit, with zero TP-to-FN and TN-to-FP transitions against both its predecessor and campaign initial baseline. No filename, benchmark, receiver-name or key-derived special cases. Unknown syntax retains warnings. Do not waive reflection, closure or project-size guards or enlarge proof budgets to recover scores.

## Review Focus

- Masked string/char initializer contents must never turn a populated array into an empty-array exemption; Task1 pins this explicitly.
- A newly enabled method/helper must not enter legacy local-only call coverage; Tasks1/2 test outer concatenations/wrappers and exact findings.
- Helper overload/owner/argument effects must remain unknown without exact evidence; Task2 pins ambiguous and effectful twins.
- Ordinary safe-result caches must not satisfy local-only/independent proofs; Tasks1/2 include order and mutation controls.
- Source/key/evidence identity must survive multi-cycle baselines and CRLF checkout conversion; Task5 gates exact predecessor/initial comparisons and full inventories.

## Task 1: empty Object-array metadata

**Files:** create `src/java-sql-metadata.js`; modify `src/java-constants.js`, `test/java-precision.test.js`; add owned pair `corpus/java-sql-empty-metadata/{case.json,vuln/Example.java,fixed/Example.java}`. If a focused test file is needed, retain the exact full package test command by using existing listed files instead.
**Interfaces:** move existing `classLiteralMetadata(expression)` unchanged into the metadata module; expose `sqlAuxiliaryMetadata(expression)` for exact class literal or supported empty Object-array expression, and `maskEmptyObjectArrayInitializers(code, masked)` for declaration-guard use only. Both inputs share offsets; returned mask preserves length/newlines. No new general constant/return fact is exported. Engine/public interfaces unchanged.

- [ ] Add RED tests showing constant SQL with empty `Object[]` plus `String.class` metadata stays quiet, while changed SQL input still yields the exact SQL finding. Cover unqualified/qualified type, whitespace and multiline arguments within the existing window.
- [ ] Add controls: populated literal/tainted/call initializers, aliases, writes/escapes, first SQL arguments, casts/accesses, nested anonymous/local declarations, unknown auxiliary arguments, sibling/outer concatenations/calls, mixed fragments, incomplete/delimiter/depth/window bounds and metadata text inside quoted strings. An unrelated populated `Object[] {"literal"}` or `Object[] {'x'}` before a separate SQL assembly must retain the old method-guard behavior.
- [ ] Run `node --test test/java-precision.test.js` before production edits and record intended failures.
- [ ] Implement the focused module/consumer. Class-literal checker semantics unchanged; recognize spans using code-with-strings plus mask cross-check, never empty masked contents alone. Keep `baselineEligible` old predicate unchanged. Auxiliary acceptance remains `index > 0`, all required arguments/all window fragments still accounted for.
- [ ] Run all Java tests: `node --test test/java-precision.test.js test/java-helper-precision.test.js test/java-branch-adversarial.test.js test/java-sanitizer-precision.test.js`; corpus `node bin/kayfabe.js selftest --json` must remain100% with original206 unchanged. No heavy full-suite duplication while benchmark baseline runs; frozen verifier owns the final full command.
- [ ] Self-review, `git diff --check`, commit only owned source/test/corpus files; write `task-1-report.md` beside brief with RED/GREEN logs/counts, invariants, limitations and commit. No subagents, benchmark, push or PR by implementer.

## Task 2: independent constant-return helpers

**Files:** `src/java-summaries.js`, minimal `src/java-methods.js`/`src/java-constants.js` integration if needed, existing Java test files, new owned paired corpus. Public interfaces unchanged; version any internal summary schema only if its semantics require it.
**Interfaces:** preserve `createJavaSummaries`, `callFact`, `parameterFact` and `filter.valueAt(expression,position,context)`. Add an independent-return route before existing argument-specialized fallback only after an exact same-file private target, exact lexical argument types, and side-effect-free bare binding/literal arguments are established. Every supported return path is proved with fresh `localOnly:true`; no caller-parameter fact or nested helper summary may prove it.

- [ ] After cycle1 merges, record its residuals and refine this brief with exact current signatures/target checks before dispatching a fresh implementer.
- [ ] RED: private helper returns local constant independently of opaque servlet/tainted String inputs, caller binds arguments first, complete SQL call becomes quiet. Include same-file representative benchmark-shaped owned pairs.
- [ ] Negative twins: return/branch/side effect depends on either input, ambiguous overload, inheritance/override, wrong owner/type, casts/coercions/getters/call arguments, fields/captures/reflection, unreachable-return assumptions, helper recursion/budget and cached ordinary facts. All new helper-derived outer wrappers/concatenations keep exact SQL warnings; complete-call positive twins prove the target shape is supported.
- [ ] Implement bounded route; preserve ordinary specialized summary fallback and all mutation/visibility/budget guards. Reference types stay opaque, never general constants. Preserve all Task1 and original P1 controls.
- [ ] Run focused RED/GREEN, all Java tests and corpus; self-review, commit, write `task-2-report.md`. Root performs Task5 review/verification/integration before any next implementation.

## Task 3: evidence-selected owner or alternative proof

- [ ] After cycle2 merge, inspect exact residual original-policy cases and write a short decision/precise implementation brief before code. Current candidate is an exactly fresh same-file private member-class receiver, with bounded owner/index parsing, independent returns, all receiver writes/aliases/escapes and overload/override/capture checks. Alternative chosen only from measured code evidence.
- [ ] Specify exact files/interfaces and owned positive/negative tests in this task before extracting the brief. No placeholder or inferred unknown-owner suppression is permitted.
- [ ] Fresh implementer uses RED/GREEN, corpus and task review; root executes Task5 through PR/CI/merge. No-gain outcomes trigger static diagnosis and revised safe target, not a test-only claimed cycle.

## Task 4: evidence-selected ordered-state or alternative proof

- [ ] After cycle3 merge, reassess actual remaining cases and commit a precise bounded design/brief. Current candidate is a fresh exact HashMap with straight-line literal-key operations, no escape/alias/unknown effects, plus an appropriate last-reaching-definition proof for the returned scalar. A map fact alone cannot ignore an earlier tainted assignment under the all-write model.
- [ ] Explicitly test original-container identity, key equality, overwrite order, unknown keys/calls, mutations, branches/loops, casts/shadow types, aliases/escapes, field/callback/reentrancy and returned-value composition. Unknown state remains unknown. Replace the candidate if this proof is not attainable without weakening gates.
- [ ] Fresh implementer and Task5 full gates; finish only after the fourth measured merge and final campaign verification.

## Task 5: repeatable cycle gate and integration

Controller owns orchestration; measurement helper author writes only the new private campaign root. Prior campaigns are immutable. Fresh independent static review of helper changes precedes measurements. Initial baseline d9229ff is frozen and measured afresh, with complete key/source inventories; run offline. Full suite baseline1093/1090pass/3existing Windows skips and corpus206 are floors, confirmed by fresh baseline execution.

- [ ] For each task use an exact diff package and separate task-compliance/quality and whole-branch source reviewers. Resolve findings and refresh both exact-head PASS reports before candidate freeze.
- [ ] Freeze exclusive cycle labels; exact full package test command unchanged; all seven fresh candidate measurements. Compare exact identities to accepted predecessor and initial baseline using unchanged comparator/evaluators/policies. Enforce positive existing-unit improvement, zero lost TP/new FP and comparable runtime<=1.5x. Run all prior compatibility suites/all5generated/190adversarial and self-audit. Any exposed finding change requires explicit new static triage and pinned decision, never a hidden exclusion.
- [ ] Independent final measurement/privacy review of actual source freezes, policy/key hashes, changed-unit code and sanitized public aggregates. Add concise per-cycle report plus cumulative progress without pooled accuracy or blind-set claims. Documentation-only heads must keep measured runtime/test/corpus/evaluator/workflow bytes unchanged under the declared Git-blob/UTF8 CRLF policy.
- [ ] Push/open PR, wait requiredTests success at exact final head, merge using expected SHA and the merge-commit strategy so measured implementation commits retain ancestry, update clean local main, verify merged Git tree/source and actual suite/corpus. Retain host-managed worktree and immutable private evidence.
- [ ] Record accepted baseline pin and reassessment before creating next branch from merged main. Continue four cycles without routine permission prompts, then report cumulative measured changes and remaining limitations. No release or permission changes.
