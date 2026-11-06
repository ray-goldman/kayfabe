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

- [x] Add RED tests showing constant SQL with empty `Object[]` plus `String.class` metadata stays quiet, while changed SQL input still yields the exact SQL finding. Cover unqualified/qualified type, whitespace and multiline arguments within the existing window.
- [x] Add controls: populated literal/tainted/call initializers, aliases, writes/escapes, first SQL arguments, casts/accesses, nested anonymous/local declarations, unknown auxiliary arguments, sibling/outer concatenations/calls, mixed fragments, incomplete/delimiter/depth/window bounds and metadata text inside quoted strings. An unrelated populated `Object[] {"literal"}` or `Object[] {'x'}` before a separate SQL assembly must retain the old method-guard behavior.
- [x] Run `node --test test/java-precision.test.js` before production edits and record intended failures.
- [x] Implement the focused module/consumer. Class-literal checker semantics unchanged; recognize spans using code-with-strings plus mask cross-check, never empty masked contents alone. Keep `baselineEligible` old predicate unchanged. Auxiliary acceptance remains `index > 0`, all required arguments/all window fragments still accounted for.
- [x] Run all Java tests: `node --test test/java-precision.test.js test/java-helper-precision.test.js test/java-branch-adversarial.test.js test/java-sanitizer-precision.test.js`; corpus `node bin/kayfabe.js selftest --json` must remain100% with original206 unchanged. No heavy full-suite duplication while benchmark baseline runs; frozen verifier owns the final full command.
- [x] Self-review, `git diff --check`, commit only owned source/test/corpus files; write `task-1-report.md` beside brief with RED/GREEN logs/counts, invariants, limitations and commit. No subagents, benchmark, push or PR by implementer.

## Task 2: independent constant-return helpers

**Reassessment after C1:** PR43 merged, OWASP287->286 FP with571TP preserved; all other six original-policy datasets unchanged, no TP loss/new FP. Exact inline auxiliary metadata is now supported but helper returns with opaque reference parameters remain unknown. Seventeen inspected Juliet source-helper shapes and OWASP SQL/helper shapes are hypotheses, not promised gains. Prior architecture reports are private static evidence only.

**Files:** modify src/java-summaries.js; minimal metadata in src/java-methods.js and src/java-constants.js if necessary; a focused src/java-independent-return.js module is permitted for isolated header/type/argument eligibility. Existing Java test files only (package full test command unchanged). Add corpus/java-independent-returns/{case.json,vuln/Example.java,fixed/Example.java}. No other runtime restructuring.

**Interfaces:** preserve createJavaSummaries, callFact, parameterFact and filter.valueAt(expression,position,context). Add a distinct route ONLY where callFact currently rejects a formal outside String/int/boolean/char/long. Keep supported-only specialized path, exact selection/type checks and existing budget consumption unchanged. A failed new route remains unknown. Do not add an earlier speculative proof pass or new header restrictions to old supported-only calls. No summary schema change is needed unless actual structure semantics require it.

**Exact proof gates:**

1. Retain parseCall/encoder/select ordering, index.complete, unique declaration, supported target, exact arity, String return, recursion/depth/method/work limits, static/this/owner checks. New route must resolve the current file index and a private method; no new public/virtual, cross-file or arbitrary receiver coverage. Retain all project completeness/reflection guards in parameterFact and existing baselineLocal/baselineEligible/complete-call statements.
2. Unsupported formals admitted here must be syntactically valid simple/dotted reference type names, never unsupported primitives, arrays, varargs, malformed dotted names or type arguments. Opaque actual arguments must be bare caller formal bindings, exactly one matching formal with exact typeAt agreement. String/primitive actuals may be bare proven bindings or bounded supported literals with exact existing type facts. Reject null conversions, casts, members/indexes/calls/new/assignment/increment/widening/boxing/coercions. No servlet names or target identifiers are whitelisted.
3. Establish a same nongeneric lexical type scope. Current index.complete does NOT reject generic classes, and caller.supported may be false for benign @Override doPost. Add a bounded explicit new-route header eligibility parser/metadata: enclosing single class header with optional nongeneric extends/implements type names; recognized caller return/name/parameters/throws and ordinary modifiers, optionally syntactic marker annotations @Qualified.Name without arguments. Reject type parameters/type arguments, malformed boundaries, annotation arguments/type-use annotations, unknown tokens, ambiguous/duplicate caller parameters, constructors/initializers/unrecognized caller contexts. Do not globally tighten old parser support. Callee.supported already rejects its own generic method header. Same text types across different scopes/files do not establish identity.
4. For every indexed target return use a newly constructed context containing only localOnly:true, mode:'constant', the SAME existing state.budget object, and stack extended by method.id. Omit parameters, parameterMethod, caller context and external facts; no context spread. Do not replenish work or allocate new method sets. localOnly recursively disables both summary hooks. All parameters remain opaque even after reassignment. Every return must pass; then return independent(), no encoding/dependency/external claim. HTML mode of this new route returns unknown; old supported HTML helper behavior stays unchanged.
5. Scope every suppression to the proved returned value and pre-existing complete sink/window envelope. Constant result does not mean effect-free helper. Helper's own unsafe sink, sibling/enclosing call, other SQL argument, field effects or unknown windows must retain their findings. New facts cannot satisfy localOnly legacy compatibility. If a newly enabled body/call boundary cannot be isolated safely, reject that shape rather than weakening guards.

**Before production edits, save contemporaneous RED stdout/stderr/exit/timestamp/hash under this plan's SDD directory.** Add intended failing positives and nonvacuous scanner positive/negative twins in existing files; prove complete-call positive shape support. Key obligations:

- unused Request/Response references, unused tainted String, independently selected local literal via already-supported arithmetic if/ternary/switch; @Override nongeneric caller positive; exact private static and private unqualified instance shapes.
- return/input alias/branch depends on opaque/tainted parameters; parameter reassignment versus local constant; tainted finally assignment/return; fields/captures/unknown calls; no unreachability guess.
- ambiguous competing declarations including unsupported return types, public virtual/override, wrong owner/types/casts, generic class/caller and inherited overload trap: private choose(Runnable) fixed versus inherited choose(CharSequence) tainted, with caller <Runnable extends CharSequence> run(Runnable input). Raw type strings coincide but actual private overload is inapplicable; retain warning. Nongeneric exact-type twin must prove helper shape, so rejection is not vacuous.
- argument effects that alter a sibling SQL value; callbacks/helper own unsafe sinks; local/anonymous declarations; unsupported annotation forms; cross-file/unknown target; all existing closure/reflection caps retained.
- caller-fact contamination through nested specialized summary context, aliases/concats/split/arrays; ordinary safe-fact order/cache controls; shared work/method/depth exhaustion; HTML fixed markup not encoded; existing supported HTML helpers unchanged.
- newly admitted helper-derived outer concatenations/wrappers/sibling windows retain exact SQL findings while complete-call safe twins pass. Preserve C1 string/char-populated arrays and original P1 enclosing-expression controls.

Run focused RED then GREEN, all four Java test files (java-precision, java-helper-precision, java-branch-adversarial, java-sanitizer-precision) and node bin/kayfabe.js selftest --json. Save raw stdout/stderr/exits/hashes, not just report counts; original207 corpus pairs/files unchanged. Root owns frozen full suite/all seven measurements; implementer must not duplicate heavy benchmark runs. Self-review, git diff --check, commit only owned source/test/corpus files. Write task-2-report.md beside extracted brief with exact commit, commands/raw evidence, invariants/limits and honest status. No subagents, benchmarks, push or PR. Root performs both source reviews and all Task5 gates before the next task.

**Pre-production refinement:** Existing javaOutputFilter can consume default constant facts, so the new route also requires a bounded effect-free local helper body. Parse every statement with brace-scoped scalar bindings; unknown calls, implicit opaque-reference conversions, member/nonlocal writes, callbacks, allocations, loops, exceptions and unrecognized syntax remain unknown. Parameters/reference values are not scalar locals. No dead-arm effect skipping or widened old supported path. Hidden response-write, expired-scope write and implicit-reference toString callback twins have saved RED/GREEN evidence. Exact marker annotations before ordinary caller modifiers are allowed; post-modifier/type-use or argument annotations remain unknown.

## Task 3: class annotation literal metadata

**Reassessment:** The accepted C2 result removes19JavaJuliet FPs with no true-positive loss/new FP, while OWASP retains286FP. Static rereading of actual remaining original-policy labels confirms class annotations with String-literal arguments block otherwise local independent SQL helpers. Existing formatter-array cases have an additional HTML capability boundary. Choose this smaller class-header proof before broader owner/map work. Candidate counts are hypotheses, never a promised gain.

**Files/interfaces:** Modify src/java-independent-return.js only for runtime, existing Java test files and new corpus/java-class-annotation-returns/{case.json,vuln/Example.java,fixed/Example.java}. Preserve independentReturnEligible signature, summary schemas and all consumers. No other runtime file, rule, package, benchmark or policy change.

### Bounded class annotation arguments

Modify only class-declaration annotation prefixes in src/java-independent-return.js, existing Java tests and a new paired corpus/java-class-annotation-returns case. No summary/fact/engine/rule API changes. Preserve the C2 fix for uncertain String conversions and every gate below annotation parsing.

Support existing qualified annotation names without annotation-name allowlists. Keep existing markers, optionally empty parentheses, one default ordinary String literal, or comma-separated unique named String literal elements (identifier = literal). Do not mix default/named values. Deliberately omit char/numeric/bool values because current evidence needs String literals only. Reject identifier/constants, null, calls/expressions, arrays/braced values, nested annotations, class literals, type arguments and duplicate/mixed forms. Unknown annotation shapes remain unknown.

Read literal-bearing comment-stripped source aligned with the mask; masked whitespace alone cannot establish a literal. Explicit typed literal tokens must consume quoted delimiter-looking text and escapes safely. Admit a documented ordinary Java String escape subset only; reject unterminated quotes, unescaped CR/LF, invalid/truncated escapes, Unicode preprocessing/text blocks and anything outside subset. Do not let '<', '>', '{', '}', parens, annotation-looking text or escaped quotes inside a literal affect class/body/type boundaries. No greedy annotation erasure.

Keep current 4000-character header cap, 256-token cap, 16 annotation cap and shared work accounting; no limit increase. Whole header must be consumed. Restrict extension to class prefixes with explicit class-only parser option or separate entry: shared caller modifiers must remain marker-only, and annotations after modifiers/type-use remain unknown. Once class metadata is read, unchanged class name/modifier/extends/implements/generic/owner/caller/arity/type/effect/body/return gates still apply. Metadata conveys no safe value, target identity or purity fact.

### Owned tests before code

Add saved contemporary RED for a complete SQL call via the existing private opaque-reference helper under an arbitrary class annotation with literal arguments. Include safe local independent return versus tainted return, default/named/multiple values/qualified annotation/ordinary marker, @Override caller. Positive original-only complete sink shape must be supported while wrappers/outer concatenations stay warned.

Negative pairs: generic caller/class and inherited-overload trap, quote/brace/angle/syntax text within literals, valid admitted escaped quote/backslash versus malformed/truncated escapes/quotes, calls/identifiers/nested/array annotations, annotation-array brace before class body, duplicates/mixed/default args, extra/trailing tokens, budgets and huge literals, placement/type-use/caller annotation-with-args. Preserve C2 uncertain-String callback negative, hidden output effects, newfact isolation/localOnly and all C1 metadata controls. No target app compilation/execution.

Run focused RED/GREEN and all four Java files plus corpus; save raw stdout/stderr/exits/hash/time and preserve original208 files/cases. Root owns exactcode two source reviews, all seven fresh unchanged-key benchmarks versus predecessor and initial, all compat/selfaudit/evidenceprivacy, PR/CI/merge. No benchmark tuning/name exceptions or project guard waivers.

JLS9.7.1 reference: https://docs.oracle.com/javase/specs/jls/se25/html/jls-9.html#jls-9.7.1 . This design implements a deliberately narrower subset.

**Evidence and handoff:** Save contemporary focused RED before production edits and all later raw stdout/stderr/exit/time/hash files in this plan SDD. Unsupported syntax parser negatives must establish proof rejection; scanner-negative assertions need genuine baseline candidates and quiet positive twins rather than vacuous unsupported fixtures. Cover underlying return input/hidden effects/uncertainString conversion/generic overload trap before asserting any annotation-only benefit. Keep original208corpus bytes; add exactly the owned pair. Run all four Java files plus corpus on final source, diffcheck/selfreview, commit ownedsource/test/corpus only, write task-3-report.md beside extractedbrief with commands/results/logpaths/hash/commit/limits. No subagents, target execution, benchmark runs, pushes or PR. Root owns two source reviews, frozen fullsuite/all7compat/selfaudit/privacy and PR/CI/merge.

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
