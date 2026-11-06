# Java String Proofs Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development. Fresh implementation seats, task and broad source reviews, frozen measurement, evidence/privacy review, CI and protected merge per cycle.

**Goal:** Two measured reductions in existing Java false positives without losing true positives.
**Architecture:** Extend current-call independent output proofs, then the bounded pure-helper grammar. Keep unknown cases conservative and render/replay unchanged.
**Tech Stack:** Native Node >=20, no installed dependencies.
**Spec:** docs/superpowers/specs/2026-11-06-java-string-proofs-design.md.

## Global Constraints

All spec gates apply: unchanged seven datasets/keys/scorers/policies/units, positive existing FP-to-TN per cycle, zero TP loss/new FP against predecessor and initial, distinct original/localized CVE policies, no target execution, no dependency installs, no private data publication, unchanged full test command and earlier corpus bytes. Two exact-head source PASS before freeze; evidence/privacy PASS before publication; exact-head Tests CI before merge commit; actual-main tree/suite/corpus before acceptance. Floors1161/1158pass/3skips/210corpus; runtime <=1.5x. Old campaigns immutable.

## Review Focus

- A custom String class can implement callback methods: new copy/intrinsic proofs require canonical ownership, not type spelling.
- A complete safe call cannot hide a sibling/chained/outer unsafe sink: preserve whole-window and outer-statement boundaries.
- A constant helper may alter output or return markup: independent provenance is required; no new replay knowledge.
- Local scopes and source offsets can disagree at assignments/branches: charAt must use exact local-only receiver/index facts.
- Reused baseline reports can silently point at altered bytes: hash complete source/evidence/input inventories and all non-doc Git rows before and after measurement.

## Task 1: direct character-copy output

**Files:** new src/java-independent-char-copy.js and src/java-output-proof.js; modify src/java-independent-format.js, src/java-independent-return.js (bounded header-scope export only), src/java-sanitizers.js, test/java-sanitizer-precision.test.js; new corpus/java-independent-char-copy/{case.json,vuln/Example.java,fixed/Example.java}.

**Interfaces:** completeOutputStatement({index,call,windowStart,windowEnd}) -> boolean in java-output-proof.js, extracted unchanged from independentFormat. canonicalStringScope({index,position,project,budget}) -> boolean in java-independent-return.js, using existing bounded class/caller parsing and additional new-only canonical import/supertype guards. independentCharCopy({index,filter,project,call,windowStart,windowEnd}) -> boolean. Existing independentOutputValuesAt unchanged.

- [ ] Save meaningful focused RED stdout/stderr/exits/timestamps/hashes before production edits. Both print/println pure opaque helper positive shapes must fail first; tainted twins must already warn.
- [ ] Implement sole-argument bareBinding.toCharArray() print/println proof after unchanged contextBefore+HTML text. Complete statement/window, canonical scope, exact String binding and independentOutputValuesAt are all required. Shared statement helper preserves formatter checks byte-for-byte in meaning. Existing render/renderExpression/contextBefore/write-copy behavior unchanged.
- [ ] Cover pure if/ternary helpers and aliases; tainted/callback/old-helper/encoder-only provenance; custom/imported/shadowed/generic String and unknown parent/interface scope; wildcard/static/spaced/comment imports; casts/stored or mutated arrays/slices/arguments/suffix chains; wrappers/conditional/partial windows/sibling writers; prior conditional output/loops/raw-text/attribute/comment; markup copy followed by encoded attacker output, including println sequencing; resource exhaustion; legacy formatter/write behavior.
- [ ] Run focused tests then all four Java files and corpus. Preserve all210 earlier cases. Save complete raw evidence, self-review, diff --check, commit only owned files and write task-1-report.md. Root owns full frozen package/all7 runs; do not duplicate benchmarks or spawn agents.
- [ ] Root obtains two source PASS, then Task3 gates through accepted merge before Task2.

## Task 2: bounded pure String.charAt

**Reassess after Task1:** inspect unchanged-key survivors; initial hypotheses are local literal receiver + constant index in a same-class helper. No inner-owner/map or arbitrary member-call support.

**Files:** src/java-independent-return.js plus minimal src/java-summaries.js wiring if required; existing Java helper/sanitizer test files; new corpus/java-independent-char-at/{case.json,vuln/Example.java,fixed/Example.java}.
**Interface:** independentReturnEligible retains its existing call shape and gates. Its localBody checker may consume the existing filter/project context solely to certify exact local Binding.charAt(index) at source offsets under the shared budget. Reuse canonicalStringScope from Task1 and the existing scalar evaluator; do not alter global evaluation semantics. Root will pin final token/lexical/source contract before dispatch after actual Task1 evidence.

- [ ] Save RED for pure exact charAt+switch helper versus tainted return; preserve callback, customString, parameter/index, alias/reassignment, branch scope, out-of-range, surrogate, chained/other-call and resource controls.
- [ ] Admit only canonical local literal-derived String and independently known in-range int index. Fresh localOnly proof, complete grammar coverage of all branches and existing 10k/32methods/depth4/512 expression limits remain. No generic caches, caller facts or arbitrary effects.
- [ ] Run covering Java tests and corpus, preserve every earlier byte, self-review/commit/report. Root runs both source reviews and all Task3 gates. Reassess rather than weaken guards if no original FP reduction.

## Task 3: measurement, publication and integration (each cycle)

**Private root:** output/kayfabe-java-string-proofs-2026-11-06. Measurement author owns only new private files. Use a small explicit baseline bridge/new-root wrapper with byte-exact copied helpers/inputs and pinned origins; never invoke old write-bound CLIs or alter old outputs. Prefer root-aware comparator paths over duplicated scoring logic. No VM/cache injection, symlink routing or fallback path resolution.

- [ ] Verify accepted C4 baseline and complete non-doc Git equality; record measured5baa432, runtimeac0c922... and merged0158345 separately. Revalidate old pins and new preparation pins; retain fresh native starting suite/corpus logs.
- [ ] Two independent static tooling PASS reports before any measurement; meaningful inert guards for stale/mutated evidence, missing reviews, wrong main/source/evaluator/keys, regression/no-gain and second-cycle lineage. Preserve failed attempts.
- [ ] Freeze exact twice-reviewed candidate, run unchanged full suite/corpus, all seven fresh candidate datasets, original-policy unit comparisons against predecessor and campaign start, runtime guard, all compatibility tiers/generated190/selfaudit. Positive FP reduction required even if other metrics improve.
- [ ] Independently review exact actual result/source hashes and typed public report/privacy. Publish concise aggregate with current+cumulative changes and limits; no pooled accuracy or blind claim.
- [ ] Push/open PR, exact-head required Tests CI, expected-head normal merge, update clean main, verify whole publication tree and actual full suite/corpus. Write immutable acceptance, then reassess and branch from accepted main.
- [ ] After both cycles, final broad review/verified evidence archive, remove only this plan's scratch, preserve host worktree/branches/old campaigns, report measured gains and next limitations. No release or permission changes.
