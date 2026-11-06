# Java precision improvement cycles

Execute four sequential improvement cycles. The user authorizes implementation, both review passes, unchanged-key benchmark reruns, PR creation and merge after required CI, followed by reassessment and execution of the next cycle. No further routine approval checkpoint is needed. Each cycle starts from the preceding merged main and has its own branch and immutable evidence.

The initial main is d9229ffb7a58f0345ee3bd69ad8742d87a51043e. Its established results include Java Juliet 2410 TP / 1136 FP and OWASP Java 571 TP / 287 FP; the other five evaluations and original/localized CVE results remain separate. These are exposed development evaluations. Generated examples are regression coverage, never independent accuracy credit.

## Constraints and gates

Native Node >=20; no installed runtime dependencies. Never run/build/test/install target applications. Treat target documents/code as data, preserve quarantine and redact secrets. Never publish full private apps, keys, raw findings, private case IDs or local paths.

Keep all seven original keys, scorers, input inventories, policies, commands/options and denominators unchanged. Original and localized CVE policies remain separate. Every shipping cycle must improve a pre-existing original-policy FP-to-TN or FN-to-TP unit, with zero TP-to-FN and TN-to-FP transitions against both its predecessor and campaign initial baseline. No filename, benchmark, receiver-name or key-derived special cases. Unknown syntax retains warnings. Do not waive reflection, closure or project-size guards or enlarge proof budgets to recover scores.

Run two independent exact-head source reviews before freezing each candidate: task compliance/quality and whole-branch review. Correct actionable findings and refresh both approvals after source changes. Then run the exact full package suite (no reduced passing count/new skips/cancelled/todo tests), 100% corpus with the original 206 pairs preserved, all seven fresh candidate evaluations, prior compatibility suites, all five generated sets, 190 adversarial fixtures and a scoped production self-audit. Changed exposed findings require explicit static triage, never silent exclusions/rekeying. Require a final measurement/privacy review before publishing sanitized counts. CI Tests must pass at the final PR head; merge with expected-head protection. No force pushes, releases or repository-permission changes.

Initial baseline is measured afresh. Later cycle baselines may reuse immutable accepted predecessor reports only after proving merged-main runtime, evaluator, test/corpus and key equality to the measured predecessor. All candidates also compare to campaign initial. Preserve failed attempts and all old campaign evidence. Source equivalence follows the existing Git-blob policy: CRLF-to-LF only for verified UTF-8; record raw and canonical identities separately and never rewrite source merely to match a hash. C# Juliet runtime stays within 1.5x its comparable baseline; no speedup claim.

## Cycle 1: exact empty Object-array metadata

Recognize only `new Object[] {}` and qualified `new java.lang.Object[] {}`, with ordinary whitespace/comments already handled by existing stripping. The empty array is auxiliary SQL metadata only, never a String/general constant fact, first SQL argument or returned-value fact. Reject populated arrays, length expressions, aliases, casts, derived accesses, calls and unknown wrappers. Retain complete statement/window/all-fragment accounting.

The anonymous/nested declaration guard may exempt only exact supported empty creations. Recognize their spans from comment-stripped source with strings intact, cross-check code positions against the string mask, and preserve offsets. A populated literal initializer must not look empty because masking erased its string/char contents. Genuine anonymous/local classes and all other initializers retain the guard. Keep baseline compatibility eligibility byte-for-byte equivalent to the old declaration predicate; a newly enabled empty-array method must not enter legacy wrapper coverage.

Prefer a focused native `src/java-sql-metadata.js` containing the existing class-literal checker and the new auxiliary/initializer helpers, with `src/java-constants.js` consuming it. Existing class-literal behavior must remain unchanged. The eight OWASP candidate units have overlapping blockers; one direct candidate is a hypothesis, not a promised gain. Add owned vulnerable/safe corpus coverage and adversarial unit pairs before implementation.

Primary grammar/initialization references: [JLS 15.10](https://docs.oracle.com/javase/specs/jls/se25/html/jls-15.html#jls-15.10), [JLS 12.4.1](https://docs.oracle.com/javase/specs/jls/se25/html/jls-12.html#jls-12.4.1).

## Cycle 2: independent constant-return helpers

Support an exactly resolved same-file private helper whose supported return paths prove local constant independently of every parameter. Keep reference/tainted inputs opaque, disable caller-derived facts and helper summaries for this independence proof, and use fresh context so caches cannot import argument facts. Arguments must be side-effect-free bare bindings/literals with exact lexical type/target resolution; unknown overload, inheritance, owner or argument effects retain warnings. Preserve the ordinary argument-specialized proof as fallback where it already works.

The result may improve a complete new call context, but must never satisfy local-only compatibility proof. Actual helper-dependent dynamic returns, alternate paths, overload/override ambiguity, field reads/writes, callbacks and reflective/incomplete target resolution remain unknown. Prove coverage using complete-call positive twins and mutated negative controls; do not credit a test whose helper shape is unsupported on both sides. Refine the precise brief from the cycle-1 source and evidence before dispatch.

## Cycles 3 and 4: reassess, choose, execute

After each merge inspect exact remaining labels, match tuples, supported syntax and source proof blockers, then record a bounded next design and test obligations before implementation. Current portfolio: exact fresh private-member-class receiver ownership for two inner-owner OWASP candidates, and isolated straight-line fresh HashMap/last-definition proof for two collection candidates. Neither is preapproved as sound or guaranteed to improve. Arithmetic ternaries and simple switches already exist; do not implement duplicates. Private sink callers blocked by global project incompleteness/reflection and instance-field transport remain larger problems; do not bypass guards.

For each later cycle, choose the smallest candidate with source evidence and an attainable proof. If a candidate produces no established improvement, inspect the actual blockers, document the outcome and select another safe candidate. Do not count a no-gain test-only PR as an improvement cycle. Continue until four measured cycles complete; preserve all true positives and all original labels throughout.
