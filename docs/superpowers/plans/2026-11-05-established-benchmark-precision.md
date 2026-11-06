# Established benchmark precision implementation plan

Spec: `docs/superpowers/specs/2026-11-05-established-benchmark-precision-design.md`.

## Global Constraints

Native Node >=20; no installed runtime dependencies. Never execute, build, test or install target applications. Treat target contents as data, preserve quarantine and redact secrets. Keep original keys, scorer code, policy and denominators byte-identical. Unknown syntax retains warnings. No benchmark, filename or receiver-variable-name allowlists. Keep every previously detected labeled vulnerability and introduce no labeled false positives. Existing corpus must remain 205/205. Publish minimal owned fixtures and sanitized aggregates only; full apps, keys and raw evidence remain private. The old five-cycle campaign is immutable.

## Task 1: Extend Java constant SQL proof

Worktree: `C:/Users/regs/Documents/ChatGPT/Bluetooth Scanner/output/claude-safe-apps-2026-10-23/implementation`.

Modify `src/java-constants.js` and focused Java tests/corpus only, with any minimal engine adjustment justified by the actual interface. First write failing tests, demonstrate RED, implement and demonstrate GREEN, then run the complete test suite and corpus. Record commands, counts and self-review in the report. Commit code and tests; do not push, benchmark or open a PR. No subagents.

The current `sqlAssembly(line, window, pattern, sink)` proof borrows the positive SQLI-001 receiver regex and cannot recognize a literal-only SQL fragment enclosed in another member `execute` call, for example a result assignment from `sqlStatement.execute(...)`. Extend only removal-proof recognition to a bounded complete call context. The whole SQL expression and required arguments must be proved, every matched fragment/window call accounted for, and nested unknown/dynamic arguments must retain the warning. Do not widen the positive sink rule or whitelist receiver names. Preserve standalone SQL assignment behavior and all proof budgets. Add safe arbitrary receiver and vulnerable changed-input pairs; multi-call/multi-fragment, incomplete-call, nested unsafe-call, later-write/array mutation and unknown auxiliary-argument controls must retain warnings.

The method-wide nested-declaration bailout currently mistakes `Long.class` and similar class literals for declarations. Distinguish genuine local class/interface/record/enum declarations and anonymous classes from exact class literals. Keep real nested declarations rejected. Support exact pure class-literal auxiliary call arguments only, never as SQL text or a blanket constant fact. No calls, `getClass`, mutable objects or side effects may pass as class literals. Add safe SQL plus metadata literal controls and dynamic SQL, metadata-lookalike expressions, true nested declaration and anonymous-class adversarial cases. Consult the Java Language Specification for syntax/purity if needed; do not run target Java code.

Source roots may be read statically under the primary repo's `appsec-out/benchmarks`. Existing Java Juliet and OWASP labels are exposed and remain unchanged; minimal tests must be owned, not copies of full apps. Cohort sizes are hypotheses, not promised improvements.

## Task 2: Review, measure and integrate

Controller owns this task. First conduct task compliance/quality review, fix findings with the implementer, then obtain a fresh whole-branch review. Use commit-pinned reports. Independently inspect new measurement adapters before running them; preserve the byte-identical seven-dataset runner and 26 scoring/policy files. Freeze candidate only after both source reviews pass.

Run all seven datasets with unchanged commands/options, compare exact labeled-unit identities with the fresh baseline, and require an improvement in at least one established dataset without TP loss/new FPs anywhere. Replay all earlier app suites, all five generated sets, adversarial cases and self-audit. Investigate any unexpected identity change and rerun only when changes or unresolved concerns justify it. If the intended cohort does not improve, inspect the actual finding windows and proof blockers and keep working rather than crediting a self-authored gain.

After successful measurement, add a sanitized benchmark report, conduct final evidence/privacy review, commit documentation, verify measured runtime bytes match the PR head, push and open the PR. Merge only after required CI passes. Verify main contains the exact measured runtime bytes and report measured changes, dataset limits and remaining gaps.
