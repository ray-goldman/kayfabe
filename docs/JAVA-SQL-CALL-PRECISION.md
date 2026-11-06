# Java SQL constant-call precision

38 previously false-positive scoring units became true negatives on the unchanged established keys. Java Juliet false positives fell 1172 → 1136 (3.07%); OWASP Java fell 289 → 287 (0.69%). No previously detected labeled vulnerability was lost and no labeled false positive was added in any of the seven datasets.

The gain is precision. Recall and missed-vulnerability counts did not improve. These are already exposed development evaluations; they are not a blind test or a controlled comparison with another scanner. Self-authored regression examples contribute no accuracy credit.

## Established results

| Dataset | Units | TP before → after | FP before → after | TN before → after | FN before → after |
|---|---:|---:|---:|---:|---:|
| C# Juliet | 59282 | 1036 → 1036 | 470 → 470 | 29131 → 29131 | 28645 → 28645 |
| OWASP Java | 2740 | 571 → 571 | 289 → 287 | 1036 → 1038 | 844 → 844 |
| Java Juliet | 57649 | 2410 → 2410 | 1172 → 1136 | 27596 → 27632 | 26471 → 26471 |
| SARD PHP sample | 20 | 10 → 10 | 0 → 0 | 0 → 0 | 10 → 10 |
| Original CVE policy | 16 | 1 → 1 | 1 → 1 | 7 → 7 | 7 → 7 |
| Supplied mixed-language apps | 227 | 87 → 87 | 11 → 11 | 79 → 79 | 50 → 50 |
| Earlier .NET apps | 230 | 32 → 32 | 1 → 1 | 90 → 90 | 107 → 107 |

Original CVE parent/fix successes remain 0/8. The separately versioned localized policy remains 1/8; it is never added to the original score. The SARD result contains 20 PHP cases. Dataset scoring units and denominators are separate; no pooled accuracy is reported.

| SQL injection (CWE-89) | Units | TP before → after | FP before → after | FN before → after |
|---|---:|---:|---:|---:|
| OWASP Java | 504 | 205 → 205 | 116 → 114 | 67 → 67 |
| Java Juliet | 4440 | 1820 → 1820 | 920 → 884 | 400 → 400 |

## What changed

The Java proof can account for complete constant SQL arguments to arbitrary receiver names in member `execute` calls, without widening positive sink rules. Exact class-literal metadata no longer looks like a nested class declaration; it is accepted only as an auxiliary argument, never as proof of SQL text or a returned String. The grammar follows [JLS 15.8.2](https://docs.oracle.com/javase/specs/jls/se25/html/jls-15.html#jls-15.8.2).

New generic and metadata-enabled contexts require a complete supported statement envelope. A constant inner call cannot hide an unknown outer expression. Previously supported recognized-sink return/wrapper cases can keep their old behavior only when every argument independently proves local constant and the method passed the original declaration guard. Both helper-return and caller-parameter summaries are disabled throughout that compatibility proof. A newly enabled helper fact cannot cross that boundary.

Original receiver-name heuristics remain incomplete. Some unsafe outer compositions can still be quiet in the inherited recognized-sink/local-constant subset. This change preserves that baseline limitation rather than claiming safe returned values. Helper-derived wrappers and unsupported syntax can still warn; type-bound receiver/return analysis is needed to improve both sides of that tradeoff.

## Validation and provenance

The final frozen suite passed 1090/1093 tests with zero failures, zero cancelled/todo tests and the same 3 Windows filesystem skips as baseline. Measurements used native Node v24.16.0 on Windows. The corpus passed 206/206 vulnerable/fixed pairs; the original 205 pairs are preserved. Those paired results measure regressions, not independent accuracy. Two exact-commit source reviews passed after the corrections.

All seven commands, options, input hashes, original keys, scoring code and policies are unchanged. The comparator checked exact scoring-unit transitions, not totals alone. All five generated sets, earlier frozen/safe apps, nine development apps in default/project modes, nickrulez, blesclues, Hermes and 190 adversarial fixtures retained their baseline finding identities. The historical adversarial inventory was first byte-pinned during verifier preparation; this is not retrospective proof of its original creation bytes.

Native C remains unsupported and receives no true-negative credit. Hermes still has incomplete Rust source coverage and receives no accuracy credit. The self-audit covers production `src/`, `bin/` and `package.json`, excluding fixtures/tests/docs/agent/workflow directories; its four existing manual false-positive dispositions were reused only after exact finding-object and whole-file hashes matched. This is not a full-coverage audit.

C# Juliet runtime was 98865 ms versus 98489 ms (1.004×), within the 1.5× guard under the same two-worker schedule. A single shared-machine run does not establish a speedup. No target application was executed, built or installed; measurements were offline.

Baseline commit: `4c683a63591335cc06c18ebdb9b4ca44e36b1db1`. Measured code commit: `9ca0af02bedc5a4e47238bae83c2e295462dcf93`.

Baseline runtime SHA-256: `b9accd4f839b69c6aa9d6bb516024daf02e9537f21409a01f32d59970704178b`. Final runtime SHA-256: `ede98d222ff29599320226b3ce3515246faf83382e19afc09872395bbde7f1d1`.

The [aggregate JSON](benchmarks/java-sql-call-precision-results.json) contains input/report/policy hashes, separate original/localized results and compatibility counts. Its SHA-256 is `0afce828ef4726f5a1c9425f68ae32a3b6ce94472bd04de5509355b8b21b398c`. Full apps, keys, raw transitions and findings remain private. Later documentation commits must preserve the measured runtime, tests, corpus and evaluator bytes. Required CI runs against the final PR head.

## Decisions and limits

The work reused the existing isolated worktree and followed the authorized PR/CI integration workflow. Java constant-proof gaps were chosen because their outcomes could be checked in established datasets. Ambiguous C# `String` binding, C# append/source ownership and the JavaScript redirect were deferred: exact C# build/reference closure is unavailable, append handling needs more ownership proof, and the redirect application exposes eval/prototype mutation. Attractive safe labels were not used to waive those proof requirements.

An intermediate source review caught a generic-call enclosing-expression false negative and required an exact request-to-JDBC regression. A follow-on restored the two known safe local wrapper controls without allowing new helper/caller facts through the compatibility exception. Intermediate evidence was retained. The first measurement also stopped at the summary privacy guard; an explicit typed allowlist replaced nested public projections before the fresh final run. No labels, scorer or policy changed in response.

These decisions cost additional reviews and reruns and leave conservative warnings plus the documented legacy gap. The measurable claim is the established-case precision delta above. Recall, original CVE performance and incomplete-language coverage remain work to do.
