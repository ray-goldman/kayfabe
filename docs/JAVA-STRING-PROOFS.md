# Java String proof cycles

Measured cycles: 1 of 2. Each candidate is checked against its accepted predecessor and the campaign's historical C4 measured source. CI, independent evidence/privacy review and protected merge are separate integration gates. These are exposed development evaluations; self-authored examples supply regression coverage only and are not blind accuracy evidence.

The campaign initial baseline reuses hash-verified historical C4 evidence: measured code `5baa432189a87bba1e0b7175289872398713e550`, raw runtime SHA-256 `ac0c92274e0a401a8b8c6dc93fb36c3a8d4555854f2ddbce8f0b6b4c4b9a7c09`, and accepted merged main `01583453a71af3254ca4277eff848029b6d27d04`. The merged main is an integration identity, not a relabeled scanned source. Every candidate in this report has seven fresh offline reports. This two-round campaign is separate from the completed [four Java precision cycles](JAVA-PRECISION-CYCLES.md).

| Cycle | Change | Existing FP → TN | Existing FN → TP | Measured code |
|---|---|---:|---:|---|
| 1 | Independent direct String character copies | 2 | 0 | [b5efb4e](https://github.com/ray-goldman/kayfabe/commit/b5efb4eaa4e42b97c449f2c0b402a1be978ff454) |

## Historical campaign initial → latest

| Dataset | Units | TP | FP | TN | FN |
|---|---:|---:|---:|---:|---:|
| C# Juliet | 59,282 | 1,036 → 1,036 | 470 → 470 | 29,131 → 29,131 | 28,645 → 28,645 |
| OWASP Java | 2,740 | 571 → 571 | 262 → 260 | 1,063 → 1,065 | 844 → 844 |
| Java Juliet | 57,649 | 2,410 → 2,410 | 1,117 → 1,117 | 27,651 → 27,651 | 26,471 → 26,471 |
| SARD PHP sample | 20 | 10 → 10 | 0 → 0 | 0 → 0 | 10 → 10 |
| Original CVE policy | 16 | 1 → 1 | 1 → 1 | 7 → 7 | 7 → 7 |
| Supplied mixed-language apps | 227 | 87 → 87 | 11 → 11 | 79 → 79 | 50 → 50 |
| Earlier .NET apps | 230 | 32 → 32 | 1 → 1 | 90 → 90 | 107 → 107 |

The current-cycle comparison has 2 FP-to-TN and 0 FN-to-TP transitions. The separate campaign-initial comparison has 2 FP-to-TN and 0 FN-to-TP transitions. Every original and localized policy has zero TP-to-FN and zero TN-to-FP transitions. No pooled dataset/language accuracy is reported.

Original CVE parent/fix success is 0/8; the separately versioned localized policy is 1/8. SARD contains 20 PHP cases. These measures and their denominators remain separate.

## Cycle 1: Independent direct String character copies

Recognize a bare String binding's direct zero-argument toCharArray copy as the sole argument of a complete current print or println statement. The existing independent-output query proves the entire value provenance, including effect-free private helpers.

Require genuine HTML document-text context and a bounded canonical String scope. The final source reviews exposed package/inventory disagreement and qualified servlet-root shadows; the new certificate now rejects both before suppressing a warning.

Share the existing complete-statement boundary checker with formatter proofs without changing its conditions. Rendering, prior-output replay, the older write-copy path, helper eligibility and proof budgets retain their earlier behavior.

The frozen full suite passed 1199/1202 tests with zero failures/cancelled/todo and 3 existing Windows skips. Corpus 211/211 passed, preserving all earlier pairs. Two exact-head source reviews passed before the freeze.

All seven original keys, source inputs, scorer/evaluator code, policies, commands/options and scoring units are unchanged. Exact unit transitions and report hashes are retained privately. All compatibility replays retained their finding identities: prior safe/frozen apps, nine development apps in default/project modes, nickrulez/blesclues, Hermes, all five generated sets and 190 adversarial fixtures. No target application was built, run or installed; scans were offline. Native C receives no TN credit; Hermes/Rust coverage remains incomplete and receives no accuracy credit. The historical 190-fixture inventory was first byte-pinned during verifier preparation, not retrospectively at creation.

The scoped production self-audit retained 4 reviewed findings and zero unreviewed findings. Scope is src/, bin/ and package.json; fixture/test/docs/agent/workflow paths are excluded, so this is not full coverage. Disposition reuse requires exact finding and source-file hashes. C# runtime ratio is 1.019x against the current baseline and 1.019x against initial, within the 1.5x guard; single shared-machine runs do not establish speedups.

Measured code: `b5efb4eaa4e42b97c449f2c0b402a1be978ff454`. Frozen raw runtime SHA-256: `f6a973332ef71a5325eaa2e0eee3ff32a9fc5571193227a9c194ad61492bfbdf`. Frozen archive/inventory and policy/input/report hashes are in the [cycle 1 aggregate](benchmarks/java-string-proofs-c1-results.json), SHA-256 `f2464d0e0e7ad5b037282b0323c8079263e59d26c6dc4b341a88120ae1543b66`. Raw archive hashes are kept separate from canonical Git identity; the established policy permits CRLF-to-LF only for verified UTF-8 when checking blob equality. Documentation-only publication heads preserve complete non-documentation Git blobs, including runtime, evaluator, tests, corpus, workflows, configuration and dependencies.

### Boundaries and reassessment

- This proof supports only current print/println calls with a sole bare-binding conversion. Stored arrays, slices, casts, literal/member/call receivers, extra arguments, wrappers and chained calls remain outside it.
- String type spelling is insufficient. Static/wildcard/ambiguous imports, custom/source/shadowed types, generic or unknown inheritance scopes and package identities inconsistent with the legacy inventory retain warnings. Canonical platform APIs are trusted after source/import ambiguity checks; no complete classpath resolver is claimed.
- No output bytes, encoding, cache entry or later-stream fact is created. Prior conditional output and unknown HTML context remain unsupported; a constant-markup copy cannot supply context for a later encoded attacker value.
- Regression tests use inert Java source, including initialized static conversion callbacks. No Java fixture was compiled or executed. Self-authored fixtures demonstrate regressions, not independent accuracy.
- Original C4 measurements are reused only as hash-verified historical baseline evidence with distinct measured and merged identities. This candidate's seven reports are fresh. Original and localized CVE policies stay separate, and exposed development results are not blind evaluations.
- The inherited recognized-sink/local-constant enclosing-expression gap, broader nominal-resolution limits, incomplete Hermes/Rust coverage and native C lack of true-negative credit remain. This cycle does not claim improved recall or overall production security.

The direct-copy examples are now covered by a current-call proof. Next, add only a certified pure String.charAt atom for immutable directly literal-initialized method-root locals and exact in-range literal indices. The value evaluator already supports those values; the stricter effect grammar is the remaining barrier in inspected same-class SQL and copy-helper examples. Keep the separate prior-conditional-output, nested-owner and ordered-map problems conservative. Select and ship the next change only after predecessor acceptance, new source reviews and another unchanged-key measured gain.

Each PR uses a merge commit to retain measured-code ancestry. Required Tests CI passes at its exact final head before merging. Full private apps, keys, case IDs, raw findings and local paths are excluded from these public reports.
