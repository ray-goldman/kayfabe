# Java String proof cycles

Measured cycles: 2 of 2. Each candidate is checked against its accepted predecessor and the campaign's historical C4 measured source. CI, independent evidence/privacy review and protected merge are separate integration gates. These are exposed development evaluations; self-authored examples supply regression coverage only and are not blind accuracy evidence.

The campaign initial baseline reuses hash-verified historical C4 evidence: measured code `5baa432189a87bba1e0b7175289872398713e550`, raw runtime SHA-256 `ac0c92274e0a401a8b8c6dc93fb36c3a8d4555854f2ddbce8f0b6b4c4b9a7c09`, and accepted merged main `01583453a71af3254ca4277eff848029b6d27d04`. The merged main is an integration identity, not a relabeled scanned source. Every candidate in this report has seven fresh offline reports. This two-round campaign is separate from the completed [four Java precision cycles](JAVA-PRECISION-CYCLES.md).

| Cycle | Change | Existing FP → TN | Existing FN → TP | Measured code |
|---|---|---:|---:|---|
| 1 | Independent direct String character copies | 2 | 0 | [b5efb4e](https://github.com/ray-goldman/kayfabe/commit/b5efb4eaa4e42b97c449f2c0b402a1be978ff454) |
| 2 | Certified literal String.charAt helper effects | 11 | 0 | [256a5db](https://github.com/ray-goldman/kayfabe/commit/256a5dbe88bebb2cce8fdc6921d8cd2a1ffdbe52) |

## Historical campaign initial → latest

| Dataset | Units | TP | FP | TN | FN |
|---|---:|---:|---:|---:|---:|
| C# Juliet | 59,282 | 1,036 → 1,036 | 470 → 470 | 29,131 → 29,131 | 28,645 → 28,645 |
| OWASP Java | 2,740 | 571 → 571 | 262 → 249 | 1,063 → 1,076 | 844 → 844 |
| Java Juliet | 57,649 | 2,410 → 2,410 | 1,117 → 1,117 | 27,651 → 27,651 | 26,471 → 26,471 |
| SARD PHP sample | 20 | 10 → 10 | 0 → 0 | 0 → 0 | 10 → 10 |
| Original CVE policy | 16 | 1 → 1 | 1 → 1 | 7 → 7 | 7 → 7 |
| Supplied mixed-language apps | 227 | 87 → 87 | 11 → 11 | 79 → 79 | 50 → 50 |
| Earlier .NET apps | 230 | 32 → 32 | 1 → 1 | 90 → 90 | 107 → 107 |

The current-cycle comparison has 11 FP-to-TN and 0 FN-to-TP transitions. The separate campaign-initial comparison has 13 FP-to-TN and 0 FN-to-TP transitions. Every original and localized policy has zero TP-to-FN and zero TN-to-FP transitions. No pooled dataset/language accuracy is reported.

Original CVE parent/fix success is 0/8; the separately versioned localized policy is 1/8. SARD contains 20 PHP cases. These measures and their denominators remain separate.

## Cycle 2: Certified literal String.charAt helper effects

Extend the opaque-helper effect grammar with one exact bare-local charAt atom. Its receiver must be a method-root String local initialized directly from a supported literal before use and never otherwise assigned. Exact source offsets and binding identities prevent later, expired or same-spelled locals from supplying a certificate.

Check every syntactic arm and defer pending-use approval until the whole body passes. Reuse existing scalar evaluation for exact literal and call slices under one cumulative 512-unit allowance charged to the shared work budget, including failed work. Both producer routes retain fresh local-only return proofs with no caller-value or encoding facts.

A targeted follow-up found that the fresh-response route could bypass the earlier servlet-root check in parentless classes. The corrected new-only nominal certificate rejects uncertain source, same-package and imported servlet roots before the implicit-Object fast path. Canonical safe copies remain supported; older renderer, context and general resolver behavior are unchanged.

The frozen full suite passed 1249/1252 tests with zero failures/cancelled/todo and 3 existing Windows skips. Corpus 212/212 passed, preserving all earlier pairs. Two exact-head source reviews passed before the freeze.

All seven original keys, source inputs, scorer/evaluator code, policies, commands/options and scoring units are unchanged. Exact unit transitions and report hashes are retained privately. All compatibility replays retained their finding identities: prior safe/frozen apps, nine development apps in default/project modes, nickrulez/blesclues, Hermes, all five generated sets and 190 adversarial fixtures. No target application was built, run or installed; scans were offline. Native C receives no TN credit; Hermes/Rust coverage remains incomplete and receives no accuracy credit. The historical 190-fixture inventory was first byte-pinned during verifier preparation, not retrospectively at creation.

The scoped production self-audit retained 4 reviewed findings and zero unreviewed findings. Scope is src/, bin/ and package.json; fixture/test/docs/agent/workflow paths are excluded, so this is not full coverage. Disposition reuse requires exact finding and source-file hashes. C# runtime ratio is 0.981x against the current baseline and 1.000x against initial, within the 1.5x guard; single shared-machine runs do not establish speedups.

Measured code: `256a5dbe88bebb2cce8fdc6921d8cd2a1ffdbe52`. Frozen raw runtime SHA-256: `79dc47d9e34a870ad2af8eb6dd2b402012d22ff9c332483f6fb21e4f735d0a13`. Frozen archive/inventory and policy/input/report hashes are in the [cycle 2 aggregate](benchmarks/java-string-proofs-c2-results.json), SHA-256 `5d5ff8ec10322f725c7fc6fb83762d7fc1eb6a2978b450c27e4972adb692d6da`. Raw archive hashes are kept separate from canonical Git identity; the established policy permits CRLF-to-LF only for verified UTF-8 when checking blob equality. Documentation-only publication heads preserve complete non-documentation Git blobs, including runtime, evaluator, tests, corpus, workflows, configuration and dependencies.

### Boundaries and reassessment

- The added atom accepts only a directly literal-initialized method-root String local and one nonnegative canonical decimal int literal in UTF-16 range. Receiver aliases, nested/switch-local declarations, any later write, computed or parameter indices, other methods, postfixes and chains remain unsupported.
- Canonical class, package, import and platform-root assumptions remain bounded. Unknown inheritance, generic scope, wildcard/static imports and source/import namespace ambiguity retain warnings. The added guards do not implement a full Java/classpath resolver or repair every older textual-type/framework lookup.
- The effect certificate supplies no return bytes, encoding, output or replay knowledge. Every return remains independently proved in a fresh local-only context. Stored arrays, slices, prior conditional output and unknown HTML context remain separate gaps.
- The earlier unshipped candidate was rejected by a follow-up source-review addendum despite passing benchmark comparisons. Its source and measurements remain separate diagnostic evidence. The corrected source receives renewed exact-head reviews and a fresh seven-dataset measurement; diagnostic gains are never added to shipping totals.
- Regressions use inert Java source and were not compiled or executed. Some rejection tests overlap earlier parser gates; exact callee-position certification is also verified in source. Self-authored fixtures and previously exposed suites are regression/development evidence, not blind accuracy estimates.
- Original and localized CVE policies remain separate. The inherited enclosing-expression and broader resolver limits, incomplete Hermes/Rust coverage, scoped self-audit and native C lack of true-negative credit remain. No recall or overall production-security improvement is implied by these precision changes.

The two planned rounds address direct copies and a narrowly certified pure String intrinsic. Remaining source-backed work includes prior conditional response output, supported member-owner binding and ordered collection state; those need distinct control-flow, ownership and assignment proofs. Prefer bounded name binding and parse-coverage reporting before wider qualified-call or map support. A fresh independently authored spec-only evaluation in an environment without harness access is needed for stronger accuracy claims. Keep the exposed seven-key suites as regression gates and tackle the unchanged recall and original CVE-pair gap separately.

Each PR uses a merge commit to retain measured-code ancestry. Required Tests CI passes at its exact final head before merging. Full private apps, keys, case IDs, raw findings and local paths are excluded from these public reports.
