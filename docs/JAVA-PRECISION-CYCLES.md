# Java precision cycles

Measured cycles: 4 of 4. Each candidate is checked against its accepted predecessor and the campaign initial main. CI and protected merge are separate integration gates. These are exposed development evaluations; self-authored examples supply regression coverage only.

| Cycle | Change | Existing FP → TN | Existing FN → TP | Measured code |
|---|---|---:|---:|---|
| 1 | Exact empty Object-array metadata | 1 | 0 | [4d8c98f](https://github.com/ray-goldman/kayfabe/commit/4d8c98f8c5923ae1bf2568108dd793bd0fe0986c) |
| 2 | Independent local-return helpers | 19 | 0 | [409b5dc](https://github.com/ray-goldman/kayfabe/commit/409b5dc0075b147eba05edc284142eeeaa737c7c) |
| 3 | Literal class-annotation metadata | 22 | 0 | [1505974](https://github.com/ray-goldman/kayfabe/commit/1505974e36f96f1df30823406c708dcc284f4359) |
| 4 | Independent current-call formatter carriers | 2 | 0 | [5baa432](https://github.com/ray-goldman/kayfabe/commit/5baa432189a87bba1e0b7175289872398713e550) |

## Campaign initial → latest

| Dataset | Units | TP | FP | TN | FN |
|---|---:|---:|---:|---:|---:|
| C# Juliet | 59,282 | 1,036 → 1,036 | 470 → 470 | 29,131 → 29,131 | 28,645 → 28,645 |
| OWASP Java | 2,740 | 571 → 571 | 287 → 262 | 1,038 → 1,063 | 844 → 844 |
| Java Juliet | 57,649 | 2,410 → 2,410 | 1,136 → 1,117 | 27,632 → 27,651 | 26,471 → 26,471 |
| SARD PHP sample | 20 | 10 → 10 | 0 → 0 | 0 → 0 | 10 → 10 |
| Original CVE policy | 16 | 1 → 1 | 1 → 1 | 7 → 7 | 7 → 7 |
| Supplied mixed-language apps | 227 | 87 → 87 | 11 → 11 | 79 → 79 | 50 → 50 |
| Earlier .NET apps | 230 | 32 → 32 | 1 → 1 | 90 → 90 | 107 → 107 |

The current-cycle comparison has 2 FP-to-TN and 0 FN-to-TP transitions. The separate campaign-initial comparison has 44 FP-to-TN and 0 FN-to-TP transitions. Every original and localized policy has zero TP-to-FN and zero TN-to-FP transitions. No pooled dataset/language accuracy is reported.

Original CVE parent/fix success is 0/8; the separately versioned localized policy is 1/8. SARD contains 20 PHP cases. These measures and their denominators remain separate.

## Cycle 4: Independent current-call formatter carriers

Certify every immutable formatting-array element under one shared independent-output proof. It accepts local scalar provenance and the existing pure private opaque-reference helper route, while excluding encoder, caller-parameter and older helper-summary facts.

A separate strict printf checker requires genuine context, complete top-level statement and window boundaries, supported literal formats, carrier ownership and canonical Locale evidence. It accepts only the current output call; the renderer and prior-output replay remain unchanged.

The final campaign source review exposed imported-prefix ownership gaps. Added opaque routes now leave package-qualified owners unknown, explicit simple-class owners require unambiguous static-import scope, and the new Locale path rejects wildcard/static/imported-root uncertainty. Both routes share one isolated-return proof operation.

The frozen full suite passed 1158/1161 tests with zero failures/cancelled/todo and 3 existing Windows skips. Corpus 210/210 passed, preserving all earlier pairs. Two exact-head source reviews passed before the freeze.

All seven original keys, source inputs, scorer/evaluator code, policies, commands/options and scoring units are unchanged. Exact unit transitions and report hashes are retained privately. All compatibility replays retained their finding identities: prior safe/frozen apps, nine development apps in default/project modes, nickrulez/blesclues, Hermes, all five generated sets and 190 adversarial fixtures. No target application was built, run or installed; scans were offline. Native C receives no TN credit; Hermes/Rust coverage remains incomplete and receives no accuracy credit. The historical 190-fixture inventory was first byte-pinned during verifier preparation, not retrospectively at creation.

The scoped production self-audit retained 4 reviewed findings and zero unreviewed findings. Scope is src/, bin/ and package.json; fixture/test/docs/agent/workflow paths are excluded, so this is not full coverage. Disposition reuse requires exact finding and source-file hashes. C# runtime ratio is 0.997x against the current baseline and 0.924x against initial, within the 1.5x guard; single shared-machine runs do not establish speedups.

Measured code: `5baa432189a87bba1e0b7175289872398713e550`. Frozen raw runtime SHA-256: `ac0c92274e0a401a8b8c6dc93fb36c3a8d4555854f2ddbce8f0b6b4c4b9a7c09`. Frozen archive/inventory and policy/input/report hashes are in the [cycle 4 aggregate](benchmarks/java-precision-c4-results.json), SHA-256 `5d0753de9afddc8f12187bc10e0e8421e52e7d182462da4b384a36a7bab237b0`. Raw archive hashes are kept separate from canonical Git identity; the established policy permits CRLF-to-LF only for verified UTF-8 when checking blob equality. Documentation-only publication heads preserve runtime, evaluator, test, corpus and workflow Git blobs.

### Boundaries and reassessment

- The formatter shortcut supports a single owned array carrier and a strict subset of %s, indexed %N$s, %n and %% directives. Direct varargs, alternate methods, casts, member/index/split caller provenance and unknown formats remain outside this shortcut.
- A conservative admission estimate reserves 4,000 per substitution within a 16,000 cap. This is not an actual output-byte bound; more than three substitutions with nonempty format remain unknown even when concrete values would be short.
- Package-qualified opaque helper calls and Locale calls with wildcard/static import uncertainty remain findings. General Java name/classpath resolution is not provided. Older supported-summary and renderer paths retain their existing limits.
- No encoding, exact helper bytes, output placeholder or later-stream fact is created. Fixed helper markup followed by externally encoded output still requires the original conservative replay checks.
- The new regression pair received explicit servlet imports before freezing; its labels and every earlier corpus case are unchanged. Tests scan inert source only; Java fixtures were not compiled or typechecked. A private report correction distinguishes one unit fixture from the independent reviewer callback witness.
- The inherited recognized-sink/local-constant enclosing-expression gap, incomplete Hermes/Rust coverage and native C lack of TN credit remain. No recall, blind-set or overall-product security claim follows from these precision changes.

All four planned measured rounds have improved pre-existing original-policy units: 25 OWASP and 19 Java Juliet false positives removed from the campaign initial baseline, with no labeled regressions. The inspected formatter carriers are now quiet. Remaining candidates include direct String character-copy output and broader helper ownership/ordered-state transport; each needs its own source evidence and bounded proof. Name binding and parse-coverage reporting should precede wider qualified-call support. A fresh independently authored spec-only set, frozen before any scan, is needed for stronger accuracy claims; the exposed development suites remain regression gates. Recall and the original 0/8 CVE parent/fix result remain unchanged.

Each PR uses a merge commit to retain measured-code ancestry. Required Tests CI passes at its exact final head before merging. Full private apps, keys, case IDs, raw findings and local paths are excluded from these public reports.
