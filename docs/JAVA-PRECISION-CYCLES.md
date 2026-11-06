# Java precision cycles

Measured cycles: 1 of 4. Each candidate is checked against its accepted predecessor and the campaign initial main. CI and protected merge are separate integration gates. These are exposed development evaluations; self-authored examples supply regression coverage only.

| Cycle | Change | Existing FP → TN | Existing FN → TP | Measured code |
|---|---|---:|---:|---|
| 1 | Exact empty Object-array metadata | 1 | 0 | [4d8c98f](https://github.com/ray-goldman/kayfabe/commit/4d8c98f8c5923ae1bf2568108dd793bd0fe0986c) |

## Campaign initial → latest

| Dataset | Units | TP | FP | TN | FN |
|---|---:|---:|---:|---:|---:|
| C# Juliet | 59,282 | 1,036 → 1,036 | 470 → 470 | 29,131 → 29,131 | 28,645 → 28,645 |
| OWASP Java | 2,740 | 571 → 571 | 287 → 286 | 1,038 → 1,039 | 844 → 844 |
| Java Juliet | 57,649 | 2,410 → 2,410 | 1,136 → 1,136 | 27,632 → 27,632 | 26,471 → 26,471 |
| SARD PHP sample | 20 | 10 → 10 | 0 → 0 | 0 → 0 | 10 → 10 |
| Original CVE policy | 16 | 1 → 1 | 1 → 1 | 7 → 7 | 7 → 7 |
| Supplied mixed-language apps | 227 | 87 → 87 | 11 → 11 | 79 → 79 | 50 → 50 |
| Earlier .NET apps | 230 | 32 → 32 | 1 → 1 | 90 → 90 | 107 → 107 |

The current-cycle comparison has 1 FP-to-TN and 0 FN-to-TP transitions. The separate campaign-initial comparison has 1 FP-to-TN and 0 FN-to-TP transitions. Every original and localized policy has zero TP-to-FN and zero TN-to-FP transitions. No pooled dataset/language accuracy is reported.

Original CVE parent/fix success is 0/8; the separately versioned localized policy is 1/8. SARD contains 20 PHP cases. These measures and their denominators remain separate.

## Cycle 1: Exact empty Object-array metadata

Exact new Object[] {} and new java.lang.Object[] {} expressions can serve as auxiliary SQL metadata. They supply no first-SQL-argument, String, general constant or returned-value fact. Existing class-literal behavior is unchanged.

The constructor guard locates empty initializers in source with strings intact and verifies their masked positions. Populated string/char initializers do not become empty when literals are masked. Unknown initializers and genuine anonymous/local classes retain the guard. The original compatibility predicate remains unchanged, so newly enabled methods require complete supported statement envelopes.

Grammar and initialization references: [JLS 15.10](https://docs.oracle.com/javase/specs/jls/se25/html/jls-15.html#jls-15.10), [JLS 12.4.1](https://docs.oracle.com/javase/specs/jls/se25/html/jls-12.html#jls-12.4.1).

The frozen full suite passed 1099/1102 tests with zero failures/cancelled/todo and 3 existing Windows skips. Corpus 207/207 passed, preserving all earlier pairs. Two exact-head source reviews passed before the freeze.

All seven original keys, source inputs, scorer/evaluator code, policies, commands/options and scoring units are unchanged. Exact unit transitions and report hashes are retained privately. All compatibility replays retained their finding identities: prior safe/frozen apps, nine development apps in default/project modes, nickrulez/blesclues, Hermes, all five generated sets and 190 adversarial fixtures. No target application was built, run or installed; scans were offline. Native C receives no TN credit; Hermes/Rust coverage remains incomplete and receives no accuracy credit. The historical 190-fixture inventory was first byte-pinned during verifier preparation, not retrospectively at creation.

The scoped production self-audit retained 4 reviewed findings and zero unreviewed findings. Scope is src/, bin/ and package.json; fixture/test/docs/agent/workflow paths are excluded, so this is not full coverage. Disposition reuse requires exact finding and source-file hashes. C# runtime ratio is 0.914x against the current baseline and 0.914x against initial, within the 1.5x guard; single shared-machine runs do not establish speedups.

Measured code: `4d8c98f8c5923ae1bf2568108dd793bd0fe0986c`. Frozen raw runtime SHA-256: `0aa3ac0065fd6e42fabead618b6f82523c1ea8c58bc43040c176cd931f49eeb8`. Frozen archive/inventory and policy/input/report hashes are in the [cycle 1 aggregate](benchmarks/java-precision-c1-results.json), SHA-256 `a42dfc695effb9b944d07adf96ca31692c679d1a74e3abacd8ecc81e444ed36f`. Raw archive hashes are kept separate from canonical Git identity; the established policy permits CRLF-to-LF only for verified UTF-8 when checking blob equality. Documentation-only publication heads preserve runtime, evaluator, test, corpus and workflow Git blobs.

### Boundaries and reassessment

- Only exact inline empty Object-array creations are supported; aliases, sized/populated arrays, casts, accesses and unknown wrappers remain unproved.
- Helper bodies containing array initializers retain their separate conservative guard; this cycle creates no helper-return fact.
- The legacy recognized-sink/local-constant enclosing-expression suppression gap remains as documented in the earlier Java SQL report. No globally sound returned-value claim is made.
- The observed gain is one established negative unit, not all eight syntactic empty-array candidates. Remaining candidates have additional helper/owner barriers.

Next, prove exactly resolved same-file private helper returns independently of opaque servlet and tainted inputs, keeping those arguments non-effectful and exactly typed. Seventeen inspected Juliet helper candidates and overlapping OWASP candidates motivate the next cycle; prospective removals remain hypotheses. Field constants had zero FPs in the inspected declaration cohort, and arithmetic ternary/simple switch support already exists, so neither is selected just to fill a cycle.

Each PR uses a merge commit to retain measured-code ancestry. Required Tests CI passes at its exact final head before merging. Full private apps, keys, case IDs, raw findings and local paths are excluded from these public reports.
