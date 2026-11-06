# Java precision cycles

Measured cycles: 3 of 4. Each candidate is checked against its accepted predecessor and the campaign initial main. CI and protected merge are separate integration gates. These are exposed development evaluations; self-authored examples supply regression coverage only.

| Cycle | Change | Existing FP → TN | Existing FN → TP | Measured code |
|---|---|---:|---:|---|
| 1 | Exact empty Object-array metadata | 1 | 0 | [4d8c98f](https://github.com/ray-goldman/kayfabe/commit/4d8c98f8c5923ae1bf2568108dd793bd0fe0986c) |
| 2 | Independent local-return helpers | 19 | 0 | [409b5dc](https://github.com/ray-goldman/kayfabe/commit/409b5dc0075b147eba05edc284142eeeaa737c7c) |
| 3 | Literal class-annotation metadata | 22 | 0 | [1505974](https://github.com/ray-goldman/kayfabe/commit/1505974e36f96f1df30823406c708dcc284f4359) |

## Campaign initial → latest

| Dataset | Units | TP | FP | TN | FN |
|---|---:|---:|---:|---:|---:|
| C# Juliet | 59,282 | 1,036 → 1,036 | 470 → 470 | 29,131 → 29,131 | 28,645 → 28,645 |
| OWASP Java | 2,740 | 571 → 571 | 287 → 264 | 1,038 → 1,061 | 844 → 844 |
| Java Juliet | 57,649 | 2,410 → 2,410 | 1,136 → 1,117 | 27,632 → 27,651 | 26,471 → 26,471 |
| SARD PHP sample | 20 | 10 → 10 | 0 → 0 | 0 → 0 | 10 → 10 |
| Original CVE policy | 16 | 1 → 1 | 1 → 1 | 7 → 7 | 7 → 7 |
| Supplied mixed-language apps | 227 | 87 → 87 | 11 → 11 | 79 → 79 | 50 → 50 |
| Earlier .NET apps | 230 | 32 → 32 | 1 → 1 | 90 → 90 | 107 → 107 |

The current-cycle comparison has 22 FP-to-TN and 0 FN-to-TP transitions. The separate campaign-initial comparison has 42 FP-to-TN and 0 FN-to-TP transitions. Every original and localized policy has zero TP-to-FN and zero TN-to-FP transitions. No pooled dataset/language accuracy is reported.

Original CVE parent/fix success is 0/8; the separately versioned localized policy is 1/8. SARD contains 20 PHP cases. These measures and their denominators remain separate.

## Cycle 3: Literal class-annotation metadata

Read bounded ordinary String-literal class annotation arguments from comment-stripped source aligned with the string mask. Typed metadata tokens preserve header boundaries even when quoted text contains braces, angle brackets or escaped quotes.

The existing independent-return proof can now handle these class headers. Annotation values are discarded; they establish no safe value, target identity or effect fact. No annotation-name allowlist or change to the helper body, summary schema or renderer is introduced.

The frozen full suite passed 1129/1132 tests with zero failures/cancelled/todo and 3 existing Windows skips. Corpus 209/209 passed, preserving all earlier pairs. Two exact-head source reviews passed before the freeze.

All seven original keys, source inputs, scorer/evaluator code, policies, commands/options and scoring units are unchanged. Exact unit transitions and report hashes are retained privately. All compatibility replays retained their finding identities: prior safe/frozen apps, nine development apps in default/project modes, nickrulez/blesclues, Hermes, all five generated sets and 190 adversarial fixtures. No target application was built, run or installed; scans were offline. Native C receives no TN credit; Hermes/Rust coverage remains incomplete and receives no accuracy credit. The historical 190-fixture inventory was first byte-pinned during verifier preparation, not retrospectively at creation.

The scoped production self-audit retained 4 reviewed findings and zero unreviewed findings. Scope is src/, bin/ and package.json; fixture/test/docs/agent/workflow paths are excluded, so this is not full coverage. Disposition reuse requires exact finding and source-file hashes. C# runtime ratio is 0.935x against the current baseline and 0.927x against initial, within the 1.5x guard; single shared-machine runs do not establish speedups.

Measured code: `1505974e36f96f1df30823406c708dcc284f4359`. Frozen raw runtime SHA-256: `5a19e3f84b770c08895f5d2cdf49713fe61b1664d147327b57db48ba462de6a6`. Frozen archive/inventory and policy/input/report hashes are in the [cycle 3 aggregate](benchmarks/java-precision-c3-results.json), SHA-256 `bbbdb54b3299e19087d46adf0afaf7657c1384f15843c18c98d26c9864ecb135`. Raw archive hashes are kept separate from canonical Git identity; the established policy permits CRLF-to-LF only for verified UTF-8 when checking blob equality. Documentation-only publication heads preserve runtime, evaluator, test, corpus and workflow Git blobs.

### Boundaries and reassessment

- Only leading class annotation markers, empty arguments, one default String literal or unique named String-literal values are supported. Numeric, boolean, char, null, identifier, expression, class, nested or array values remain unknown.
- The ordinary escape subset is bounded; octal, Unicode preprocessing, text blocks and unsupported escapes remain unknown. Existing header/token/annotation and shared proof limits are preserved.
- Caller annotations retain the marker-only grammar. Generic caller/class scope, exact private target/types, opaque references, uncertain String conversions, effect rejection, all-return proof and local-only compatibility boundaries are unchanged.
- This adds header coverage rather than Java type resolution, HTML encoding or output-context knowledge. Safe formatter carriers can still remain findings when their scalar values lack the required provenance.
- The inherited recognized-sink/local-constant enclosing-expression gap remains; no new helper fact enters that compatibility path.

The measured header extension removes 22 OWASP false positives without changing recall. The inspected direct SQL helper examples are now quiet; two inspected literal-format carrier examples remain findings. Next, prove every carrier element independently under one shared budget, using only local scalar provenance and the existing pure private helper route. Apply this only to complete current printf statements with genuine context; preserve the old renderer and prior-output replay so no new HTML or later-stream claim is introduced.

Each PR uses a merge commit to retain measured-code ancestry. Required Tests CI passes at its exact final head before merging. Full private apps, keys, case IDs, raw findings and local paths are excluded from these public reports.
