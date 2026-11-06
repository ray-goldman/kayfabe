# Java precision cycles

Measured cycles: 2 of 4. Each candidate is checked against its accepted predecessor and the campaign initial main. CI and protected merge are separate integration gates. These are exposed development evaluations; self-authored examples supply regression coverage only.

| Cycle | Change | Existing FP → TN | Existing FN → TP | Measured code |
|---|---|---:|---:|---|
| 1 | Exact empty Object-array metadata | 1 | 0 | [4d8c98f](https://github.com/ray-goldman/kayfabe/commit/4d8c98f8c5923ae1bf2568108dd793bd0fe0986c) |
| 2 | Independent local-return helpers | 19 | 0 | [409b5dc](https://github.com/ray-goldman/kayfabe/commit/409b5dc0075b147eba05edc284142eeeaa737c7c) |

## Campaign initial → latest

| Dataset | Units | TP | FP | TN | FN |
|---|---:|---:|---:|---:|---:|
| C# Juliet | 59,282 | 1,036 → 1,036 | 470 → 470 | 29,131 → 29,131 | 28,645 → 28,645 |
| OWASP Java | 2,740 | 571 → 571 | 287 → 286 | 1,038 → 1,039 | 844 → 844 |
| Java Juliet | 57,649 | 2,410 → 2,410 | 1,136 → 1,117 | 27,632 → 27,651 | 26,471 → 26,471 |
| SARD PHP sample | 20 | 10 → 10 | 0 → 0 | 0 → 0 | 10 → 10 |
| Original CVE policy | 16 | 1 → 1 | 1 → 1 | 7 → 7 | 7 → 7 |
| Supplied mixed-language apps | 227 | 87 → 87 | 11 → 11 | 79 → 79 | 50 → 50 |
| Earlier .NET apps | 230 | 32 → 32 | 1 → 1 | 90 → 90 | 107 → 107 |

The current-cycle comparison has 19 FP-to-TN and 0 FN-to-TP transitions. The separate campaign-initial comparison has 20 FP-to-TN and 0 FN-to-TP transitions. Every original and localized policy has zero TP-to-FN and zero TN-to-FP transitions. No pooled dataset/language accuracy is reported.

Original CVE parent/fix success is 0/8; the separately versioned localized policy is 1/8. SARD contains 20 PHP cases. These measures and their denominators remain separate.

## Cycle 2: Independent local-return helpers

Prove a same-file private helper return independently of unused opaque reference and tainted scalar arguments. Exact lexical target, type and caller-header checks precede fresh local-only return proofs; parameter values remain opaque.

A bounded local-body grammar rejects unknown calls, implicit object conversions, member/nonlocal writes, callbacks and unsupported control flow. This prevents constant return values from concealing helper effects when existing output consumers use constant facts. Existing supported-parameter helper behavior is retained.

The frozen full suite passed 1122/1125 tests with zero failures/cancelled/todo and 3 existing Windows skips. Corpus 208/208 passed, preserving all earlier pairs. Two exact-head source reviews passed before the freeze.

All seven original keys, source inputs, scorer/evaluator code, policies, commands/options and scoring units are unchanged. Exact unit transitions and report hashes are retained privately. All compatibility replays retained their finding identities: prior safe/frozen apps, nine development apps in default/project modes, nickrulez/blesclues, Hermes, all five generated sets and 190 adversarial fixtures. No target application was built, run or installed; scans were offline. Native C receives no TN credit; Hermes/Rust coverage remains incomplete and receives no accuracy credit. The historical 190-fixture inventory was first byte-pinned during verifier preparation, not retrospectively at creation.

The scoped production self-audit retained 4 reviewed findings and zero unreviewed findings. Scope is src/, bin/ and package.json; fixture/test/docs/agent/workflow paths are excluded, so this is not full coverage. Disposition reuse requires exact finding and source-file hashes. C# runtime ratio is 1.086x against the current baseline and 0.992x against initial, within the 1.5x guard; single shared-machine runs do not establish speedups.

Measured code: `409b5dc0075b147eba05edc284142eeeaa737c7c`. Frozen raw runtime SHA-256: `97d5a83c05c6a2537c4a801042061cf0068a173f7d0d6c8a5876c6d26df6413a`. Frozen archive/inventory and policy/input/report hashes are in the [cycle 2 aggregate](benchmarks/java-precision-c2-results.json), SHA-256 `fa055a567bb91bcc02d820f7f477bd3f3eab440d047f9ccab4f3c1a8b92fd6b5`. Raw archive hashes are kept separate from canonical Git identity; the established policy permits CRLF-to-LF only for verified UTF-8 when checking blob equality. Documentation-only publication heads preserve runtime, evaluator, test, corpus and workflow Git blobs.

### Boundaries and reassessment

- The new route is restricted to uniquely resolved same-file private String helpers with exact bare binding/literal arguments and understood nongeneric caller/type scopes. It does not add general Java type resolution or cross-file reference summaries.
- Calls such as charAt, member/index access, allocation, loops and try/finally inside newly admitted helpers remain unsupported. Marker annotations are accepted only in the understood leading header position.
- A binding spelled String is treated as an uncertain reference for expression effects. Its copies and reference equality can remain supported, while concatenation and other conversion operators stay unknown; literal-only concatenation remains supported. This avoids assuming java.lang.String identity from a name.
- HTML encoding is not inferred from return independence. Helpers containing markup can still produce constant-mode facts; explicit HTML structure, context and text-safety proof remain separate requirements.
- The legacy recognized-sink/local-constant enclosing-expression gap remains inherited; new helper facts cannot enter that local-only compatibility path. Exact empty-array SQL metadata remains auxiliary only.

The 19 resolved Java Juliet labels establish a measured return-proof gain; OWASP outcomes are unchanged in this cycle. Remaining annotation-bearing helper candidates are blocked by the marker-only class-header grammar. The next bounded proposal is class annotations with literal String arguments, followed by an explicit independent literal-text capability for surviving formatter substitutions. Recheck exact residuals after each merge; keep stream-context, type, effect and unknown-syntax guards. Broader member-owner, collection and character-copy coverage remain separate work.

Each PR uses a merge commit to retain measured-code ancestry. Required Tests CI passes at its exact final head before merging. Full private apps, keys, case IDs, raw findings and local paths are excluded from these public reports.
