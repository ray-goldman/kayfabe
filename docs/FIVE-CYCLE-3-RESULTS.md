# Cycle 3: C# private-helper named arguments

Part of the approved five-cycle improvement campaign. Each cycle uses fresh application, implementation and review agents; all generated apps are self-authored exposed development/regression evidence. Fresh context and a separate folder do not establish independent authorship on a shared host.

## Established benchmark comparison

Inputs, keys, evaluators, policies and options retain their existing meaning. Each dataset is scored separately; no pooled accuracy estimate or production comparison is claimed. Every scored unit was compared, with no established TP→FN or TN→FP transition.

| Dataset | TP before → after | FP before → after | Misses before → after | FP→TN | FN→TP |
|---|---:|---:|---:|---:|---:|
| csharp | 1036 → 1036 | 470 → 470 | 28645 → 28645 | 0 | 0 |
| owasp-java | 571 → 571 | 289 → 289 | 844 → 844 | 0 | 0 |
| juliet-java | 2410 → 2410 | 1172 → 1172 | 26471 → 26471 | 0 | 0 |
| sard | 10 → 10 | 0 → 0 | 10 → 10 | 0 | 0 |
| cve-fixes | 1 → 1 | 1 → 1 | 7 → 7 | 0 | 0 |
| supplied | 87 → 87 | 11 → 11 | 50 → 50 | 0 | 0 |
| dotnet-apps | 32 → 32 | 1 → 1 | 107 → 107 | 0 | 0 |

Original CVE parent/fix pair success: 0/8 → 0/8. Separate localized policy: 1/8 → 1/8. The localized result does not replace the original score.

## Generated application replays

Each new set contains two apps with four vulnerable/safe pairs each; keys and source inventories were reviewed and SHA-256 frozen before scanning. A missed vulnerable label remains a miss even if its syntax is unsupported. Quiet fixed cases below receive no true-negative credit without case-level proof of completed coverage. Unmatched findings remain visible in the aggregate and require triage.

| Set cycle | App | Profile | TP | Misses | FP | Quiet fixed, uncredited | FP→quiet | FN→TP |
|---:|---|---|---:|---:|---:|---:|---:|---:|
| 1 | reporting-service | default | 4 | 0 | 1 | 3 | 0 | 0 |
| 1 | reporting-service | project | 4 | 0 | 1 | 3 | 0 | 0 |
| 1 | background-job-scheduler | default | 4 | 0 | 3 | 1 | 0 | 0 |
| 1 | background-job-scheduler | project | 4 | 0 | 3 | 1 | 0 | 0 |
| 2 | SupportDeskUtility | default | 4 | 0 | 4 | 0 | 0 | 0 |
| 2 | SupportDeskUtility | project | 4 | 0 | 4 | 0 | 0 | 0 |
| 2 | ExportBatchProcessor | default | 4 | 0 | 4 | 0 | 0 | 0 |
| 2 | ExportBatchProcessor | project | 4 | 0 | 4 | 0 | 0 | 0 |
| 3 | maintenance-api | default | 4 | 0 | 0 | 4 | 4 | 0 |
| 3 | maintenance-api | project | 4 | 0 | 0 | 4 | 4 | 0 |
| 3 | document-service | default | 4 | 0 | 0 | 4 | 4 | 0 |
| 3 | document-service | project | 4 | 0 | 0 | 4 | 4 | 0 |

Full apps, answer-key cases and raw reports remain local. Only minimal scanner-owned corpus fixtures and sanitized measurement metadata are published. These gains measure the supported development cases; established results may remain unchanged.

All eight removed warnings are literal named calls to unique private static helpers returning one exact keyword-string formal. Arguments must all be pure string literals; named identifiers, compound expressions, instance helpers, optional/ref/generic/overloaded members and arbitrary helper bodies remain unsupported. Qualified receivers with unresolved inheritance retain warnings. A shared 65,536-unit value-query budget fails closed on exhaustion. Positional inference is not a general purity or type checker. The earlier region, contextual-type, interpolation and ordinary-method mutation/query limitations remain; cycle-one and cycle-two residual warnings are unchanged.

## Validation and limits

- Full exact-archive suite: 844 tests, 841 passed, 0 failed, 3 platform skips; corpus 200/200.
- Juliet C# default scan: 92.90 s → 94.04 s (1.012×; limit 1.5×). Shared-machine single runs do not establish a speedup.
- 26 existing evaluator/policy files byte-verified unchanged. Existing frozen safe/prior sets, nine development apps, nickrulez/blesclues and 190 adversarial fixtures replayed.
- Immutable Hermes variants replayed in both profiles, with archive/input hashes verified. Rust remains incomplete; zero findings receive no accuracy credit. Cargo inventory is not vulnerability reachability.
- Harness production scope self-audited and all candidates manually reviewed. Fixture/test/documentation scope is explicitly separate; no complete security assessment is implied.
- Two fresh-context review passes cover code/unsafe twins, final evidence, runtime, coverage and publication privacy. Review findings were repaired and rechecked before publication.
- No target apps executed, dependencies installed or target identities queried online. Existing optional analysis gates and bounded work limits remain enforced.

## Frozen provenance

Baseline commit: `e7667206c25a339f645f2ed76b926ab6f1dc4ca3`. Measured implementation: `5e3ec695f1981482917a326345bee2a8ba1df0ec`. Subsequent evidence changes are documentation only.

Baseline reports reuse the preceding cycle measurement at `6c73034581d4d5d7bb56ac1076484323fb97c661`: its exact runtime hash matches verified main `e7667206c25a339f645f2ed76b926ab6f1dc4ca3`. Original report bytes/timestamps are retained. Every new candidate reruns all seven datasets; this is not a fresh timing run of unchanged baseline code.

Baseline source SHA-256: `9afbe1259943d755ddd1dbe0564319f7afe93f452475801fda4ac5f89a0bbc4c`.

Candidate source SHA-256: `ab9b4376c91215b11a50646fac9cdff86de9dc414956d176b7df89e53a35b86e`.

Candidate archive SHA-256: `f8e84901a1710441a3e5915e73c201c010c671b3c5234ea3cd4cd5427e587eb0`.

Candidate inventory SHA-256: `88e1f6fc94f2f45d778ecce52bf9ef2325748ae7c62e7dcaefb1522904a71b34`.

[Sanitized aggregate](benchmarks/five-cycle-3-results.json). Remaining language/control-flow gaps are retained in the scope documentation and aggregate limitations.
