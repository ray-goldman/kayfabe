# Cycle 5: Rust local builder handoff

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
| 3 | maintenance-api | default | 4 | 0 | 0 | 4 | 0 | 0 |
| 3 | maintenance-api | project | 4 | 0 | 0 | 4 | 0 | 0 |
| 3 | document-service | default | 4 | 0 | 0 | 4 | 0 | 0 |
| 3 | document-service | project | 4 | 0 | 0 | 4 | 0 | 0 |
| 4 | telemetry-uploader | default | 4 | 0 | 0 | 4 | 0 | 0 |
| 4 | telemetry-uploader | project | 4 | 0 | 0 | 4 | 0 | 0 |
| 4 | artifact-mirror | default | 4 | 0 | 0 | 4 | 0 | 0 |
| 4 | artifact-mirror | project | 4 | 0 | 0 | 4 | 0 | 0 |
| 5 | webhook-relay | default | 4 | 0 | 0 | 4 | 0 | 4 |
| 5 | webhook-relay | project | 4 | 0 | 0 | 4 | 0 | 4 |
| 5 | backup-client | default | 4 | 0 | 0 | 4 | 0 | 4 |
| 5 | backup-client | project | 4 | 0 | 0 | 4 | 0 | 4 |

Full apps, answer-key cases and raw reports remain local. Only minimal scanner-owned corpus fixtures and sanitized measurement metadata are published. These gains measure the supported development cases; established results may remain unchanged.

The eight new detections use one adjacent immutable builder local and one consuming chain. Initial settings, later literal resets, final backend selection and the original dangerous-setting location are tracked within that subset. Multiple owners, aliases, references, moves, escapes, reassignments, arbitrary intervening calls/effects and unsupported flow remain unresolved. Constructor and auxiliary API identity must be established; this is not general borrow/type analysis or a proof of Result identity. Physical coverage counts remain bounded and incomplete. The eight quiet safe labels receive no TN credit, and a TLS configuration finding does not establish an executed request or exploitability.

## Validation and limits

- Full exact-archive suite: 864 tests, 861 passed, 0 failed, 3 platform skips; corpus 204/204.
- Juliet C# default scan: 96.73 s → 96.68 s (0.999×; limit 1.5×). Shared-machine single runs do not establish a speedup.
- 26 existing evaluator/policy files byte-verified unchanged. Existing frozen safe/prior sets, nine development apps, nickrulez/blesclues and 190 adversarial fixtures replayed.
- Immutable Hermes variants replayed in both profiles, with archive/input hashes verified. Rust remains incomplete; zero findings receive no accuracy credit. Cargo inventory is not vulnerability reachability.
- Harness production scope self-audited and all candidates manually reviewed. Fixture/test/documentation scope is explicitly separate; no complete security assessment is implied.
- Two fresh-context review passes cover code/unsafe twins, final evidence, runtime, coverage and publication privacy. Review findings were repaired and rechecked before publication.
- No target apps executed, dependencies installed or target identities queried online. Existing optional analysis gates and bounded work limits remain enforced.

## Frozen provenance

Baseline commit: `47d0a80f7faaf21eac2e27a136fe893ee07bc397`. Measured implementation: `5c8f6f0f8ff3d8756316ec55bb96111a9da8db6e`. Subsequent evidence changes are documentation only.

Baseline reports reuse the preceding cycle measurement at `91038abc511259a6903cd9a7b4600970c4e31d09`: its exact runtime hash matches verified main `47d0a80f7faaf21eac2e27a136fe893ee07bc397`. Original report bytes/timestamps are retained. Every new candidate reruns all seven datasets; this is not a fresh timing run of unchanged baseline code.

Baseline source SHA-256: `9f25e8e0674c88294eaa20fa4860faf9c93a0789fbc98e5f0d6c0e32c2100a67`.

Candidate source SHA-256: `3246c857fc825a515e349d9bb69879292ccfedf9fd6f1186ddd595aaedfb5aaa`.

Candidate archive SHA-256: `c6ce8dce05a0e62ad86642bfee47e4568dd9bd6eab2a21f0902e8915699dfa8f`.

Candidate inventory SHA-256: `1ea2867e5f44cfb022ffb479ce82362b2d72d51b82f1222d2c1e8e131522a0f3`.

[Sanitized aggregate](benchmarks/five-cycle-5-results.json). Remaining language/control-flow gaps are retained in the scope documentation and aggregate limitations.
