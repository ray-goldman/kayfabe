# Cycle 1: C# multiline sink precision

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
| 1 | reporting-service | default | 4 | 0 | 3 | 1 | 1 | 0 |
| 1 | reporting-service | project | 4 | 0 | 3 | 1 | 1 | 0 |
| 1 | background-job-scheduler | default | 4 | 0 | 3 | 1 | 1 | 0 |
| 1 | background-job-scheduler | project | 4 | 0 | 3 | 1 | 1 | 0 |

Full apps, answer-key cases and raw reports remain local. Only minimal scanner-owned corpus fixtures and sanitized measurement metadata are published. These gains measure the supported development cases; established results may remain unchanged.

## Remaining cases

Six safe-case warnings remain per profile. Four SQL cases have ambiguous method ownership because primary-constructor declarations are indexed as an overlapping outer method. Two command cases remain outside the stricter proof's supported multi-type/value subset; interpolated strings also remain unsupported. These warnings are retained, and their source/key bytes remain frozen for later cycles.

## Validation and limits

- Full exact-archive suite: 627 tests, 624 passed, 0 failed, 3 platform skips; corpus 198/198.
- Juliet C# default scan: 104.75 s → 95.01 s (0.907×; limit 1.5×). Shared-machine single runs do not establish a speedup.
- 26 existing evaluator/policy files byte-verified unchanged. Existing frozen safe/prior sets, nine development apps, nickrulez/blesclues and 190 adversarial fixtures replayed.
- Immutable Hermes variants replayed in both profiles, with archive/input hashes verified. Rust remains incomplete; zero findings receive no accuracy credit. Cargo inventory is not vulnerability reachability.
- Harness production scope self-audited and all candidates manually reviewed. Fixture/test/documentation scope is explicitly separate; no complete security assessment is implied.
- Two fresh-context review passes cover code/unsafe twins, final evidence, runtime, coverage and publication privacy. Review findings were repaired and rechecked before publication.
- No target apps executed, dependencies installed or target identities queried online. Existing optional analysis gates and bounded work limits remain enforced.

## Frozen provenance

Baseline commit: `29aa84cc9afe60760e903b2fd9b5e25a81d1ad44`. Measured implementation: `39bf5f299ec2f188c8aa31b03649781be970d706`. Subsequent evidence changes are documentation only.

Baseline source SHA-256: `388ea41e01d6d96acbe5518ba9ac534c921708e602a905d58788fd36be9d6853`.

Candidate source SHA-256: `0edd40d6cdad90e4980eab59d2840bff0c6f344d8b363935129058961df4f77e`.

Candidate archive SHA-256: `c5aef15dc297a6eac8d4bce7aa4a34ef1fcc8c56c3bad747b94a7198fd474fe6`.

Candidate inventory SHA-256: `a7c31e261fdc915794ac09db859d0d91dd510e0b051b26c046913fbc2db0d25d`.

[Sanitized aggregate](benchmarks/five-cycle-1-results.json). Remaining language/control-flow gaps are retained in the scope documentation and aggregate limitations.
