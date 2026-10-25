# Rust modules and cfg: measurements

A bounded module graph and three-state cfg evaluation now precede the existing reqwest TLS checks. All established benchmark decisions were preserved. This extends supported syntax; it does not establish general Rust detection accuracy or resolve the original Hermes aggregate resource concern.

## Preserved benchmark decisions

Counts below are identical before and after. Each dataset retains its own unchanged labels, policy and unit matching; do not pool these numbers. Existing benchmarks and exposed development sets were rerun, not used as a new blind evaluation.

| Dataset | Units | TP | FP | TN | Misses |
|---|---:|---:|---:|---:|---:|
| Juliet C# | 59282 | 1036 | 470 | 29131 | 28645 |
| OWASP Java | 2740 | 571 | 289 | 1036 | 844 |
| Juliet Java | 57649 | 2410 | 1172 | 27596 | 26471 |
| SARD PHP sample | 20 | 10 | 0 | 0 | 10 |
| Original CVE-fix units | 16 | 1 | 1 | 7 | 7 |
| Supplied mixed-language labels | 227 | 87 | 11 | 79 | 50 |
| Earlier supplied .NET labels | 230 | 32 | 1 | 90 | 107 |

Original real-CVE parent/fix pair success remains **0/8**. The separate localized policy remains **1/8** and does not replace the original result. No established FP reduction or recall gain is claimed for this Rust change.

## Rust scope and Hermes

The existing checks flag explicitly disabled certificate verification and explicitly native-TLS hostname verification on resolved, built reqwest clients. The [module and cfg layer](RUST-MODULES-CFG.md) follows selected default module paths and evaluates proven configuration predicates. Platform and feature options remain unresolved; the scanner host is never treated as the Rust build target. Internal imports, custom module paths, macro expansion and complex control flow remain gaps.

| Development replay | Files tokenized | Functions in supported subset | Automated findings | Source coverage |
|---|---:|---:|---:|---|
| Hermes original | 1/1 | 0/19 | 0 | incomplete |
| Hermes fixed | 1/1 | 0/20 | 0 | incomplete |

Hermes now records one reachable module scope and one unresolved inert cfg condition per variant. Unknown macro attributes and complex function bodies still leave 0/19 original and 0/20 fixed functions in the supported semantic subset. The pair contains no explicit TLS-verification bypass for the existing rules.

Both immutable Hermes variants were replayed under default and project profiles; all 18 extracted files and the original archive hash were verified before/after. No frozen vulnerability answer key exists for this pair, so zero findings receive no accuracy or true-negative credit. Each variant still inventories 265 packages, including 264 public-registry entries. A passing severity gate does not pass required coverage.

The two new scanner-owned module/cfg pairs now detect their unsafe variants (baseline 0/2, candidate 2/2), with both fixed variants quiet. Both earlier flat TLS pairs retain their detections and quiet fixed controls. These four pairs are self-authored regressions, not independent accuracy data. The corpus increases from 195 to 197 pairs. Hermes body admission, semaphore/stream lifetime, authorization intent, SSRF origin control and upstream deadlines remain manual review gaps.

## Other replays and checks

- Safe-only C# set: 0 FP and 20 TN per profile; recall undefined. Native C remains unsupported with no TN credit.
- Earlier frozen C# set: 2 TP, 8 misses, 0 FP and 20 TN per profile; unchanged.
- Nine supplied apps: exact finding identities unchanged in both profiles. Their prior adjudications remain development labels.
- nickrulez and blesclues: 9 and 36 candidates respectively per profile; unchanged identities, no new accuracy score.
- 190 earlier adversarial fixtures unchanged.
- Windows full suite: 585 tests, 582 passed, 0 failed, 3 platform skips. Corpus: 197/197.
- Juliet C# scan time: 90.81 s → 96.85 s (1.067×; acceptance limit 1.5×). Single shared-machine runs do not support a speedup claim.

## Provenance and review

Baseline: `5485072a2bf7ea2c25160b81b9bad2cc27240744`. Measured implementation: `1c06b4bd7d8f1aaa907e8797072f0a6a459d6d9a`. All 26 evaluator/policy files were byte-verified unchanged. Scanner archives were checked against Git blobs, allowing only verified UTF-8 CRLF normalization for the comparison, and their actual archived bytes were inventoried.

Baseline source SHA-256: `2a5d8af6fca50821091745534a0f0e738c92790de56a823cff43db1ba7b0dc7b`.

Candidate source SHA-256: `388ea41e01d6d96acbe5518ba9ac534c921708e602a905d58788fd36be9d6853`.

Candidate archive SHA-256: `55abefceb9a0ef4435dabc5a632cc38ddf874355a48e3ee7835561eb234b7363`.

Candidate inventory SHA-256: `50320aaba43f00792a5394beb32860bf069124a90e85d2763ef21935632d75b2`.

Two fresh-context code reviews checked module/cfg reachability, imports, Cargo target selection, physical function counts and shared work bounds. Review repairs were completed before freezing this measured candidate. Review dispositions and final evidence were rechecked before the PR. No held-out labels or scoring policies were changed.

No supplied code was executed, dependencies installed, target identities queried online, or supplied source/keys/raw reports published. [Sanitized machine-readable results](benchmarks/rust-modules-cfg-results.json) retain separate dataset policies, hashes and replay counts. Cargo advisory breadth remains limited and unchanged.
