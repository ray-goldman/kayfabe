# Initial Rust source analysis: measurements

Two bounded reqwest TLS checks and two scanner-owned vulnerable/fixed pairs were added. All established benchmark decisions were preserved. This is an initial source-analysis foundation; it does not establish general Rust detection accuracy or resolve the original Hermes aggregate resource concern.

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

The new checks flag explicitly disabled certificate verification and explicitly native-TLS hostname verification on resolved, built reqwest clients. The [supported syntax and limits](RUST-SOURCE-ANALYSIS.md) deliberately exclude ambiguous crate identities, module graphs, macros, conditional compilation, chained imports and complex control flow. Unsupported cases remain incomplete.

| Development replay | Files tokenized | Functions in supported subset | Automated findings | Source coverage |
|---|---:|---:|---:|---|
| Hermes original | 1/1 | 0/19 | 0 | incomplete |
| Hermes fixed | 1/1 | 0/20 | 0 | incomplete |

Both immutable Hermes variants were replayed under default and project profiles; all 18 extracted files and the original archive hash were verified before/after. No frozen vulnerability answer key exists for this pair, so zero findings receive no accuracy or true-negative credit. Each variant still inventories 265 packages, including 264 public-registry entries. A passing severity gate does not pass required coverage.

The new scanner-owned vulnerable/fixed pairs pass: unsafe settings are detected and validation-enabled variants remain quiet for those rules. These two pairs increase the self-authored corpus from 193 to 195; they measure regression behavior only. Hermes body admission, semaphore/stream lifetime, authorization intent, SSRF origin control and upstream deadlines remain manual review gaps.

## Other replays and checks

- Safe-only C# set: 0 FP and 20 TN per profile; recall undefined. Native C remains unsupported with no TN credit.
- Earlier frozen C# set: 2 TP, 8 misses, 0 FP and 20 TN per profile; unchanged.
- Nine supplied apps: exact finding identities unchanged in both profiles. Their prior adjudications remain development labels.
- nickrulez and blesclues: 9 and 36 candidates respectively per profile; unchanged identities, no new accuracy score.
- 190 earlier adversarial fixtures unchanged.
- Windows full suite: 568 tests, 565 passed, 0 failed, 3 platform skips. Corpus: 195/195.
- Juliet C# scan time: 99.10 s → 91.98 s (0.928×; acceptance limit 1.5×). Single shared-machine runs do not support a speedup claim.

## Provenance and review

Baseline: `17f7dcee48b964d5d48115d5d664a29300f05c7a`. Measured implementation: `da57622131e49dec42bf14b5da3fb3a080d7a2dd`. All 26 evaluator/policy files were byte-verified unchanged. Scanner archives were checked against Git blobs, allowing only verified UTF-8 CRLF normalization for the comparison, and their actual archived bytes were inventoried.

Baseline source SHA-256: `a98e5e7ec9badd35c7759f6f0bd20f06696fbad64b65218c61fbd58b68571278`.

Candidate source SHA-256: `2a5d8af6fca50821091745534a0f0e738c92790de56a823cff43db1ba7b0dc7b`.

Candidate archive SHA-256: `318df414cdfc746aaa787f9ed058af2c616dd211b24c0720e3ad3239d47e211c`.

Candidate inventory SHA-256: `8fed57f3db02e2f8975a62ddce357b1a971de51948dbc440a1a333bd15586a5e`.

Two fresh-context code reviews found and verified repairs for cfg/macro reachability, dependency/library identity, normalized alias collisions, known termination and its aliases, invalid lexical tokens, Cargo config replacements, excluded-test scope and nested builder arguments. The earlier candidate runs are retained locally as superseded development evidence after these code-review fixes. Final acceptance uses only the corrected candidate above. No new held-out labels were inspected or retuned.

No supplied code was executed, dependencies installed, target identities queried online, or supplied source/keys/raw reports published. [Sanitized machine-readable results](benchmarks/rust-source-analysis-results.json) retain separate dataset policies, hashes and replay counts. Cargo advisory breadth remains limited and unchanged.
